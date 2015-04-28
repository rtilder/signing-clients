# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

import fnmatch
import hashlib
import itertools
import os.path
import re
import zipfile

from base64 import b64encode, b64decode
from cStringIO import StringIO

from M2Crypto import Err
from M2Crypto.BIO import BIOError, MemoryBuffer
from M2Crypto.SMIME import SMIME, PKCS7, PKCS7_DETACHED, PKCS7_BINARY
from M2Crypto.X509 import X509_Stack
from M2Crypto.m2 import pkcs7_read_bio_der

# Lame hack to take advantage of a not well known OpenSSL flag.  This omits
# the S/MIME capabilities when generating a PKCS#7 signature.  If included,
# XPI signature verification breaks.
PKCS7_NOSMIMECAP = 0x200

headers_re = re.compile(
    r"""^((?:Manifest|Signature)-Version
          |Name
          |Digest-Algorithms
          |(?:MD5|SHA1)-Digest(?:-Manifest)?)
          \s*:\s*(.*)""", re.X | re.I)
continuation_re = re.compile(r"""^ (.*)""", re.I)
directory_re = re.compile(r"[\\/]$")

# Python 2.6 and earlier doesn't have context manager support
ZipFile = zipfile.ZipFile
if not hasattr(zipfile.ZipFile, "__enter__"):
    class ZipFile(zipfile.ZipFile):
        def __enter__(self):
            return self
        def __exit__(self, type, value, traceback):
            self.close()


class ParsingError(Exception):
    pass


def ignore_certain_metainf_files(filename):
    """
    We do not support multiple signatures in XPI signing because the client
    side code makes some pretty reasonable assumptions about a single signature
    on any given JAR.  This function returns True if the file name given is one
    that we dispose of to prevent multiple signatures.
    """
    ignore = ("META-INF/manifest.mf",
              "META-INF/*.sf",
              "META-INF/*.rsa",
              "META-INF/*.dsa",
              "META-INF/ids.json")

    for glob in ignore:
        if fnmatch.fnmatch(filename, glob):
            return True
    return False


def file_key(zinfo):
    '''
    Sort keys for xpi files
    @param name: name of the file to generate the sort key from
    '''
    # Copied from xpisign.py's api.py and tweaked
    name = zinfo.filename
    prio = 4
    if name == 'install.rdf':
        prio = 1
    elif name in ["chrome.manifest", "icon.png", "icon64.png"]:
        prio = 2
    elif name in ["MPL", "GPL", "LGPL", "COPYING", "LICENSE", "license.txt"]:
        prio = 5
    parts = [prio] + list(os.path.split(name.lower()))
    return "%d-%s-%s" % tuple(parts)


def _digest(data):
    md5 = hashlib.md5()
    md5.update(data)
    sha1 = hashlib.sha1()
    sha1.update(data)
    return {'md5': md5.digest(), 'sha1': sha1.digest()}


class Section(object):
    __slots__ = ('name', 'algos', 'digests')

    def __init__(self, name, algos=('md5', 'sha1'), digests={}):
        self.name = name
        self.algos = algos
        self.digests = digests

    def __str__(self):
        # Important thing to note: placement of newlines in these strings is
        # sensitive and should not be changed without reading through
        # http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#JAR%20Manifest
        # thoroughly.
        algos = ''
        order = self.digests.keys()
        order.sort()
        for algo in order:
            algos += " %s" % algo.upper()
        entry = ''
        # The spec for zip files only supports extended ASCII and UTF-8
        # See http://www.pkware.com/documents/casestudies/APPNOTE.TXT
        # and search for "language encoding" for details
        #
        # See https://bugzilla.mozilla.org/show_bug.cgi?id=1013347
        if isinstance(self.name, unicode):
            name = self.name.encode("utf-8")
        else:
            name = self.name
        name = "Name: %s" % name
        # See https://bugzilla.mozilla.org/show_bug.cgi?id=841569#c35
        while name:
            entry += name[:72]
            name = name[72:]
            if name:
                entry += "\n "
        entry += "\n"
        entry += "Digest-Algorithms:%s\n" % algos
        for algo in order:
            entry += "%s-Digest: %s\n" % (algo.upper(),
                                          b64encode(self.digests[algo]))
        return entry


class Manifest(list):
    version = '1.0'
    extra_newline = False

    def __init__(self, *args, **kwargs):
        super(Manifest, self).__init__(*args)
        for k, v in kwargs.iteritems():
            setattr(self, k, v)

    @classmethod
    def parse(klass, buf):
        #version = None
        if hasattr(buf, 'readlines'):
            fest = buf
        else:
            fest = StringIO(buf)
        kwargs = {}
        items = []
        item = {}
        header = ''  # persistent and used for accreting continuations
        lineno = 0
        # JAR spec requires two newlines at the end of a buffer to be parsed
        # and states that they should be appended if necessary.  Just throw
        # two newlines on every time because it won't hurt anything.
        for line in itertools.chain(fest.readlines(), "\n" * 2):
            lineno += 1
            line = line.rstrip()
            if len(line) > 72:
                raise ParsingError("Manifest parsing error: line too long "
                                   "(%d)" % lineno)
            # End of section
            if not line:
                if item:
                    items.append(Section(item.pop('name'), **item))
                    item = {}
                header = ''
                continue
            # continuation?
            continued = continuation_re.match(line)
            if continued:
                if not header:
                    raise ParsingError("Manifest parsing error: continued line"
                                       " without previous header! Line number"
                                       " %d" % lineno)
                item[header] += continued.group(1)
                continue
            match = headers_re.match(line)
            if not match:
                raise ParsingError("Unrecognized line format: \"%s\"" % line)
            header = match.group(1).lower()
            value = match.group(2)
            if '-version' == header[-8:]:
                # Not doing anything with these at the moment
                #payload = header[:-8]
                #version = value.strip()
                pass
            elif '-digest-manifest' == header[-16:]:
                if 'digest_manifests' not in kwargs:
                    kwargs['digest_manifests'] = {}
                kwargs['digest_manifests'][header[:-16]] = b64decode(value)
            elif 'name' == header:
                if directory_re.search(value):
                    continue
                item['name'] = value
                continue
            elif 'digest-algorithms' == header:
                item['algos'] = tuple(re.split('\s*', value.lower()))
                continue
            elif '-digest' == header[-7:]:
                if not 'digests' in item:
                    item['digests'] = {}
                item['digests'][header[:-7]] = b64decode(value)
                continue
        if len(kwargs):
            return klass(items, **kwargs)
        return klass(items)

    @property
    def header(self):
        return "%s-Version: %s" % (type(self).__name__.title(),
                                       self.version)

    @property
    def body(self):
        return "\n".join([str(i) for i in self])

    def __str__(self):
        segments = [self.header, "", self.body]
        if self.extra_newline:
            segments.append("")
        return "\n".join(segments)


class Signature(Manifest):
    omit_individual_sections = True
    digest_manifests = {}
    filename = 'zigbert'

    @property
    def digest_manifest(self):
        return ["%s-Digest-Manifest: %s" % (i[0].upper(), b64encode(i[1]))
                for i in sorted(self.digest_manifests.iteritems())]

    @property
    def header(self):
        segments = [str(super(Signature, self).header), ]
        segments.extend(self.digest_manifest)
        if self.extra_newline:
            segments.append("")
        return "\n".join(segments)

    # So we can omit the individual signature sections
    def __str__(self):
        if self.omit_individual_sections:
            return str(self.header) + "\n"
        return super(Signature, self).__str__()


class JarExtractor(object):
    """
    Walks an archive, creating manifest.mf and signature.sf contents as it goes

    Can also generate a new signed archive, if given a PKCS#7 signature
    """

    def __init__(self, path, outpath=None, ids=None,
                 omit_signature_sections=False, extra_newlines=False):
        """
        """
        self.inpath = path
        self.outpath = outpath
        self._digests = []
        self.omit_sections = omit_signature_sections
        self.extra_newlines = extra_newlines
        self._manifest = None
        self._sig = None
        self.ids = ids

        def mksection(data, fname):
            digests = _digest(data)
            item = Section(fname, algos=tuple(digests.keys()),
                           digests=digests)
            self._digests.append(item)
        with ZipFile(self.inpath, 'r') as zin:
            for f in sorted(zin.filelist, key=file_key):
                # Skip directories and specific files found in META-INF/ that
                # are not permitted in the manifest
                if (directory_re.search(f.filename)
                        or ignore_certain_metainf_files(f.filename)):
                    continue
                mksection(zin.read(f.filename), f.filename)
            if ids:
                mksection(ids, 'META-INF/ids.json')

    def _sign(self, item):
        digests = _digest(str(item))
        return Section(item.name, algos=tuple(digests.keys()),
                       digests=digests)

    @property
    def manifest(self):
        if not self._manifest:
            self._manifest = Manifest(self._digests,
                                      extra_newline=self.extra_newlines)
        return self._manifest

    @property
    def signatures(self):
        # The META-INF/*.sf files should contain hashes of the individual
        # sections of the the META-INF/manifest.mf file.  So we generate those
        # signatures here
        if not self._sig:
            self._sig = Signature([self._sign(f) for f in self._digests],
                                  digest_manifests=_digest(str(self.manifest)),
                                  omit_individual_sections=self.omit_sections,
                                  extra_newline=self.extra_newlines)
        return self._sig

    @property
    def signature(self):
        # Returns only the x-Digest-Manifest signature and omits the individual
        # section signatures
        return self.signatures.header + "\n"

    def make_signed(self, signature, outpath=None, sigpath=None):
        outpath = outpath or self.outpath
        if not outpath:
            raise IOError("No output file specified")

        if os.path.exists(outpath):
            raise IOError("File already exists: %s" % outpath)

        sigpath = sigpath or signature.filename
        # Normalize to a simple filename with no extension or prefixed
        # directory
        sigpath = os.path.splitext(os.path.basename(sigpath))[0]
        sigpath = os.path.join('META-INF', sigpath)

        with ZipFile(self.inpath, 'r') as zin:
            with ZipFile(outpath, 'w', zipfile.ZIP_DEFLATED) as zout:
                # The PKCS7 file("foo.rsa") *MUST* be the first file in the
                # archive to take advantage of Firefox's optimized downloading
                # of XPIs
                zout.writestr("%s.rsa" % sigpath, signature)
                for f in sorted(zin.infolist()):
                    # Make sure we exclude any of our signature and manifest
                    # files
                    if ignore_certain_metainf_files(f.filename):
                        continue
                    zout.writestr(f, zin.read(f.filename))
                zout.writestr("META-INF/manifest.mf", str(self.manifest))
                zout.writestr("%s.sf" % sigpath, str(self.signatures))
                if self.ids is not None:
                    zout.writestr('META-INF/ids.json', self.ids)


class JarSigner(object):

    def __init__(self, privkey, certchain):
        self.privkey = privkey
        self.chain = certchain
        self.smime = SMIME()
        # We short circuit the key loading functions in the SMIME class
        self.smime.pkey = self.privkey
        self.smime.set_x509_stack(self.chain)

    def sign(self, data):
        # XPI signing is JAR signing which uses PKCS7 detached signatures
        pkcs7 = self.smime.sign(MemoryBuffer(data),
                                PKCS7_DETACHED | PKCS7_BINARY
                                | PKCS7_NOSMIMECAP)
        pkcs7_buffer = MemoryBuffer()
        pkcs7.write_der(pkcs7_buffer)
        return pkcs7


# This is basically a dumbed down version of M2Crypto.SMIME.load_pkcs7 but
# that reads DER instead of only PEM formatted files
def get_signature_serial_number(pkcs7):
    """
    Extracts the serial number out of a DER formatted, detached PKCS7
    signature buffer
    """
    pkcs7_buf = MemoryBuffer(pkcs7)
    if pkcs7_buf is None:
        raise BIOError(Err.get_error())

    p7_ptr = pkcs7_read_bio_der(pkcs7_buf.bio)
    p = PKCS7(p7_ptr, 1)

    # Fetch the certificate stack that is the list of signers
    # Since there should only be one in this use case, take the zeroth
    # cert in the stack and return its serial number
    return p.get0_signers(X509_Stack())[0].get_serial_number()
