# coding=utf-8
# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

import unittest

from signing_clients.apps import Manifest, JarExtractor, ParsingError


MANIFEST = """Manifest-Version: 1.0

Name: test-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: 5BXJnAbD0DzWPCj6Ve/16w==
SHA1-Digest: 5Hwcbg1KaPMqjDAXV/XDq/f30U0=

Name: test-dir/nested-test-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: 53dwfEn/GnFiWp0NQyqWlA==
SHA1-Digest: 4QzlrC8QyhQW1T0/Nay5kRr3gVo=
"""

SIGNATURE = """Signature-Version: 1.0
MD5-Digest-Manifest: dughN2Z8uP3eXIZm7GVpjA==
SHA1-Digest-Manifest: rnDwKcEuRYqy57DFyzwK/Luul+0=
"""

SIGNATURES = SIGNATURE + """
Name: test-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: jf86A0RSFH3oREWLkRAoIg==
SHA1-Digest: 9O+Do4sVlAh82x9ZYu1GbtyNToA=

Name: test-dir/nested-test-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: YHTqD4SINsoZngWvbGIhAA==
SHA1-Digest: lys436ZGYKrHY6n57Iy/EyF5FuI=
"""

CONTINUED_MANIFEST = MANIFEST + """
Name: test-dir/nested-test-dir/nested-test-dir/nested-test-dir/nested-te
 st-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: 53dwfEn/GnFiWp0NQyqWlA==
SHA1-Digest: 4QzlrC8QyhQW1T0/Nay5kRr3gVo=
"""

# Test for 72 byte limit test
BROKEN_MANIFEST = MANIFEST + """
Name: test-dir/nested-test-dir/nested-test-dir/nested-test-dir/nested-test-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: 53dwfEn/GnFiWp0NQyqWlA==
SHA1-Digest: 4QzlrC8QyhQW1T0/Nay5kRr3gVo=
"""

VERY_LONG_MANIFEST = """Manifest-Version: 1.0

Name: test-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: 5BXJnAbD0DzWPCj6Ve/16w==
SHA1-Digest: 5Hwcbg1KaPMqjDAXV/XDq/f30U0=

Name: test-dir/nested-test-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: 53dwfEn/GnFiWp0NQyqWlA==
SHA1-Digest: 4QzlrC8QyhQW1T0/Nay5kRr3gVo=

Name: test-dir/nested-test-dir-0/nested-test-dir-1/nested-test-dir-2/lon
 g-path-name-test
Digest-Algorithms: MD5 SHA1
MD5-Digest: 9bU/UEp83EbO/DWN3Ds/cg==
SHA1-Digest: lIbbwE8/2LFOD00+bJ/Wu80lR/I=
"""

# Test for Unicode
UNICODE_MANIFEST = """Manifest-Version: 1.0

Name: test-dir/súité-höñe.txt
Digest-Algorithms: MD5 SHA1
MD5-Digest: +ZqzWWcMtOrWxs8Xr/tt+A==
SHA1-Digest: B5HkCxgt6fXNr+dWPwXH2aALVWk=
"""


class SigningTest(unittest.TestCase):

    def _extract(self, omit=False):
        return JarExtractor('signing_clients/tests/test-jar.zip',
                            'signing_clients/tests/test-jar-signed.jar',
                            omit_signature_sections=omit)

    def test_00_extractor(self):
        self.assertTrue(isinstance(self._extract(), JarExtractor))

    def test_01_manifest(self):
        extracted = self._extract()
        self.assertEqual(str(extracted.manifest), MANIFEST)

    def test_02_signature(self):
        extracted = self._extract()
        self.assertEqual(str(extracted.signature), SIGNATURE)

    def test_03_signatures(self):
        extracted = self._extract()
        self.assertEqual(str(extracted.signatures), SIGNATURES)

    def test_04_signatures_omit(self):
        extracted = self._extract(True)
        self.assertEqual(str(extracted.signatures), SIGNATURE)

    def test_05_continuation(self):
        manifest = Manifest.parse(CONTINUED_MANIFEST)
        self.assertEqual(str(manifest), CONTINUED_MANIFEST)

    def test_06_line_too_long(self):
        self.assertRaises(ParsingError, Manifest.parse, BROKEN_MANIFEST)

    def test_07_wrapping(self):
        extracted = JarExtractor('signing_clients/tests/test-jar-long-path.zip',
                                 'signing_clients/tests/test-jar-long-path-signed.jar',
                                 omit_signature_sections=False)
        self.assertEqual(str(extracted.manifest), VERY_LONG_MANIFEST)

    def test_08_unicode(self):
        extracted = JarExtractor('signing_clients/tests/test-jar-unicode.zip',
                                 'signing_clients/tests/test-jar-unicode-signed.jar',
                                 omit_signature_sections=False)
        self.assertEqual(str(extracted.manifest), UNICODE_MANIFEST)
