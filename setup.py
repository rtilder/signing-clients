""" Setup file.
"""
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.md')) as f:
    README = f.read()


setup(name='signing_clients',
    version='0.1.13',
    description="Applications signature/manifest manipulator and receipt verifier",
    long_description=README,
    classifiers=[
        "Programming Language :: Python",
    ],
    keywords="web services",
    author='Ryan Tilder',
    author_email="service-dev@mozilla.com",
    url="http://mozilla.org",
    install_requires=["M2Crypto"],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    test_suite='signing_clients.tests'
)
