# -*- coding: utf-8 -*-
# ===========================
# Setup file
# ===========================

import re
from setuptools import setup, find_packages


version = re.search(r'__version__\s*=\s*"(.+)"', open('vulners/__init__.py', 'rt').read()).group(1)

with open('README.md') as f:
    long_description = f.read()
    

setup(
    name='vulners',
    version=version,
    description ='Python library and command-line utility for Vulners (https://vulners.com)',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Kirill Ermakov',
    author_email='isox@vulners.com',
    url='https://github.com/vulnersCom/api',
    packages=find_packages(exclude=['samples']),
    install_requires = [
        'requests',
        'six'
    ],
    keywords=['security', 'network', 'vulners', 'vulnerability', 'CVE'],
    classifiers =[
        "Development Status :: 5 - Production/Stable",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Topic :: Software Development :: Version Control",
        "Topic :: Utilities"
    ],
)
