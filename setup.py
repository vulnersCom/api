#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ==============
#      Pypy setup file
# ==============

from setuptools import setup

dependencies = open('requirements.txt', 'r').read().split('\n')

setup(
    name = 'vulners',
    version = '0.1',
    description = 'Python library and command-line utility for Vulners (https://vulners.com)',
    author = 'Kirill Ermakov',
    author_email = 'isox@vulners.com',
    url = 'https://github.com/vulnersCom/api',
    packages = ['vulners'],
    install_requires = dependencies,
    keywords = ['security', 'network', 'vulners', 'vulnerability', 'CVE'],
    classifiers = [
        "Development Status :: 3 - Alpha",
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