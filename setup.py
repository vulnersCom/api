# -*- coding: utf-8 -*-
# ===========================
# Setup file
# ===========================

from setuptools import setup, find_packages

setup(
    name = 'vulners',
    version = '1.0',
    description = 'Python library and command-line utility for Vulners (https://vulners.com)',
    author = 'Kirill Ermakov',
    author_email = 'isox@vulners.com',
    url = 'https://github.com/vulnersCom/api',
    packages = find_packages(exclude=['samples']),
    install_requires = [
        'requests'
    ],
    keywords = ['security', 'network', 'vulners', 'vulnerability', 'CVE'],
    classifiers = [
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