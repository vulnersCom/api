# -*- coding: utf-8 -*-

import re
import os
from setuptools import setup, find_packages


def get_version(package):
    init_py = open(os.path.join(package, "__init__.py")).read()
    return re.search("__version__ = ['\"]([^'\"]+)['\"]", init_py).group(1)


def get_long_description(long_description_file):
    long_description = open(long_description_file).read()
    return long_description


setup(
    name="vulners",
    version=get_version("vulners"),
    description="Python library and command-line utility for Vulners (https://vulners.com)",
    long_description=get_long_description("README.md"),
    long_description_content_type="text/markdown",
    author="Kirill Ermakov, Andrei Churin",
    author_email="isox@vulners.com, aachurin@gmail.com",
    url="https://github.com/vulnersCom/api",
    packages=find_packages(exclude=["samples"]),
    install_requires=["requests", "six", "appdirs"],
    keywords=["security", "network", "vulners", "vulnerability", "CVE"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Topic :: Software Development :: Version Control",
        "Topic :: Utilities",
    ],
)
