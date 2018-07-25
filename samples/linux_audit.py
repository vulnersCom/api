#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ==============
#      Vulners Linux audit example
# ==============

import vulners

vulners_api = vulners.Vulners()

# Example for CentOS 7
# You can use it for any RPM based OS
# Execute command: rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'
# Use it as package variable input

centos_vulnerabilities = vulners_api.audit(os= 'centos', os_version= '7', package= ['glibc-common-2.17-157.el7_3.5.x86_64'])
vulnerable_packages = centos_vulnerabilities.get('packages')
missed_patches_ids = centos_vulnerabilities.get('vulnerabilities')
cve_list = centos_vulnerabilities.get('cvelist')
how_to_fix = centos_vulnerabilities.get('cumulativeFix')

# Example for Debian 8
# You can use it for any DEB based OS
# Execute command: dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n'
# Use it as package variable input

debian_vulnerabilities = vulners_api.audit(os= 'debian', os_version= '8', package= ['uno-libs3 4.3.3-2+deb8u7 amd64'])
