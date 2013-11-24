#!/usr/bin/env python
# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
# 
# Software distributed under the License is distributed on an "AS IS"
# basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
# License for the specific language governing rights and limitations
# under the License.
# 
# The Original Code is pynsca.
#
# The Initial Developer of the Original Code is Dustin J. Mitchell.  Portions
# created by Dustin J. Mitchell are Copyright (C) Mozilla, Inc. All Rights
# Reserved.
#
# Alternatively, the contents of this file may be used under the terms of the
# GNU Public License, Version 2 (the  "GPLv2 License"), in which case the
# provisions of GPLv2 License are applicable instead of those above. If you
# wish to allow use of your version of this file only under the terms of the
# GPLv2 License and not to allow others to use your version of this file under
# the MPL, indicate your decision by deleting the provisions above and replace
# them with the notice and other provisions required by the GPLv2 License. If
# you do not delete the provisions above, a recipient may use your version of
# this file under either the MPL or the GPLv2 License.

import os
from setuptools import setup, find_packages

descr = open(os.path.join(os.path.dirname(__file__), 'README.txt')).read()

setup(
    name='pynsca',
    version='1.5',
    description='Simple Python interface to Nagios Service Check Architecture',
    long_description=descr,
    author='Dustin J. Mitchell',
    author_email='dustin@mozilla.com',
    url='http://github.com/djmitche/pynsca',
    license='MPL-1.1',
    packages=find_packages(),
    py_modules=['pynsca'],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Mozilla Public License 1.1 (MPL 1.1)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
