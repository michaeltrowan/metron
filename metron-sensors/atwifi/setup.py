#
#  Licensed to the Apache Software Foundation (ASF) under one or more
#  contributor license agreements.  See the NOTICE file distributed with
#  this work for additional information regarding copyright ownership.
#  The ASF licenses this file to You under the Apache License, Version 2.0
#  (the "License"); you may not use this file except in compliance with
#  the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
import os
from setuptools import setup


def fread(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()


def get_version():
    return fread('VERSION')


setup(
    name='atwifi',
    version=get_version(),
    author='ArmoredThings, forked off the Apache pycapa and the AT wifi Tutella scanner',
    author_email='info@armroedthings.com',
    description='Scan for nearby cell devices and publish them every 5 minutes to metron',
    long_description=fread('README.md'),
    entry_points = {
      "console_scripts": ['atwifi = atwifi.atwifi_cli:main'],
    },
    packages=['atwifi']
)
