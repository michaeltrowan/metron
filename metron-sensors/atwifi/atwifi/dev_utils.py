#
# Copyright (c) 2018 by Armored Things, Inc.  All rights reserved.
#

import subprocess
from datetime import datetime
import struct
import logging
logger = logging.getLogger(__name__)


# lifted from metron's common.py in pycapa -- marked with copyright
#
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



def to_hex(s):
    """ Transforms a string to hexadecimal notation. """
    hex_str = ' '.join("{0:02x}".format(ord(c)) for c in s)
    return '\n'.join([hex_str[i:i+48] for i in range(0, len(hex_str), 48)])


def to_date(epoch_micros):
    """ Transforms a timestamp in epoch microseconds to a more legible format. """
    epoch_secs = epoch_micros / 1000000.0
    return datetime.fromtimestamp(epoch_secs).strftime('%Y-%m-%d %H:%M:%S.%f')


def pack_ts(ts):
    """ Packs a timestamp into a binary form. """
    return struct.pack(">Q", ts)


def unpack_ts(packed_ts):
    """ Unpacks a timestamp from a binary form. """
    return struct.unpack_from(">Q", bytes(packed_ts), 0)[0]

#
#  end of the stuff from common.py in the apache code
#


def _break_up_config(container, config):
    key = None
    previous_key = None
    config_list = config.split('=')
    for _index in range(len(config_list)):
        if key is None:
            key = config_list[_index]
            continue
        previous_key = key
        val = config_list[_index]
        last_space = val.rfind(' ')

        # The value will have both the value and the next key -- and the value may have spaces in it.
        if last_space != -1:
            container['config_' + key] = val[:last_space].strip()
            key = val[last_space:].strip()
        else:
            container['config_' + key] = val
            key = None

    if key is not None:
        container['config_' + previous_key] += " %s" % key

    return


def get_hci_addresses():
    """
    # hcitool dev
    Devices:
        hci0    74:E5:F9:9E:79:96


    Returns:

    """
    proc = subprocess.Popen(['hcitool', 'dev'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, errors = proc.communicate()
    if proc.returncode != 0:
        logger.error('hcitool failed, can not find bluetooth interfaces. (rc %s, errors %s)', proc.returncode, errors)
        raise RuntimeError('no hcitool')

    hcis = dict()
    for line in output.splitlines():
        if line.startswith('Devices'):
            continue
        parts = line.strip().split()
        if len(parts) == 2:
            hcis[parts[0]] = parts[1]
    return hcis


def get_device_data(classname='network', capability=None):
    """

    Returns:

    """
    proc = subprocess.Popen(['lshw', '-C', classname], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, errors = proc.communicate()
    if proc.returncode != 0:
        logger.error('lshw failed, can not find network interfaces. (rc %s, errors %s)', proc.returncode, errors)
        raise RuntimeError('no lshw')
    current_entry = None
    networks = dict()
    for line in output.splitlines():
        line = line.strip()
        if line.startswith('*-'):
            name = line.replace('*-', '')
            current_entry = dict()
            #networks[name] = current_entry
            continue
        key, _, value = line.partition(':')
        current_entry[key.strip()] = value.strip()
        if key.lower() == 'configuration':
            _break_up_config(current_entry, value)
        elif key.lower() == 'logical name':
            networks[value.strip()] = current_entry

    if capability is not None:
        if capability == 'bluetooth':
            hci_package = get_hci_addresses()
            hci_keys = sorted(hci_package.keys())

        new_networks = dict()
        _index = 0
        for dev, package in networks.items():
            if package.get('capabilities').find(capability) != -1:
                new_networks[dev] = package
                # FIXME:  This is wrong -- how do we match the HCI dev to the devid/stuff in lshw?  works for 1, so go
                if capability == 'bluetooth' and len(hci_keys) > _index:
                    new_networks[dev]['hci'] = hci_keys[_index]
                    _index += 1

        networks = new_networks
    return networks

