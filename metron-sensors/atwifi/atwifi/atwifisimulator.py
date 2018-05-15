#
# Copyright (c) 2018 by Armored Things, Inc.  All rights reserved.
#

import os
import time
import threading
from simulation import simulation_get_data, simulation_get_source_device
import traceback
import subprocess
from addict import Dict
from dev_utils import get_device_data
from atnet import AtNet
from wifi_constants import manufacturer_oui_prefixes, cellphone_manufacturers
from logging import getLogger

logger = getLogger(__name__)


class AtWifiSimulation(AtNet):
    COLLECTION_FORMAT = "{tshark} -I -i {adapter} -a duration:{scantime} -w {tmpfile}"
    PROCESS_FORMAT = "{tshark} -r {tmpfile} -T fields -e wlan.sa -e wlan.bssid -e radiotap.dbm_antsignal"

    def __init__(self, name, agent_id, description=None, broker_url=None, zookeeper_url=None):
        super(AtWifiSimulation, self).__init__(name, agent_id, description, broker_url, zookeeper_url)
        self.index = 0
        logger.debug('AtWifi initted')

    @staticmethod
    def get_mac_addr(line):
        segments = line.split()
        if len(segments) != 3 or ':' not in segments[0]:
            return None, None

        leader = segments[0].strip().split(',')
        data = segments[2].split(',')

        if len(leader) == 0:
            return None, None
        machine_address = leader[0]
        if len(data) > 1:
            rssi = float(data[0]) / 2 + float(data[1]) / 2
        else:
            rssi = float(data[0])
        return machine_address, rssi

    def scan(self, **kwargs):
        """

        Args:
            **kwargs:

        Returns:

        """
        self.index += 1
        return simulation_get_data(self.index)

    def scan_for_devices(self):
        """
        We can only do scanning on certain chipsets:

        Atheros AR9271, Ralink RT3070, Ralink RT3572, Ralink RT5572, or RaLink RT5372

        Of course, scanning on anything else doesn't break, it just won't produce any results.


        Returns:

        """
        source, device = simulation_get_source_device()
        dev = Dict(major_type='networkscanner', sub_type='wifi', protocol='', name=device,
                       handler=self.name, manufacturer='at', device_id=source, private=device,
                       location=self.location, geolocation=self.geolocation, groups=self.groups,
                       status='Active', controls=None, states=None)

        self.devices = [dev]
        #self.update_state(self.devices)
        # self.signal_scan_completed()
        self.jobs = [None] * len(self.devices)
        return

