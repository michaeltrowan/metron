#
# Copyright (c) 2018 by Armored Things, Inc.  All rights reserved.
#

import os
import time
import threading
import netifaces
import traceback
import subprocess
from addict import Dict
from dev_utils import get_device_data
from atnet import AtNet
from wifi_constants import manufacturer_oui_prefixes, cellphone_manufacturers
from logging import getLogger

logger = getLogger(__name__)


class AtWifi(AtNet):
    COLLECTION_FORMAT = "{tshark} -I -i {adapter} -a duration:{scantime} -w {tmpfile}"
    PROCESS_FORMAT = "{tshark} -r {tmpfile} -T fields -e wlan.sa -e wlan.bssid -e radiotap.dbm_antsignal"

    def __init__(self, name, agent_id, description=None, broker_url=None, zookeeper_url=None):
        super(AtWifi, self).__init__(name, agent_id, description, broker_url, zookeeper_url)

        self.tshark = None
        for path in os.environ["PATH"].split(':'):
            tshark = "%s/%s" % (path, 'tshark')
            if os.path.isfile(tshark) and os.access(tshark, os.X_OK):
                self.tshark = tshark
        if self.tshark is None:
            raise RuntimeError('No Tshark installed in PATH')
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
        arguments = dict(tmpfile='/tmp/tshark_%s_%s.output' % (os.getpid(), kwargs.get('private')),
                         tshark=self.tshark, scantime=self.scan_time, adapter=kwargs.get('private'))
        collection = self.COLLECTION_FORMAT.format(**arguments).split()
        analysis = self.PROCESS_FORMAT.format(**arguments).split()

        timer = threading.Thread(target=time.sleep, args=(self.scan_time,))
        timer.daemon = True
        timer.start()
        run_tshark = subprocess.Popen(collection, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, errors = run_tshark.communicate()
        timer.join()
        rc = run_tshark.returncode
        logger.debug('thark collection returned %s, output lenght is %s', rc, -1 if stdout is None else len(stdout))
        if rc != 0:
            logger.error('Tshark error %s\n---stdout:\n%s\n---stderr:\n%s', rc, stdout, errors)
            return

        run_tshark = subprocess.Popen(analysis, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, errors = run_tshark.communicate()
        rc = run_tshark.returncode
        logger.debug('thark analysis returned %s, output length is %s', rc, -1 if output is None else len(output))
        if rc != 0:
            logger.error('Tshark error %s\n---stdout:\n%s\n---stderr:\n%s', rc, stdout, errors)
            return

        mac_addrs = dict()
        for line in output.decode('utf-8').split('\n'):
            mac, rssi = self.get_mac_addr(line.strip())

            if mac is None:
                continue
            # Save the rssi's as a list so we can average them if we get multiple readings.
            if mac not in mac_addrs:
                mac_addrs[mac] = [rssi]
            else:
                mac_addrs[mac].append(rssi)

        package = []
        for mac, rssi_list in mac_addrs.items():
            prefix = mac[:8]
            oui_id = manufacturer_oui_prefixes.get(prefix)
            if oui_id in cellphone_manufacturers:
                entry = dict(company=oui_id, rssi=float(sum(rssi_list)) / float(len(rssi_list)),
                             rssi_first=rssi_list[0], rssi_last=rssi_list[-1], scan_time=self.scan_time,
                             rssi_max=max(rssi_list), rssi_min=min(rssi_list))
                self._anonymize_mac(mac, entry)
                package.append(entry)

        return package

    def scan_for_devices(self):
        """
        We can only do scanning on certain chipsets:

        Atheros AR9271, Ralink RT3070, Ralink RT3572, Ralink RT5572, or RaLink RT5372

        Of course, scanning on anything else doesn't break, it just won't produce any results.


        Returns:

        """
        _supported_vendors = ['ralink', 'atheros']
        _supported_chips = ['AR9271', 'RT3070', 'RT3572', 'RT5572', 'RT5372']
        networks = get_device_data('network', 'wireless')
        # self.signal_scan_started()
        self.devices = []
        for iface in netifaces.interfaces():
            interface = networks.get(iface)

            if interface is None:
                logger.debug('Network interface %s not in the lshw output (%s)', iface, networks.keys())
                continue

            vendor = interface.get('vendor', '').lower()
            if vendor not in _supported_vendors:
                logger.debug('Skipping interface %s - vendor %s', iface, vendor)
                continue

            if 'wireless' not in interface.get('description', '').lower():
                logger.debug('Skipping interface %s - not wireless (%s)', iface, interface.get('description'))
                continue

            devid = "%s--%s" % (self.hostname, len(self.devices))
            logger.debug('Found network wifi port %s, Vendor %s, ', iface, interface.get('vendor'))
            dev = Dict(major_type='networkscanner', sub_type='wifi', protocol='', name=iface,
                       handler=self.name, manufacturer=vendor, device_id=devid, private=iface,
                       location=self.location, geolocation=self.geolocation, groups=self.groups,
                       status='Active', controls=add_controls('networkscanner', 'wifi'),
                       states=add_states("networkscanner", "wifi"))

            self.devices.append(dev)
            logger.debug('Adding devices %s', str(dev))

        self.save_devices(self.devices)
        #self.update_state(self.devices)
        # self.signal_scan_completed()
        self.jobs = [None] * len(self.devices)
        return


def networkscanner_wifi_api_factory(name, agent_id, description, broker_url, zookeeper_url):
    return AtWifi(name, agent_id, description=description, broker_url=broker_url, zookeeper_url=zookeeper_url)


def main():
    import os
    import sys
    import signal
    import argparse

    parser = argparse.ArgumentParser(description='Start the wifi scanner agent.')
    parser.add_argument('--debug', "-d", action='store_true', default=False,
                        help='connect to python debugger')

    args = parser.parse_args()

    if args.debug:
        initialize_debug()

    def _sigterm_handler(signum, frame):
        logger.info('Caught signal %d, shutting down (%r)', signum, frame)
        agent.stop()
        agent.shutdown()

    signal.signal(signal.SIGTERM, _sigterm_handler)
    signal.signal(signal.SIGINT, _sigterm_handler)

    broker = os.environ.get('AT_BROKER_URL', 'amqp://atuser:atuser@atbroker/armoredthings')
    zookeeper = os.environ.get('AT_ZOOKEEPER_URL', '127.0.0.1:2181')

    agent = networkscanner_wifi_api_factory('atwifi', 136, 'wifi scanner agent', broker, zookeeper)
    try:
        agent.start_consumer(None)
        agent.startup()
        agent.scan_for_devices()
        agent.start()
        agent.loop_forever()
    except Exception as e:
        print traceback.format_exc()
        pass

    agent.stop()
    agent.shutdown()


if __name__ == '__main__':
    main()

