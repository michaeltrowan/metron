#
# Copyright (c) 2018 by Armored Things, Inc.  All rights reserved.
#

import json
import pytz
import bcrypt
import socket

from addict import Dict
from atsensor import AtSensor

from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler

logger = get_logger(__name__)


class AtNet(AtSensor):

    def __init__(self, name, agent_id, description=None, broker_url=None, zookeeper_url=None):
        super(AtNet, self).__init__(name, agent_id, description, broker_url, zookeeper_url)

        self.name = name if name is not None else __name__.lower()
        # FIXME - we need a thread for each devices in start, and we need to build these commands in scan based on
        # the device.
        self.updates = []

        # FIXME -- end

        self.timezone = pytz.UTC
        self.api = {}
        self.hostname = socket.gethostname()
        self.location = self.cget('location')
        self.geolocation = self.cget('geolocation')
        self.groups = self.cget('groups')
        self.pattern = self.cget('pattern', '')
        self.anonymize = self.cget('anonymize', False)
        self.annotate = self.cget('annotate', True)
        self.scan_time = self.cget('scan_time', 60)
        self.frequency = self.cget('frequency', dict(minute="*/5"))
        # If set, this brackets what RSSI's will count as a occupant.
        self.minimum_rssi = self.cget('minimum_rssi')
        self.maximum_rssi = self.cget('maximum_rssi')

        self.salt = self.cget('anon_salt', '$2a$31$FWpEhDxhvvb.g2/S6xrcKe')
        self.jobs = []
        self.devices = []
        self.scheduler = BackgroundScheduler()
        self.started = False

        self.queued_results = []

    def _anonymize_mac(self, mac, package):

        if self.anonymize:
            package['mac'] = bcrypt.hashpw(mac, self.salt)
        else:
            package['mac'] = mac

        if self.anonymize and self.annotate:
            package['_real_mac'] = mac

        return

    def get_next_packet(self):
        import time
        while len(self.queued_results) < 1:
            logger.debug('... no packet ready, sleeping...')
            time.sleep(60)

        logger.debug('... returning packet')
        return self.queued_results.pop(0)

    def update_state(self, devices):
        dt = datetime.now(tz=self.timezone)
        if isinstance(devices, list) is False:
            devices = [devices]

        for device in devices:
            logger.debug('Device scan %s starting', device.get('name'))
            package = self.scan(**device)
            # self.update_device_state(device, 'nearby', package, force=True)
            self.queued_results.append(dict(device=device, package=package, scan_time=dt))
            logger.debug('Device scan %s complete - package %s', device.get('name'), json.dumps(package))

        logger.debug('update_state complete')
        #self._tweak_update_list(dt, datetime.now(tz=self.timezone))
        #for device in devices:
        #    self._publish_occupancy(device)

    def _tweak_update_list(self, started, ended):
        self.updates.insert(0, Dict(started=started, ended=ended))
        if len(self.updates) > 5:
            self.updates = self.updates[:5]
        return

    def update_device_state(self, device, state, data, force=False):
        raise RuntimeError('update_device_state must be overridden')

    def scan(self, *args, **kwargs):
        raise RuntimeError('scan must be overridden')

    def _count_in_occupancy(self, mac_entry, peer_entry):
        """
        Calculate whether our entry for this mac address should be in our occupancy or in the peers.

        Currently this is just blindly comapring the rssi value, which is the average rssi reading over the minute
        of scanning we did.

        Args:
            mac_entry:
            peer_entry:

        Returns:

        """
        rssi = mac_entry.get('rssi')

        if self.minimum_rssi is not None:
            if self.minimum_rssi > rssi or self.maximum_rssi < rssi:
                logger.debug('rssi entry for %s out of range (%s > this %s > %s)', mac_entry.get('mac'),
                             self.minimum_rssi, rssi, self.maximum_rssi)
                return False

        if rssi > peer_entry.get('rssi'):
            return True
        return False

    def _publish_occupancy(self, device):
        """
        Walk the last cycle's data (not the one we just recorded) and see which mac addresses were closest to us (vs
        everyone else) -- we only want one device counting a "mac" at a time.

        This is all going to move to a ML model and get much more sophisticated -- our calculation of our own
        "occupancy" at the scanner device level might be useful later too -- but for now it's a proxy for the ML
        occupancy we want to do later.

        Returns:
            nada

        """

        if len(self.updates) < 2:
            return
        ending_time = self.updates[0].started - timedelta(seconds=60)
        starting_time = self.updates[1].started - timedelta(seconds=60)
        events = svc.dlsGetControls(utc_date={'$gt': starting_time, '$lt': ending_time}, device_handler='atwifi',
                                    device_class=device.get('major_type'), state='nearby').run()
        my_entry = None
        for event in events:
            logger.debug('checking event: %s', event)
            if event.get('state') != 'nearby':
                logger.debug('ERROR: got event %s --', event)
                continue
            try:
                # datetime.strptime(s, '%Y-%m-%d %H:%M:%S.%f')
                logger.debug('TIME %s (%s)', event.get('utc_date'), type(event.get('utc_date')))

                if ending_time > event.get('utc_date') > starting_time:
                    logger.debug('DATEERROR: event out of window %s - %s -- %s  : %s', event.get('utc_date'), starting_time,
                                 ending_time, event)
            except:
                logger.debug('%s > %s > %s', ending_time, event.get('utc_date'), starting_time)

            logger.debug('checking event %s', event)
            if event.get('device_id') == device.get('device_id'):
                logger.debug('found myself...')
                my_entry = event
            # Let's create a dict for each comparison
            macs = dict()
            for mac in event.get('value', []):
                logger.debug('tweaking mac %s', mac)
                macs[mac.get('mac')] = mac
            event['_maclist'] = macs

        if my_entry is None:
            logger.error('There was no entry for this device (%s) between %s and %s', device.get('device_id'),
                         starting_time, ending_time)
            logger.error('Entries: %s', events)
            return

        events.remove(my_entry)
        my_macs = my_entry.get('_maclist')
        for event in events:
            for key in event.get('_maclist').keys():
                if key in my_macs.keys():
                    if not self._count_in_occupancy(my_macs[key], event['_maclist'][key]):
                        logger.debug('mac %s has better values in %s - not counting for %s', key,
                                     event.get('device_id'), device.get('device_id'))
                        del my_macs[key]

        self.update_device_state(device, 'occupancy', dict(occupancy=len(my_macs), time=self.updates[1].ended,
                                                           macs=my_macs.keys()), force=True)
        return

    def start(self, device_ids=None):
        if self.scheduler.running:
            return

        if len(self.devices) != len(self.scheduler.get_jobs()):
            if self.scheduler.running:
                self.scheduler.shutdown()
            self.scheduler.remove_all_jobs()

            for idx, device in enumerate(self.devices):
                self.jobs[idx] = self.scheduler.add_job(self.update_state, args=(device,), trigger="cron",
                                                        **self.frequency)

        self.scheduler.start()
        return

    def stop(self):
        self.started = False
        if self.scheduler.running:
            self.scheduler.shutdown()

