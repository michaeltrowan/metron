
import socket
import pymongo
import os
from datetime import datetime
import traceback

_mongo_db = None
_source = None
_device = None

def _init_db_connections(verbose=False):
    dbsettings = dict(host=os.environ.get('AT_SCANNER_DB', 'scannerdb.documents.azure.com'),
                      port=os.environ.get('AT_SCANNER_PORT', 10255),
                      ssl="ssl=true" if os.environ.get('AT_SCANNER_DB_SSL', True) else "",
                      replica=os.environ.get('AT_SCANNER_REPLICA', 'replicaSet=globaldb'),
                      db="athings",
                      user=os.environ.get('AT_SCANNER_USER', 'scannerdb'),
                      pw=os.environ.get('AT_SCANNER_PW', '0UPKuXqxT8bnKJtboIwoiIiGrTUK7Xm5qxEuhMTDlf2zR78t7LsKpzY5k'
                                                             'UDVOadY3uLV6Lro9NUnviURceOxLw=='))
    _mongo_connection_string = "mongodb://{user}:{pw}@{host}:{port}/{db}?{ssl}&{replica}".format(**dbsettings)

    if verbose:
        print "simulation: connecting to mongo database"
    _mongo_db = pymongo.MongoClient(_mongo_connection_string).athings
    try:
        doc = _mongo_db.devices.find_one()
        if verbose:
            print ".... got doc set back <%s>" % doc
    except Exception, e:
        print "ERROR: db connection %s errored out: %s" % (_mongo_connection_string, e)
    if verbose:
        print "INITDB: completed"

    # Find most populous device source
    first = list(_mongo_db.devices.aggregate([{"$group": {"_id": '$source', "adapter": {'$first': '$adapter'},
                                                          "cnt": {'$sum': 1}}},
                                              {"$sort": {"cnt": -1}}]))
    _source = first[0].get('source')
    _device = first[0].get('adapter')
    return


def simulation_get_source_device():
    global _mongo_db, _source, _device
    if _mongo_db is None:
        _init_db_connections(verbose=verbose)

    return _source, _device


def simulation_get_data(index=0, verbose=False):

    global _mongo_db, _source, _device
    if _mongo_db is None:
        _init_db_connections(verbose=verbose)

    try:
        doc = _mongo_db.find(dict(source=_source), sort=[('date', pymongo.ASCENDING)], limit=1, skip=index).next()
    except:
        print "traceback %s" % traceback.format_exc()
        return dict(device="unknown", package=[])

    tod = datetime.now()
    package = dict(device=doc.get('adapter'), package=[])
    for pck in doc.get('data'):
        rssi = pck.get('rssi')
        package['package'].append(dict(company=pck.get('company'), rssi=rssi, rssi_first=rssi, rssi_last=rssi,
                                       rssi_max=rssi, rssi_min=rssi, scan_time=tod))

    return package