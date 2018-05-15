
import os
import yaml


class AtSensor(object):

    def __init__(self, name, agent_id, description=None, broker_url=None, zookeeper_url=None, config_file=None):

        if config_file is None:
            config_file = "atwifi.yml"

        self.variables = self.load_yaml(config_file)
        return

    def cget(self, cname, default=None):
        return os.environ.get(cname.upper(), self.variables.get(cname, default))

    def load_yaml(self, filename):
        # if they don't tell us, try this directory and everything on up
        load_path = os.environ.get('AT_CONFIG_PATH', '.:..:../..:../../..:/etc:/usr/local/etc')

        if os.path.dirname(__file__) not in load_path:
            load_path += ":%s" % os.path.dirname(__file__)

        if filename.startswith('/'):
            # add no directory at the front so we get the absolute path
            load_path = ":%s" % load_path
        for path in load_path.split(':'):
            fpath = "%s/%s" % (path, filename)
            if os.path.exists(fpath):
                with open(fpath, 'r') as _f:
                    return yaml.load(_f.read())
        return dict()
