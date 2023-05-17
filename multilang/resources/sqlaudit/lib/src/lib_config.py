import ConfigParser
import re


class ReadIni(object):
    def __init__(self, config_file):
        self.config_file = config_file
    def get_with_dict(self):
        conf = ConfigParser.ConfigParser()
        conf.read(self.config_file)
        option_dict = {}
        secs = conf.sections()
        for sec in secs:
            option_dict[sec] = {}
            for option in  conf.options(sec):
                key = option
                value = conf.get(sec,key)
                if key=='regex':
                    value=re.compile(value)
                option_dict[sec][key] = value
        return option_dict
