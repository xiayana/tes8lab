# -*- coding: utf-8 -*-
import configparser
import re
import os
import sys
import logging
import json

class ReadIni(object):
    def __init__(self, config_file):
        self.config_file = config_file
    def get_with_dict(self):
        conf = configparser.ConfigParser()
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
                option_dict[sec][key] = self.getStr2number(value)
        return option_dict
    
    def getStr2number(self,s):
        #把能够转化为数字的值转化为数字
        if s.isdigit():
            return int(s)
        try:
            v=float(s)
        except ValueError:
            v=s
            
        return v
    
try:
    if not os.path.isfile(sys.argv[1]):
        print("FAIL")
    else:
        conf=ReadIni(sys.argv[1]).get_with_dict()
        print(json.dumps(conf))
except Exception as e:
    print("EXPT")
    print(repr(e))
    