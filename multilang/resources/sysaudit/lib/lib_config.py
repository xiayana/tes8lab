import configparser
import re
import sys
import os

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
                option_dict[sec][key] = value
        return option_dict

#预处理启发式知识结构
def parseHeuristicKnowledge(knowledge):
    heuristic_flag=knowledge['heuristic_flag']
    for name,flagset in heuristic_flag.items():
        for key,model in flagset['condition'].items():
            if 'ree' in model:
                model['ree']=re.compile(model['ree'])

def loadmodule(mpath):
    #根据绝对路径动态加载模块
    import importlib
    d,kname=os.path.split(mpath)
    if d not in sys.path:
        sys.path.append(d)
    
    module=importlib.import_module(kname)
    return module

