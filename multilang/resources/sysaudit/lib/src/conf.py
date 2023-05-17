#coding=utf8

import configparser
import re

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
    
class conf:
    def __init__(self,confp,log=None):
        self.confpath=confp
        self.conf=ReadIni(self.confpath).get_with_dict()
        if log and (not self.conf):
            log.error("[Error] config not vaild,again")
        '''
        self.conf={}
        self.conf['system']={'hdfspath':'/tmp/nisax',
                     'deltmp':0}
        self.conf['server']={'host':'172.17.0.2',
                     'port':9099,
                     'name':'admin',
                     'passwd':'secret',
                     'upload':0}#是否更新到远程服务器
        self.conf['hdfs']={'host':'172.17.0.2',
                   'port':8020}
        #定义滑动窗口包含事件,sec表明sec秒一窗口,当队列消息长度达maxlen时同样触发生成窗口检测
        #定义每生成一个窗口,事件队列减小1/divisor
        self.conf['window']={'sec':60,
                     'maxlen':30,
                     'divisor':4}
        #定义每个用户,每个算法的告警冷却时间,默认60s
        self.conf['alert']={'dup':60}
        
        self.conf['parameter']={'part':6,
                     'pearson_cov':0.5,
                     'kdm_parameter':4,
                     'time_kdm_parameter':3,
                     'malcov_p':0.25,
                     'ngram_cov':0.5,
                     }
        '''
