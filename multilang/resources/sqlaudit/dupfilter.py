#coding=utf8
import logging
import sys
import time
import re
import os
import traceback
from collections import namedtuple
from collections import deque
reload(sys)
sys.setdefaultencoding('utf-8')
import storm

from lib.alertbase import alert
from lib.dexport import *
#import lib.conf as nisacf
import json


log = logging.getLogger('dupfilter')

#grouping by host
class DupfilterBolt(storm.BasicBolt):
    #重复过滤和启发式引擎
    #{time,user,ip,cmd,src,dst,ppname,flag}
    def initialize(self,conf, context):
        log.info("dupfilter module init...")
        self.active={} #存储主机之前的3条不同记录
        self.conf=sqlconf.conf
        self.getfilter()
        self.getexport()
    
    def getexport(self):
        self.export=[]
        if not self.conf.has_key('export'):
            return
        gdict=globals()
        for i in self.conf['export']['type'].split(','):
            i=i.strip()
            if not i:continue
            key="export_%s" %i
            if gdict.has_key(key):
                epclass=gdict[key]
                self.export.append(epclass(self.conf['export'],log))
                
    def getfilter(self):
        self.dfilter={}
        if not self.conf.has_key('filter'):
            return
        for k,v in self.conf['filter'].iteritems():
            self.dfilter[k]=self.conf['filter'][k].strip().split(';')
        #log.debug(self.dfilter)
            
    def process(self, tup):
        table,tup=tup.values
        if self.confilter(tup):return #配置过滤
        #if self.active.has_key(host):
        #临时过滤策略
        log.debug(str(tup))
        map(lambda x:x.write(tup),self.export)
        storm.emit((table,tup)) #常规数据发送到后续检测流
     
    def confilter(self,tup):
        #配置文件定义过滤
        for k,v in self.dfilter.iteritems():
            for i in self.dfilter[k]:
                if not i:continue
                if tup[k].find(i)>=0:
                    return True
        return False
        
class contain:
    conf=None     
    
if __name__ == '__main__':
    sqlconf=contain()
    sqlconf.conf=json.loads(sys.argv[1])
    log.info("[INFO] config info: %s" %str(sqlconf.conf))
    if sqlconf.conf['system'].has_key('log'):
        sqlog=sqlconf.conf['system']['log']
    else:
        sqlog='/tmp/sqlnisa'
        
    if not sqlconf.conf['system'].has_key('level'):
        pylog=logging.INFO
    elif sqlconf.conf['system']['level']=='debug':
        pylog=logging.DEBUG
    elif sqlconf.conf['system']['level']=='info':
        pylog=logging.INFO
    elif sqlconf.conf['system']['level']=='error':
        pylog=logging.ERROR
    else:
        pylog=logging.INFO
        
    logging.basicConfig(
        level=pylog,
        filename=os.path.join(sqlog,'dupfilter.log'),
        format="%(message)s",
        filemode='w',
    )

    try:
        DupfilterBolt().run()
    except Exception,e:
        log.error("[Error] %s" %repr(e))
        log.error("[Error INFO] %s" %traceback.format_exc())
    
