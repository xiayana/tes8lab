#coding=utf8
import logging
from collections import namedtuple
import sys
import os
import time
import traceback
#import pandas as pd
import numpy as np
reload(sys)
sys.setdefaultencoding('utf-8')

import lib.opert as opert
#import lib.conf as nisacf
import json

from lib.alertbase import alert
import lib.lib_alg
import algorithm
import storm

log = logging.getLogger('tablemodel')


    
class TableModelBolt(storm.BasicBolt):
    
    def initialize(self,conf, context):
        #初始化,获取配置信息,读取用户画像,实例化检测对象
        self.window = {} #存储待检测队列
        self.conf=sqlconf
        self.readmodels()
        self.userstatsdf={}
        self.alg=algorithm.startcheck(self.conf,log)
        log.debug("============initialize succfully==================")
  
    
    def readmodels(self): 
        #加载所有用户画像数据
        log.info("read models...")
        opt=opert.opert(self.conf.conf)
        self.models= opt.getusermodel(log,self.conf.conf['system']['account'],'sqlaudit',whiltlist=['table_alg'])
        log.info("=============Load models succfully=================")
        #输出画像到日志
        log.info('loads sqlaudit table models %d' %(len(self.models)))
        #for host,objdict in self.models.iteritems():
        #    log.debug(host+':'+str(objdict))
              
    def getblock(self):
        h=int(time.ctime()[11:13])
        div = 24 / int(self.conf.conf['parameter']['part'])
        return h / div
    
    def calcStat(self,user,tup):
        self.userstatsdf.setdefault(user,{})
        b=self.getblock()
        if len(self.userstatsdf[user])==0 or self.userstatsdf[user]['block']!=b:
            self.userstatsdf[user]={'block':b,'stats':{},'cmdsum':0}
        #self.userstatsdf[user]['stats'].setdefault(tup['cmd'],0)
        #self.userstatsdf[user]['stats'][tup['cmd']]+=1
        self.userstatsdf[user]['cmdsum']+=1
    
    
    def IsDetection(self,user):
        if self.window[user][-1]['time']-self.window[user][0]['time']>=self.conf.conf['window']['sec']: #时间窗口定义
            log.debug("send window with time window")
            return True
        elif len(self.window[user])>=self.conf.conf['window']['maxlen']: #或者在时间窗口内事件数超过maxlen个，直接开始异常检测
            log.debug("send window with event window")
            return True
        return False
    
    #调试状态下，打印检测窗口
    def printwindowlist(self,user,winlist):
        if not log.isEnabledFor("DEBUG"):
            return
        log.debug("%s %d sum" %(user,len(winlist)))
        #for event in winlist:
        #    log.debug(str(event))

    def process(self,tup):
        #{'time':1,'user':2,'ip':3,'cmd':4,'table':5,'src':6}
        table,tup=tup.values
        if not self.models.has_key(table): #判定是否用对应用户画像,暂时不对table为null的对象进行检测
            #log.debug("[NOT_MODEL] Have not model with %s" %table)
            storm.emit((tup['user'],tup)) #后续数据转发
            return
        
        self.calcStat(table,tup)
        if not self.window.has_key(table):
            self.window[table]=[tup]
        else:
            self.window[table].append(tup)
        
        if not self.IsDetection(table): #未触发检测，添加数据队列后直接返回
            storm.emit((tup['user'],tup)) #后续数据转发
            return

        windowlist=self.window[table]
        self.printwindowlist(table,windowlist)

        rss=self.alg.start(table, windowlist, self.models[table],self.userstatsdf[table])#,self.userstatsdf[user]) #异常检测调用
        self.window[table]=self.window[table][len(windowlist)/self.conf.conf['window']['divisor']:] #待检测事件队列更新,删除队列中的前1/divisor事件
        map(lambda x:log.debug("[Alert:] %s %s" %(table,x[2])),rss)  
        log.debug("================")        
        if rss:
            storm.emit((table,rss)) #发现异常，进入告警blot
            
        storm.emit((tup['user'],tup)) #后续数据转发

class contain:
    conf=None     
    
if __name__ == '__main__':
    sqlconf=contain()
    sqlconf.conf=json.loads(sys.argv[1])
    
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
        filename=os.path.join(sqlog,'tablemodel.log'),
        format="%(message)s",
        filemode='w',
    )
    try:
        TableModelBolt().run()
    except Exception,e:
        log.error("[Error] %s" %repr(e))
        log.error("[Error INFO] %s" %traceback.format_exc())
    