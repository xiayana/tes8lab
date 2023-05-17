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
import algorithm

import storm

log = logging.getLogger('detection')


class DectBaseBolt(storm.BasicBolt):
    
    
    def initialize(self,conf, context):
        #初始化,获取配置信息,读取用户画像,实例化检测对象
        
        self.window = {} #存储待检测队列
        self.conf=sqlconf
        #self.today=self.Getoday()
        #algorithm.algconf=self.conf()
        self.readmodels()
        self.userstatsdf={}
        self.alg=algorithm.startcheck(self.conf,log)
        log.info("============initialize succfully==================")
        
    def Getoday(self):
        now=time.time()
        return now-(now%86400)+time.timezone
    
    def createuserdf(self,user,cmdset):
        l=len(cmdset)
        df=pd.DataFrame(np.zeros((24,l),dtype=np.int32),index=range(24),columns=cmdset)
        self.userstatsdf[user]=df
        return df
    
    def readmodels(self): 
        #加载所有用户画像数据
        log.info("read models...")
        opt=opert.opert(self.conf.conf)
        self.models=opt.getusermodel(log,self.conf.conf['system']['account'],'sqlaudit',whiltlist=['user_alg'])
        log.info("=============Load models succfully=================")
        #输出画像到日志
        log.info('loads sqlaudit user models %d' %(len(self.models)))
        #for user,objdict in self.models.iteritems():
        #    log.debug(user+':'+str(objdict))
            
    def getindex4ts(self,ts):
        return int((ts-self.today)/3600)
    
    
    def checkseconday(self,windowlist,index,user,cmdset):
        new=windowlist[index]['time']
        if new-self.today>86400: #新的一天，清空历史统计数据
            self.userstatsdf[user]=self.createuserdf(user, cmdset)
        
    def getblock(self):
        h=int(time.ctime()[11:13])
        div = 24 / int(self.conf.conf['parameter']['part'])
        return h / div
    
    def calcStat(self,user,tup):
        self.userstatsdf.setdefault(user,{})
        b=self.getblock()
        if len(self.userstatsdf[user])==0 or self.userstatsdf[user]['block']!=b:
            self.userstatsdf[user]={'block':b,'stats':{},'cmdsum':0,'tablesum':0}
        self.userstatsdf[user]['cmdsum']+=1
        if tup['table']!='null':
            self.userstatsdf[user]['tablesum']+=1
        #self.userstatsdf[user]['stats'].setdefault(tup['cmd'],0)
        #self.userstatsdf[user]['stats'][tup['cmd']]+=1
        #self.userstatsdf[user]['sum']+=1
    
    
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
        user,tup=tup.values
        if type(tup)!=dict:
            #log.debug("have a alert from heuristic")
            storm.emit((user,tup)) #启发式异常，进入告警blot
            return
        if not self.models.has_key(user): #判定是否有对应用户画像
            #log.debug("[NOT_MODEL] Have not model with %s" %user)
            return
        self.calcStat(user,tup)
        if not self.window.has_key(user):
            self.window[user]=[tup]
        else:
            self.window[user].append(tup)
        if not self.IsDetection(user): #未触发检测，添加数据队列后直接返回
            return
        windowlist=self.window[user]
        
        self.printwindowlist(user,windowlist)
        rss=self.alg.start(user, windowlist, self.models[user],self.userstatsdf[user])#,self.userstatsdf[user]) #异常检测调用
        self.window[user]=self.window[user][len(windowlist)/self.conf.conf['window']['divisor']:] #待检测事件队列更新,删除队列中的前1/divisor事件
        try:
            map(lambda x:log.debug(u"[Alert:] %s %s;" %(user,x[2])),rss)
        except Exception,e:
            log.warn("[Warn] %s" %repr(e))
        log.debug("================")        
        if rss:
            storm.emit((user,rss)) #发现异常，进入告警blot

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
        filename=os.path.join(sqlog,'detection.log'),
        format="%(message)s",
        filemode='w',
    )

    try:
        DectBaseBolt().run()
    except Exception,e:
        log.error("[Error] %s" %repr(e))
        log.error("[Error INFO] %s" %traceback.format_exc())
    