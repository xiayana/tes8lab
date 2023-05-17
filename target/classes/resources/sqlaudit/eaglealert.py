#coding=utf8
import logging
import os
import sys
import time
import traceback
reload(sys)
sys.setdefaultencoding('utf-8')
import storm

import lib.client as client
#import lib.conf as nisacf
import json

log = logging.getLogger('eaglealert')


class eaglealert(storm.BasicBolt):
    
    def initialize(self,conf, context):
        self.conf=sqlconf.conf
        self.server=self.conf['server']
        self.client=client.eagleclient(self.server['host'],self.server['port'],self.server['name'],self.server['passwd'])
        self.dupcontron={}
        
    def process(self, tup):
        #告警数据格式定义
        #tup=(user,alerts)
        #alerts=[(alg_name,alert_content),...]
        user,alerts=tup.values
        log.info('==========')
        for onealert in alerts:
            log.info("%s:%s[%s]:%s" %(user,onealert[0],\
                                       onealert[1][0]['alertContext']['properties']['alertTimestamp'],\
                                       onealert[1][0]['alertContext']['properties']['alertMessage']))
            if self.duplicatecheck(user,onealert[0]):
                self.alert(user,onealert[0],onealert[1])
                
    def alert(self,user,alg,info):
        s=str(info).replace("'",'"')
        log.info("Alert: %s %s" %(user,alg))
        if self.server['upload']:
            self.client.alert(s,log)

    def duplicatecheck(self,user,name):
        '''
        冷却告警检测函数,防止对同一用户在同一算法下的高频告警
        '''
        if self.dupcontron.has_key(user):
            if self.dupcontron[user].has_key(name):
                now=time.time()
                if now-self.dupcontron[user][name]>self.conf['alert']['dup']: #定义的冷却时间间隔
                    self.dupcontron[user][name]=now
                    return True
                else:
                    log.info("Have a cool down alert with %s:%s" %(user,name))
                    return False
            else:
                self.dupcontron[user][name]=time.time()
                return True
        else:
            self.dupcontron[user]={name:time.time()}
            return True

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
        filename=os.path.join(sqlog,'eaglealert.log'),
        format="%(message)s",
        filemode='w',
    )
    
    try:
        eaglealert().run()
    except Exception as e:
        log.error("[Error] %s" %repr(e))
        log.error("[Error INFO] %s" %traceback.format_exc())
    
