#coding=utf8
import logging
import os
import sys
import time
import traceback
import json


import storm
import lib.client as client
import lib.lib_config as libconfig
from lib.dexport import *
import json

# sys.path.append('gen-py') #PYTHON3
pathdir = os.path.split(sys.argv[0])[0]
pathdir = os.path.split(pathdir)[0]
pathdir_ = os.path.join(pathdir, 'gen-py')  # PYTHON3
sys.path.append(pathdir_)
from NisaRPC import NisaRPC #引入客户端类
 
from thrift import Thrift 
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from collections import Iterable

log = logging.getLogger('eaglealert')


class eaglealert(storm.BasicBolt):
    
    def initialize(self,conf, context):
        self.conf=sysconf.conf
        self.server=self.conf['server']
        self.qingcloudalert = self.conf['qingcloudalert']
        self.getupload()
        self.client=client.eagleclient(self.server['host'],self.server['port'],self.server['name'],self.server['passwd'],self.qingcloudalert)
        # self.lmodule=libconfig.loadmodule(self.conf['system']['language'])
        self.lmodule = libconfig.loadmodule('sys_language_cn')  # 本地查找文件
        self.dupcontron={}
        self.connectserver()

    def asynmanage(self):
        self.connectserver()
        clienthread=threading.Thread(target=self.getservercomm)
        clienthread.setDaemon(True) #设置守护进程标识，当主线程结束后，子线程同时强制结束
        clienthread.start()

    def connectserver(self):
        try:
            ip,port=self.conf['system']['calladdr'].split(':',1)
            log.warn("Connect %s:%s" %(ip,port))
            transport = TSocket.TSocket(ip, int(port))
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            self.rpcclient = NisaRPC.Client(protocol)
            transport.open()
        except Exception as e:
            log.error('[ERROR] fail with : %s' %repr(e))
    
    def getuserinfo(self,user,key):
        req={"type":"get","user":user,"key":key}
        rs=self.rpcclient.userInfo(json.dumps(req))
        return rs
    
    def additionloginmsg(self,alertobj):
        #添加触发告警用户的登录信息
        host=alertobj[1][0]['alertContext']['properties']['host']
        try:
            rs=self.getuserinfo(host,["login"])
        except Exception as e:
            log.error("[ERROR] get the userinfo fail from rpc,reconnect the rpc server!")
            self.connectserver()
            return
        
        log.info("UserInfo: %s" %rs)
        rs=json.loads(rs)
        
        if rs['flag']==0:
            dt=rs['data']
            msg=self.lmodule.alert_login_remote %(dt['login']['user'],dt['login']['addr'],time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(dt['login']['time'])))
        else:
            msg=self.lmodule.alert_login_local %host
        
        log.info("Addr: %s" %msg)
        alertobj[1][0]['alertContext']['properties']['alertMessage'] += ("\n" + msg)
        
    def process(self, tup):
        # storm.ack(tup)
        #告警数据格式定义
        #tup=(user,alerts)
        #alerts=[(alg_name,alert_content),...]
        user,alerts=tup.values
        log.info('=======')
        log.debug(f'alertdata={tup.values}\n')

        if isinstance(alerts, Iterable):
            try:
                for onealert in alerts:
                    log.warn("Alert: %s:%s[%s]:%s" %(user,onealert[0],\
                                           onealert[1][0]['alertContext']['properties']['alertTimestamp'],\
                                           onealert[1][0]['alertContext']['properties']['alertMessage']))

                    if self.duplicatecheck(user,onealert[0]):
                        log.info(f"alert msg:{onealert}")
                        # self.additionloginmsg(onealert)
                        self.upload2dst(user,onealert)
                        self.alert(user,onealert[0],onealert[1])
            except Exception as e:
                log.error("[ERROR] user:%s ,alerts:%s" %(user,str(alerts)))
                log.error(traceback.format_exc())
        else:
            log.info(alerts)
                
    def alert(self,user,alg,info):
        s=json.dumps(info)
        log.info("Upload: %s" %user)
        if self.server['upload']:
            self.client.alert(s,log)

    def duplicatecheck(self,user,name):
        '''
        冷却告警检测函数,防止对同一用户在同一算法下的高频告警
        '''
        if user in self.dupcontron:
            if name in self.dupcontron[user]:
                now=time.time()
                if now-self.dupcontron[user][name]>self.conf['alert']['dup']: #定义的冷却时间间隔
                    self.dupcontron[user][name]=now
                    return True
                else:
                    log.info("Have a cool down alert with %s" %user)
                    return False
            else:
                self.dupcontron[user][name]=time.time()
                return True
        else:
            self.dupcontron[user]={name:time.time()}
            return True
    
    def upload2dst(self,user,alertobj):
        log.info("ToRedis: have a upload2dst with %s:%s" %(user,alertobj[0]))
        #包含告警时间，事件时间，告警用户，算法，告警消息
        tup={'type':'nisalert','user':user,'alg':alertobj[0],
             'alertimestamp':alertobj[1][0]['alertContext']['properties']['alertTimestamp'],
             'alertobj':alertobj[1][0]['alertContext']['properties']['alertMessage'],
             'msgtimestamp':int(alertobj[1][0]['alertContext']['properties']['timestamp'])/1000.0}
        list(map(lambda x:x.write(tup),self.uploadobj))
        
    def getupload(self):
        self.uploadobj=[]
        if 'uploadtype' not in self.conf['alert']:
            return
        for i in self.conf['alert']['uploadtype'].split(','):
            i=i.strip()
            if not i:continue
            key="export_%s" %i
            try:
                if key in globals():
                    log.debug(f"{key} in")
                    epclass=globals()[key]
                    self.uploadobj.append(epclass(self.conf['alert'], log))
            except Exception as e:
                log.error("[ERROR] Fail create upload obj with %s" %key)
                pass 
class contain:
    conf=None


if __name__ == '__main__':
    sysconf=contain()
    sysconf.conf=json.loads(sys.argv[1])
    if 'log' in sysconf.conf['system']:
        syslog=sysconf.conf['system']['log']
    else:
        syslog='/tmp/sqlnisa'

    Bolt=eaglealert()
    taskid=Bolt.getaskid()

    log.info("[INFO] config info: %s" %str(sysconf.conf))
    if 'level' not in sysconf.conf['system']:
        pylog=logging.INFO
    elif sysconf.conf['system']['level']=='debug':
        pylog=logging.DEBUG
    elif sysconf.conf['system']['level']=='info':
        pylog=logging.INFO
    elif sysconf.conf['system']['level']=='warn':
        pylog=logging.WARN
    elif sysconf.conf['system']['level']=='error':
        pylog=logging.ERROR
    else:
        pylog=logging.INFO

    logging.basicConfig(
        level=logging.DEBUG,
        filename=os.path.join(syslog,'eaglealert.log'+taskid),
        format="%(message)s",
        filemode='w',
    )
    try:
        Bolt.run()
    except Exception as e:
        log.error("[Error] %s" %repr(e))
        log.error("[Error INFO] %s" %traceback.format_exc())


