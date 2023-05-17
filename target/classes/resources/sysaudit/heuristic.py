#coding=utf8
from imp import reload
import logging
import sys
import time
import re
import os
import copy
import traceback
from collections import namedtuple
from lib.lib_alg import sortlist,dictcmp
import json


import storm
from lib.alertbase import alert
from lib.heuristicEngine import heuristicEngine
import lib.lib_config as libconfig

#python3
# sys.path.append('gen-py')
pathdir = os.path.split(sys.argv[0])[0]
pathdir = os.path.split(pathdir)[0]
pathdir_ = os.path.join(pathdir, 'gen-py')  # PYTHON3
sys.path.append(pathdir_)
from NisaRPC import NisaRPC #引入客户端类,python3
from imp import reload
#with open(r'/home/longjiemin/log.txt','w') as f:
    #f.write(__file__)
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import threading


log = logging.getLogger('heuristic')

#emit 到后续流程需要忽略的数据
ignorelist=['user_auth','user_acct','user_end']
#grouping by host
class HeuristicBolt(storm.BasicBolt):
    #重复过滤和启发式引擎
    #[time,user,ip,cmd,src,dst,flag]
    def initialize(self,conf, context):
        self.gconf=sysconf.conf
        self.conf=sysconf.conf['heuristic']

        self.dsortlist={} #强排序队列
        self.kmodule=libconfig.loadmodule(self.gconf['system']['knowledge'])
        # self.lmodule=libconfig.loadmodule(self.gconf['system']['language'])
        self.lmodule=libconfig.loadmodule('sys_language_cn') #本地查找文件
        self.getknowledge()
        self.engine=heuristicEngine(self.userknowledge,log,self.gconf,self.lmodule)
        self.asynmanage()

    def asynmanage(self):
        self.connectserver()
        clienthread=threading.Thread(target=self.getservercomm)
        clienthread.setDaemon(True) #设置守护进程标识，当主线程结束后，子线程同时强制结束
        clienthread.start()

    def getknowledge(self):
        #获取知识模块的最新状态数据
        reload(self.kmodule)

        userknowledge=copy.deepcopy(self.kmodule.heuristic_knowledge)
        try:
            libconfig.parseHeuristicKnowledge(userknowledge)
            self.userknowledge=userknowledge
            log.warn("load knowledge succfully!!!")
        except Exception as e:
            log.error("[ERROR] %s" %repr(e))
            log.error("load knowledge Fail!!!")

    def connectserver(self):
        try:
            ip,port=self.gconf['system']['calladdr'].split(':',1)
            log.warn("Connect %s:%s" %(ip,port))
            transport = TSocket.TSocket(ip, int(port))
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            self.rpcclient = NisaRPC.Client(protocol)
            transport.open()
        except Exception as e:
            log.error('[ERROR] fail with : %s' %repr(e))

    def getservercomm(self):
        lastcall=time.time()
        while True:
            time.sleep(self.gconf['system']['callintev'])
            args={'method':'get','timep':lastcall,'from':'heuri'}
            try:
                rs=self.rpcclient.controlCentre(json.dumps(args))
            except Exception:
                self.connectserver()
                log.info("send order fail,reconnect rpc server!!!")
                continue
            rs=json.loads(rs)
            if rs['flag']==0:
                lastcall=rs['timep']
                self.clientact(rs)
            

    def clientact(self,rs):
        #{"flag":0,"msg":"ok","command":"",'data':{},'timep':xxx}
        log.warn("=======GetOrder in: %s=============" %time.asctime())
        if rs['command']=='updatemodels':
            #log.info("[INFO] have a updatemodels command")
            self.getknowledge()
            self.engine=heuristicEngine(self.userknowledge,log,self.gconf,self.lmodule)
        elif rs['command']=='resetconfig':
            log.info('[INFO] have a resetconfig command')
            log.info(str(rs['data']))
            self.gconf=rs['data']
            self.conf=rs['data']['heuristic']

    def setuserinfo(self,flags,tup):
        #根据设定的标识，在远程服务器上设置对应用户信息，
        if "login_succ" in flags:
            req={"type":"set","user":tup['ip'],"setdata":{"login":{"user":tup['dst'],"addr":tup['src'],"time":tup['time']}}}
            self.rpcclient.userInfo(json.dumps(req))

    def process(self, tup):
        # storm.ack(tup)
        try:
            host,tup=tup.values
            log.debug(f'heuristic--->{tup}')
            #缓存数据，进行强行排序
            self.dsortlist.setdefault(host,sortlist(fcmp=dictcmp))
            self.dsortlist[host].append(tup) #添加到队列并自动排序
            log.debug(f"time is {self.dsortlist[host].get(-1)['time'] - self.dsortlist[host].get(0)['time']}")

            #对排序后数据进行检测
            #self.dsortlist.setdefault(host,deque())
            #当强制排序队中队尾到队首时间差>=sortwait
        except Exception as err:
            log.debug(f"ERROR,ERROR1, 错误是：{err}")
        while self.dsortlist[host].get(-1)['time']-self.dsortlist[host].get(0)['time']>=self.conf['sortwait']: #把排序队列中所有符合条件的弹出检测发送
            tup=self.dsortlist[host].pop(0)
            user=tup['user']
            #=============================
            log.debug(str(tup))
            try:
                rs,flags=self.engine.detection(tup)#(alg,ac.getAlert()) #返回一个告警
            except Exception as err:
                log.debug(f"ERROR,ERROR2, 错误是：{err}")
            if rs:
                #有告警，发送到后续Bolt处理
                #log.debug("[Alert: ]"+str(rs))
                log.debug(f"有告警，发送到后续Bolt处理")
                storm.emit((host,[rs])) #启发式检测告警 flag=true|false
            if flags:
                #有flag设置，进行相关处理
                log.debug(f"有flag设置，进行相关处理")
                self.setuserinfo(flags,tup)
            if tup['cmd'] not in ignorelist: #对用户登录操作数据忽略后续检测
                #log.debug(tup)
                log.debug(f"常规数据发送到后续检测流")
                storm.emit((user,tup)) #常规数据发送到后续检测流


class contain:
    conf=None
if __name__ == '__main__':
    sysconf=contain()
    #a='{"hdfs": {"host": "172.17.0.2", "port": 50070}, "heuristic": {"sshbrute": 3, "sshwindow": 60, "quickbackdoor": 5, "sortwait": 30}, "system": {"hdfspath": "/tmp/tmpnisax", "notblockalert": 0, "account": "8lab", "callintev": 30, "log": "/tmp/sysnisa", "level": "info", "sence": "sysaudit", "deltmp": 0, "dupfilter": 1, "calladdr": "127.0.0.1:9898", "store": "mysql", "knowledge": "/home/lab8/Git/PyNISA/conf/sys_knowledge"}, "alert": {"dup": 600, "amendment": 0}, "filter": {"ip": "192.168.1.182", "cmd": "fread", "src": "/tmp/"}, "window": {"maxlen": 50, "issec": 1, "sec": 300, "divisor": 2}, "deleteclass": {"core_alg": "alg.core_alg", "example": "alg.example"}, "mysql": {"host": "192.168.1.210", "password": "8lab", "db": "nisabk", "port": 3306, "user": "8lab"}, "export": {"fistr": 1, "rkey": "nisalog", "ristr": 0, "rhost": "192.168.1.241", "fname": "nisalog", "fdir": "/tmp/sysexp", "type": "None", "rport": 9000}, "server": {"passwd": "secret", "host": "172.17.0.2", "upload": 1, "port": 9099, "name": "admin"}, "parameter": {"simalg": "similarity_jaccard2", "clster_weight": 0.7, "core_comm": 0, "time_kdm_parameter": 3, "kdm_parameter": 4, "pathrank": 4, "threshold_exec": 0.6, "part": 12, "ministd": 50, "frequency_weight": 0.2, "malcov_transform": 0.45, "minidiff": 0.1, "core_exec": 1, "threshold_normal": 0.8, "ngram_weight": 0.1}}'
    #sysconf.conf=json.loads(a)
    sysconf.conf=json.loads(sys.argv[1])
    if 'log' in sysconf.conf['system']:
        syslog=sysconf.conf['system']['log']
    else:
        syslog='/tmp/sqlnisa'
    Bolt=HeuristicBolt()
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
        filename=os.path.join(syslog,'heuristic.log'+taskid),
        format="%(message)s",
        filemode='w',
    )
    try:
        Bolt.run()
    except Exception as e:
        log.error("[Error] %s" %repr(e))
        log.error("[Error INFO] %s" %traceback.format_exc())
