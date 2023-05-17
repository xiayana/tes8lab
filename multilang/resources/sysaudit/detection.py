#coding=utf8
import logging
from collections import namedtuple
import sys
import os
import time
import re
import traceback
import importlib
import json
import numpy as np
import copy


import algorithm
from lib.alertbase import alert
import lib.opert as opert
import lib.lib_alg as libalg 
import lib.lib_config as libconfig
import storm

# sys.path.append('gen-py')
pathdir = os.path.split(sys.argv[0])[0]
pathdir = os.path.split(pathdir)[0]
pathdir_ = os.path.join(pathdir, 'gen-py')  # PYTHON3
sys.path.append(pathdir_)
from NisaRPC import NisaRPC #引入客户端类,python3
from thrift import Thrift 
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import threading

log = logging.getLogger('detection')


class DectBaseBolt(storm.BasicBolt):
    
    
    def initialize(self,conf, context):
        #定义脚本执行程序标识
        self.shellProcess=["sh","bash","dash","busybox","python","ruby","perl"]
        res=["sh","bash","dash","busybox","python\S{0,4}","ruby","perl"]
        self.sr=[re.compile(x,re.I) for x in res]
        #=========
        #初始化,获取配置信息,读取用户画像,实例化检测对象
        self.window = {} #存储待检测队列
        self.conf=sysconf.conf
        #self.today=self.Getoday()
        #algorithm.algconf=self.conf()
        self.readmodels()
        self.kmodule=libconfig.loadmodule(self.conf['system']['knowledge'])
        # self.lmodule=libconfig.loadmodule(self.conf['system']['language'])
        self.lmodule = libconfig.loadmodule('sys_language_cn')  # 本地查找文件
        self.getknowledge()
        self.userstatsdf={}
        self.syscall={}
        self.userflag={}
        self.dispatch=algorithm.dispatch(self.conf,self.models,self.lmodule,log)
        self.div = 24 / int(self.conf['parameter']['part']) #时间分块大小
        self.asynmanage()
        log.warn("============initialize succfully==================")
        
    def getAlert(self,host,user,alertcontent,alertevent):
        #获取一个可返回的告警结构 
        ac=alert(self.conf)
        ac.setHost(host)
        ac.setUser(user)
        ac.setAlertmsg(alertcontent)
        ac.setAlertevent(alertevent)
        return ac.getAlert()
    
    def getknowledge(self):
        #获取知识模块的最新状态数据
        self.kmodule=libconfig.loadmodule(self.conf['system']['knowledge'])#debug
        userknowledge=copy.deepcopy(self.kmodule.sensitive_knowledge)
        try:
            libalg.parseKnowledge(userknowledge)
            self.userknowledge=userknowledge
            self.malobj=libalg.malware(self.userknowledge,log)
            log.warn("load knowledge succfully!!!")
        except Exception:
            log.error("load knowledge Fail!!!")
    
    def asynmanage(self):
        self.connectserver()
        clienthread=threading.Thread(target=self.getservercomm)
        clienthread.setDaemon(True)
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
    
    def getservercomm(self):
        lastcall=time.time()
        while True:
            time.sleep(self.conf['system']['callintev'])
            args={'method':'get','timep':lastcall,'from':'dect'}
            try:
                rs=self.rpcclient.controlCentre(json.dumps(args))
            except Exception:
                log.warn("send order fail,reconnect rpc server!!!")
                self.connectserver()
                continue
            rs=json.loads(rs)
            if rs['flag']==0:
                lastcall=rs['timep']
                self.clientact(rs)

    def clientact(self,rs):
        #{"flag":0,"msg":"ok","command":"",'data':{},'timep':xxx}
        log.warn("=======GetOrder in: %s=============" %time.asctime())
        if rs['command']=='updatemodels':
            log.warn("[WARN] have a updatemodels command")
            self.readmodels()
            self.getknowledge()
            log.warn("============updatemodels succfully==================")
        elif rs['command']=='resetconfig':
            log.warn('[WARN] have a resetconfig command')
            log.warn(str(rs['data']))
            self.conf=rs['data']
            log.warn("============updateconfig succfully==================")
               
    def readmodels(self): 
        #加载所有用户画像数据
        opt=opert.opert(self.conf)
        try:
            blacklist = list(self.conf['deleteclass'].keys())
        except:
            blacklist = []
        log.warn(f"blacklist is :{blacklist}")
        self.models=opt.getusermodel(log,self.conf['system']['account'],'sysaudit',whiltlist=list(self.conf['deleteclass'].keys()), blacklist=blacklist)
        self.getgsyscall()
        log.warn("================Load models succfully=======================")
        #输出画像到日志
        log.warn('loads sysaudit %s models %d' %(str(list(self.conf['deleteclass'].keys())),len(self.models)))
        #for user,objdict in self.models.iteritems():
        #    log.debug(user+':'+str(objdict))
        
    def getgsyscall(self):
        #获取全局syscall数据结构
        gsyscall={}
        #gsyscall={user:{b1:[cmd1,cmd2],b2:[cmd1,cmd2],...},user2:{...}}
        for user,model in self.models.items():
            gsyscall.setdefault(user,{})
            for name in ['core','dl']:
                if name not in model:
                    continue
                for cellmodel in model[name]:
                    modeldata=cellmodel['data'] 
                    for b,syscalldata in modeldata['syscall'].items():
                        gsyscall[user].setdefault(b,[])
                        for k in list(syscalldata.keys()):
                            if not k in  gsyscall[user][b]:
                                gsyscall[user][b].append(k)
        self.gsyscall=gsyscall
        
    def getblock(self,tp):
        st=time.localtime(tp)                       
        return (str(int(st.tm_hour/self.div)),st.tm_mday) #python3
        #return (str(st.tm_hour/self.div),st.tm_mday)
    
    def issyscall(self,user,tup,b):
        if tup['cmd'] in self.gsyscall[user][b]:
            return True
        return False
        
    def IsDetection(self,user):
        lenght=len(self.window[user])
        if lenght>=self.conf['window']['maxlen']: #或者在时间窗口内事件数超过maxlen个，直接开始异常检测
            log.debug("send window with event window")
            self.userflag[user]['wintype']=1 #maxlen 类型触发
            return True
        #去掉时间窗口
        elif lenght>20 and self.conf['window']['issec'] and (self.window[user][-1]['time']-self.window[user][-2]['time']>=self.conf['window']['sec']): #当开启时间窗口 且，消息队列符合时间要求时(相邻有效用户操作间隔一定时间）
            log.debug("send window with time window")
            self.userflag[user]['wintype']=2 #sec win 类型触发
            return True
        return False
    
    #调试状态下，打印检测窗口
    def printwindowlist(self,user,winlist):
        if not log.isEnabledFor("DEBUG"):
            return
        log.info("%s %d sum" %(user,len(winlist)))

    def process(self,tup):
        start_time = time.time()
        try:
            user,tup=tup.values
            log.debug(f'输入,type:{type(tup)}, {tup}')
            if type(tup)!=dict:
                #log.debug("have a alert from heuristic")
                log.debug(f"type(tup)!=dict into...")
                storm.emit((user,tup)) #启发式异常，进入告警blot
                return
            if user not in self.models: #判定是否用对应用户画像
                #log.debug("[NOT_MODEL] Have not model with %s" %user)
                log.debug("[NotEXIST]have noexist user or block model: %s" % (str(tup)))
                return

            self.malobj.setflag(tup)
            tb,td=self.getblock(tup['time'])
        except Exception as err:
            log.debug(f"出现错误1，错误原因是：{err}\n")
            log.debug("ERROR ERROR" * 10)
        try:
            #对syscall命令进行统一忽略
            if self.issyscall(user,tup,tb):return
        except KeyError:
            #无分区模型数据的数据，直接返回
            log.info("[NotEXIST]have noexist user or block model: %s" %(str(tup)))
            #理论上不会接收到不存在数据模型的数据，都会在上一个bolt触发异常后被过滤，但因存在ppname原始数据的失败问题，导致此种数据会忽略上一个bolt检测
            return
        except Exception as e:
            log.error("[ERROR] calc-once error: %s" %repr(e))
            return

        #设定告警标识
        alertf=False
        try:
            active=self.dispatch.pushtup(user,tup,tb)
        except Exception as err:
            log.debug(f"出现错误2，错误原因是：{err}\n")
            log.debug("ERROR ERROR" * 10)
        log.debug(f"激活操作是：{active}")
        if not active:
            log.debug(f"不激活直接返回，{active},,\n")
            return
        newest=max([self.dispatch.userflag[user][x]['newest'] for x in active]) #取当前检测事件中的最新时间
        try:
            rss=self.dispatch.start(user,active,None)
        except Exception as err:
            log.debug(f"出现错误3，错误原因是：{err}\n")
            log.debug("ERROR ERROR" * 10)

        try:
            new_time = time.strftime("%Y_%m_%d %H:%M:%S", time.gmtime(newest))
        except:
            new_time = rss
        log.debug(f"告警信息是：{rss},newest:{new_time}, user:{user}\n")
        if rss and self.malobj.getflag(user,newest):
            list(map(lambda x:log.warn("[Alert:] %s \n[Events:] %s" %(x[1],x[2])),rss))
            alertf=True
        else:
            list(map(lambda x:log.warn("[EXCEPT:] %s \n[Events:] %s" %(x[1],x[2])),rss))

        log.info("======")
        log.debug(f"======{alertf},耗时：{time.time() - start_time}")
        # alertf=True debug use
        if alertf:
            rss=[("detection_"+i[0],self.getAlert(tup['ip'],tup['user'],i[1],i[2])) for i in rss] #告警信息统一转化成完整的告警结构
            log.debug(f"alertf into")
            log.debug(f"rss:{rss}")
            storm.emit((user,rss)) #发现异常，进入告警blot



class contain:
    conf=None


if __name__=="__main__":
    sysconf=contain()
    #a='{"hdfs": {"host": "172.17.0.2", "port": 50070}, "heuristic": {"sortwait": 10}, "system": {"hdfspath": "/tmp/tmpnisax", "notblockalert": 0, "account": "8lab", "callintev": 30, "log": "/tmp/sysnisa", "language": "/home/lab8/Git/PyNISA/conf/sys_language_cn", "level": "info", "filtersort": 5, "sence": "sysaudit", "deltmp": 0, "rebuilpp": 1, "rebuildclear": 60, "dupfilter": 1, "calladdr": "127.0.0.1:9898", "statsexp": 0, "store": "mysql", "knowledge": "/home/lab8/Git/PyNISA/conf/sys_knowledge"}, "alert": {"amendment": 0, "uploadtype": "redis", "rkey": "nisalert", "rhost": "172.20.0.1", "dup": 600, "rport": 6379}, "filter": {"ip": "192.168.1.182", "cmd": "fread"}, "window": {"maxlen": 50, "issec": 1, "sec": 300, "divisor": 2}, "deleteclass": {"core": "alg.core_alg", "dl": "alg.dl_alg"}, "mysql": {"host": "192.168.1.210", "password": "8lab", "db": "nisabk", "port": 3306, "user": "8lab"}, "export": {"rkey": "nisalog", "rhost": "172.17.0.4", "fname": "nisalog", "fdir": "/tmp/sysexp", "type": "None", "rport": 6379}, "server": {"passwd": "secret", "host": "nisa", "upload": 1, "port": 9099, "name": "admin"}, "parameter": {"execdiff": 0.5, "simalg": "similarity_jaccard2", "dlsimalg": "simbehavior", "core_comm": 0, "time_kdm_parameter": 3, "kdm_parameter": 4, "pathrank": 4, "threshold_exec": 0.6, "part": 8, "ministd": 50, "frequency_weight": 0.2, "malcov_transform": 0.45, "minidiff": 0.1, "core_exec": 1, "threshold_normal": 0.8, "ngram_weight": 0.1, "clster_weight": 0.7}}'
    #sysconf.conf=json.loads(a)
    sysconf.conf=json.loads(sys.argv[1])
    if 'log' in sysconf.conf['system']:
        syslog=sysconf.conf['system']['log']
    else:
        syslog='/tmp/sqlnisa'

    Bolt=DectBaseBolt()
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
        filename=os.path.join(syslog,'detection.log'+taskid),
        format="%(message)s",
        filemode='w',
    )
    #Bolt.initialize(None,None)
    try:
        Bolt.run()
    except Exception as e:
        log.error("[Error] %s" %repr(e))
        log.error("[Error INFO] %s" %traceback.format_exc())
