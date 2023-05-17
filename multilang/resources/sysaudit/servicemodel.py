#coding=utf8
import logging
from collections import namedtuple
import sys
import os
import time
import traceback
import importlib
import json
import copy
import numpy as np


import lib.opert as opert
import algorithm
import lib.lib_alg as libalg 

from lib.alertbase import alert
import lib.knowledge as knowledge
import lib.lib_config as libconfig
from lib.lib_servicemodel import *

import storm
#python3
# sys.path.append('gen-py') #PYTHON3
pathdir = os.path.split(sys.argv[0])[0]
pathdir = os.path.split(pathdir)[0]
pathdir_ = os.path.join(pathdir, 'gen-py')  # PYTHON3
sys.path.append(pathdir_)
log = logging.getLogger('servicemodel')
log.debug(f"检索的路径是：{sys.argv}\n")
from NisaRPC import NisaRPC #引入客户端类
from imp import reload
 
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import threading




def pathsplit(cpath):
    i=cpath.rfind('\\')
    if i<0:i=cpath.rfind('/')
    if i>0:
        return cpath[:i],cpath[i+1:]
    
class ServiceBolt(storm.BasicBolt):
    
    def initialize(self,conf, context):
        #初始化,获取配置信息,读取用户画像,实例化检测对象
        self.window = {} #存储待检测队列
        self.windowindex={} #存储新数据索引
        self.useralert={} #存储用户告警状态和数据
        self.userstatsdf={}
        self.conf=sysconf.conf
        self.readmodels()
        self.kmodule=libconfig.loadmodule(self.conf['system']['knowledge'])
        # self.lmodule=libconfig.loadmodule(self.conf['system']['language'])
        self.lmodule = libconfig.loadmodule('sys_language_cn')  # 本地查找文件
        self.getknowledge()
        self.mergemodels()
        self.modifymodels()
        self.asynmanage()
        self.div = 24 / int(self.conf['parameter']['part']) #时间分块大小
        log.warn("============initialize succfully==================")
        #time.sleep(600)

    def modifymodels(self):
        #对模型中相关数据进行微调优化x
        #对static方差数据进行微调
        for user,model in self.models.items():
            modeldata=model['service']['data'] #core 算法模型数据
            for b,staticdata in modeldata['static'].items():
                if staticdata[1]<=self.conf['parameter']['ministd']:
                    modeldata['static'][b][1]=self.conf['parameter']['ministd']

    
    def getknowledge(self):
        #获取知识模块的最新状态数据
        reload(self.kmodule)
        userknowledge=copy.deepcopy(self.kmodule.detection_userknowledge)
        try:
            libalg.parseKnowledge(userknowledge)
            self.userknowledge=userknowledge
            self.kbase=knowledge.knowledgeBase(self.conf,self.userknowledge,log)
            log.warn("load knowledge succfully!!!")
        except Exception as e:
            log.error("[ERROR] %s" %repr(e))
            log.error("load knowledge Fail!!!")
            
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
    
    def getservercomm(self):
        lastcall=time.time()
        while True:
            time.sleep(self.conf['system']['callintev'])
            args={'method':'get','timep':lastcall,'from':'service'}
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
            log.warn("[WARN] have a updatemodels command")
            self.readmodels()
            self.mergemodels()
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
        self.models= opt.getusermodel(log,self.conf['system']['account'],'sysaudit',whiltlist=['service'])
        
        #获取later 模型数据（用户交互后训练数据）
        opt=opert.opert(self.conf,'latermodels')
        self.latermodels= opt.getusermodel(log,self.conf['system']['account'],'sysaudit',whiltlist=['service'])
        log.warn("===============Load models succfully===============")
        #输出画像到日志
        log.warn('loads sysaudit service models %d' %(len(self.models)))
        log.warn('loads later sysaudit service models %d' %(len(self.latermodels)))
        #for host,objdict in self.models.iteritems():
        #    log.debug(host+':'+str(objdict))
        
    def calcStat(self,user,tup,b,d):
        #计算并存储对应用户当前时区命令统计信息,初始化数据存储结构
        self.userstatsdf.setdefault(user,{})
        if d not in self.userstatsdf[user]: #清除前一天信息，保存新一天信息
            self.userstatsdf[user]={}
            self.userstatsdf[user][d]={}
        if b not in self.userstatsdf[user][d]:
            self.userstatsdf[user][d][b]={'stats':{},'sum':0}
        #跳过以下命令
        if tup['cmd'] in ['fwrite','fread','rwrite','rread','nlisten','noutput']:
            return 0
        #目前检测过程未使用stats数据，注释
        self.userstatsdf[user][d][b]['stats'].setdefault(tup['cmd'],0)
        self.userstatsdf[user][d][b]['stats'][tup['cmd']]+=1
        self.userstatsdf[user][d][b]['sum']+=1
        return 1

    def getblock(self,tp):
        st=time.localtime(tp)
        #with open(r'/tmp/sysnisa/int_service.txt','a') as f: #python3 debug
            #f.write(str(int(st.tm_hour/self.div)))
            #f.write('\n')
        return (str(int(st.tm_hour/self.div)),st.tm_mday) #python3
        #return (str(st.tm_hour/self.div),st.tm_mday) 
        
    def mergemodels(self):
        #循环遍历latermodels，把其中数据数据更新到models
        for user,usermodel in self.latermodels.items():
            if user not in self.models: #若果存在latermodel但不存在常规模型，忽略处理
                continue
            servicemodel=usermodel['service']
            modeldata=servicemodel['data']['servicemodel']
            for block in list(modeldata.keys()):
                #合并新出现的分区
                if block not in self.models[user]['service']['data']['servicemodel']:
                    self.models[user]['service']['data']['servicemodel'][block]=modeldata[block]
                    continue
                blockmodel=self.models[user]['service']['data']['servicemodel'][block]
                laterblockmodel=modeldata[block]
                #合并cmd
                for pp in list(laterblockmodel[0].keys()):
                    if pp not in blockmodel[0]:
                        blockmodel[0][pp]=laterblockmodel[0][pp]
                    else:
                        for p in laterblockmodel[0][pp]:
                            if p not in blockmodel[0][pp]:
                                blockmodel[0][pp][p]=laterblockmodel[0][pp][p]
                
                #合并file,net,reg
                for i in range(1,4):
                    typemodel=laterblockmodel[i] #遍历获取file，net,reg
                    for key in list(typemodel.keys()):
                        for pp in list(typemodel[key].keys()):
                            if pp not in blockmodel[i][key]:
                                blockmodel[i][key][pp]=typemodel[key][pp]
                            else:
                                for p in list(typemodel[key][pp].keys()):
                                    if p not in blockmodel[i][key][pp]:
                                        blockmodel[i][key][pp][p]=typemodel[key][pp][p]
                
        
    def generatealert(self,tup,name,msg):
        log.warn("[Alert:] %s" %msg)
        ac=alert(sysconf.conf)
        ac.setHost(tup['ip'])
        ac.setUser(tup['user'])
        ac.setMessagetp(tup['time'])
        ac.setAlertmsg(msg)
        ac.setCmd(tup['cmd'])
        ac.setSrc(tup['src'])  # 设置src信息
        reason = f"{tup['ip']}在时间{str(ac.getAlertTimestamp())}触发命令{tup['cmd']}操作文件{tup['src']}"
        ac.setReason(reason)  # 设置reason信息
        ac.delPolicyId()  # 删除policyId信息
        ac.setDst(tup['dst'])  # 设置dst信息
        log.debug(f"emit--->{(tup['user'],[(name,ac.getAlert())])}\n")
        storm.emit((tup['user'],[(name,ac.getAlert())]))
            
    def process(self,tup):
        user,tup=tup.values
        log.debug(f"sericemodel data====>>>>{user, tup}")
        if type(tup)!=dict:
            log.info("have a alert from heuristic")
            storm.emit((user,tup)) #启发式异常，进入告警blot
            return

        #相关命令统计异常检测
        tb,td=self.getblock(tup['time'])
        #统计数据，返回是否标识，是否把数据发送到下一bolt
        emitflag=self.calcStat(user,tup,tb,td)
        #取用户静态统计数据
        if self.conf['system']['statsexp'] and user in self.models and tb in self.models[user]['service']['data']['static']:
            userstaticdata=self.models[user]['service']['data']['static'][tb]
            #log.info(userstaticdata)
        else:
            userstaticdata=None
        #log.info(self.userstatsdf)
        if userstaticdata and self.userstatsdf[user][td][tb]['sum']-userstaticdata[0] > 3*userstaticdata[1]:
            if "alertflag" in self.userstatsdf[user][td][tb]:
                #当前分区已告警，不再重复告警
                pass
            else:
                msg=self.lmodule.service_statexp %(user,self.userstatsdf[user][td][tb]['sum'],\
                                                                           userstaticdata[0],userstaticdata[1])
                self.generatealert(tup,service_stats, msg)
                #设置告警标识
                self.userstatsdf[user][td][tb]["alertflag"]=1

        #因数据获取端对ppname的抓取技术问题，偶偶失败，对ppname==‘NULL’的情况一律忽略不检测
        abnormalflag=False
        if tup['ppname']!='NULL' and user in self.models: #若不存在ppname或对应主机模型，不检测
            log.debug(str(tup))
            info=Detection(tup,self.models[user],self.conf,self.lmodule) #info[0]告警类型 info[1] 告警对象

            if info:
                abnormalflag=True
                log.debug(info)
            if info and self.kbase.servicemodeldecide(tup): #异常 且 经知识判定为真异常，告警
                log.debug(f"-->in {info}")
                if info[0]=="noexist" and self.conf['system']['notblockalert']==0: #仅对配置为空告警的配置进行告警
                    #如果是因不存在分区模型数据导致告警，且配置有noblockalert=1时，忽略告警
                    return
                self.useralert.setdefault(tup['user'],{})
                if info[0] not in self.useralert[tup['user']]:
                    self.useralert[tup['user']][info[0]]={'tp':0,'accumsg':[],'accuevent':[]} #上一次告警时间，累积告警数据
                flagdata=self.useralert[tup['user']][info[0]]
                #添加告警数据
                if info[1]['msg'] not in flagdata['accumsg']:
                    flagdata['accumsg'].append(info[1].pop('msg'))
                    flagdata['accuevent'].append(info[1])
                #对未到冷却时间的告警存储后立即返回
                log.debug(f"--{tup['time']-flagdata['tp']}")
                if tup['time']-flagdata['tp']<600:
                    return #直接返回
                msg='\n'.join(flagdata['accumsg'])
                log.warn("[Alert:] %s" %msg)
                ac=alert(sysconf.conf)
                ac.setHost(tup['ip'])
                ac.setUser(tup['user'])
                ac.setMessagetp(tup['time'])
                ac.setAlertmsg(msg)
                ac.setCmd(tup['cmd'])
                ac.setSrc(tup['src'])  # 设置src信息
                reason = f"{tup['ip']}在时间{str(ac.getAlertTimestamp())}触发{info[1]['msg']},导致告警，建议检查用户是否违规操作"
                ac.setReason(reason)  # 设置reason信息
                ac.delPolicyId()  # 删除policyId信息
                ac.setDst(tup['dst'])  # 设置dst信息
                ac.setAlertevent(flagdata['accuevent']) #存储告警元数据
                flagdata['tp']=tup['time']
                flagdata['accumsg']=[] #重置为空
                flagdata['accuevent']=[] #重置为空
                #对不同行为异常设置不同算法名称使其告警显示
                algname="service_%s" %(info[1]['cmd'])
                log.debug(f'into {(tup["user"], (algname, ac.getAlert()))}')
                storm.emit((tup['user'],[(algname,ac.getAlert())])) #发现异常，进入告警blot
                return #如果对此数据进行告警，不进行后续行为检测
        elif user in self.models and tup['ppname']=='NULL':
            log.debug(f'ppname null {user}')
            if tup['cmd'] in self.models[user]['service']['data']['cmdsets']:
                log.debug('pass')
                pass
            else:
                abnormalflag=True

                if self.kbase.servicemodeldecide(tup):
                    self.generatealert(tup,"service_%s" %tup['cmd'],self.lmodule.service_cmdnotexist %tup['cmd']) #python3

        #只要产生异常 不进行后续的行为异常检测
        if emitflag and (not abnormalflag):
            log.debug('into next bolt')
            storm.emit((user,tup)) #后续数据转发，只转发不触发告警的数据

class contain:
        conf=None
if __name__=="__main__":
    sysconf=contain()
    #a='{"hdfs": {"host": "172.17.0.2", "port": 50070}, "heuristic": {"sortwait": 10}, "system": {"hdfspath": "/tmp/tmpnisax", "notblockalert": 0, "account": "8lab", "callintev": 30, "log": "/tmp/sysnisa", "language": "/home/lab8/Git/PyNISA/conf/sys_language_cn", "level": "warn", "filtersort": 5, "sence": "sysaudit", "deltmp": 0, "rebuilpp": 1, "rebuildclear": 60, "dupfilter": 1, "calladdr": "127.0.0.1:9898", "statsexp": 0, "store": "mysql", "knowledge": "/home/lab8/Git/PyNISA/conf/sys_knowledge"}, "alert": {"amendment": 0, "uploadtype": "redis", "rkey": "nisalert", "rhost": "172.20.0.1", "dup": 600, "rport": 6379}, "filter": {"ip": "192.168.1.182", "cmd": "fread"}, "window": {"maxlen": 50, "issec": 1, "sec": 300, "divisor": 2}, "deleteclass": {"core_alg": "alg.core_alg"}, "mysql": {"host": "192.168.1.210", "password": "8lab", "db": "nisa", "port": 3306, "user": "8lab"}, "export": {"rkey": "nisalog", "rhost": "172.17.0.4", "fname": "nisalog", "fdir": "/tmp/sysexp", "type": "None", "rport": 6379}, "server": {"passwd": "secret", "host": "nisa", "upload": 1, "port": 9099, "name": "admin"}, "parameter": {"execdiff": 0.5, "simalg": "similarity_jaccard2", "clster_weight": 0.7, "core_comm": 0, "time_kdm_parameter": 3, "kdm_parameter": 4, "pathrank": 4, "threshold_exec": 0.6, "part": 8, "ministd": 50, "frequency_weight": 0.2, "malcov_transform": 0.45, "minidiff": 0.1, "core_exec": 1, "threshold_normal": 0.8, "ngram_weight": 0.1}}'
    #sysconf.conf=json.loads(a)
    sysconf.conf=json.loads(sys.argv[1])
    if 'log' in sysconf.conf['system']:
        syslog=sysconf.conf['system']['log']
    else:
        syslog='/tmp/sqlnisa'  
    
    Bolt=ServiceBolt()
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
        filename=os.path.join(syslog,'servicemodel.log'+taskid),
        format="%(message)s",
        filemode='w',
    )
    #tup={"time":"2017-12-09 18:50:19,737","flag":"true","user":"sys.0.192.168.1.177","ip":"192.168.1.177","cmd":"http","src":"NULL","dst":"/usr/lib/apt/methods/http","ppname":"dash_/usr/bin/apt-key","pid":29036,"ppid":29028}
    #obj=ServiceBolt()
    #obj.initialize(None, None)
    #r=obj.kbase.servicemodeldecide(tup)
    #pass
    try:
        Bolt.run()
    except Exception as e:
        log.error("[Error] %s" %repr(e))
        log.error("[Error INFO] %s" %traceback.format_exc())

    