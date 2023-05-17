#coding=utf8
import logging
import sys
import time
import re
import os
import traceback
import importlib
import copy
from collections import namedtuple
from collections import deque
from imp import reload


import storm

import lib.lib_alg as libalg 
from lib.alertbase import alert
from lib.dexport import *

#import lib.conf as nisacf
import json

# sys.path.append('gen-py') #PYTHON3
pathdir = os.path.split(sys.argv[0])[0]
pathdir = os.path.split(pathdir)[0]
pathdir_ = os.path.join(pathdir, 'gen-py')  # PYTHON3
sys.path.append(pathdir_)
from NisaRPC import NisaRPC #引入客户端类,PYTHON3
from imp import reload
 
from thrift import Thrift 
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import threading


log = logging.getLogger('dupfilter')

notdupfilter=['user_auth','user_acct','user_end']
ree=re.compile('^(java|bash|dash|sh|python|perl|busybox)$')
vaildpname=re.compile('^(sh|bash|dash|python|perl|ruby|busybox)_')

def getvaildpname(ppinfo):
    if vaildpname.match(ppinfo['pcmd']):
        return ppinfo['pcmd']
    return ppinfo['pname']

#grouping by host
class DupfilterBolt(storm.BasicBolt):
    #重复过滤和启发式引擎
    #{time,user,ip,cmd,src,dst,ppname,flag}
    def initialize(self,conf, context):
        self.active={} #存储主机之前的3条不同记录
        self.dsortlist={} #强排序队列
        self.conf=sysconf.conf
        self.getfilter()
        self.getexport()
        self.asynmanage()
        self.kmodule=self.loadkmodule()
        self.getknowledge()
        #mappp
        self.pidmap={} #pid映射表，用于对ppname失败的数据进行重建
        self.lastime=0
        if 'rebuildclear' in self.conf['system']:
            self.clearhistorytime=self.conf['system']['rebuildclear']
        else:
            self.clearhistorytime=60
        log.warn("============initialize succfully==================")

    def loadkmodule(self):
        import importlib
        d,kname=os.path.split(self.conf['system']['knowledge'])
        sys.path.append(d)
        knowledge=importlib.import_module(kname)
        return knowledge
    
    def getknowledge(self):
        #获取知识模块的最新状态数据
        reload(self.kmodule)
        #debug
        #elf.kmodule=self.loadkmodule()
        userknowledge=copy.deepcopy(self.kmodule.parse_userknowledge)
        try:
            libalg.parseKnowledge(userknowledge)
            self.userknowledge=userknowledge
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
            self.getknowledge()
            log.warn("============updatemodels succfully==================")
        elif rs['command']=='resetconfig':
            log.warn('[WARN] have a resetconfig command')
            log.warn(str(rs['data']))
            self.conf=rs['data']
            log.warn("============updateconfig succfully==================")
            
    def getexport(self):
        self.export=[]
        if 'export' not in self.conf:
            return
        for i in self.conf['export']['type'].split(','):
            i=i.strip()
            if not i:continue
            key="export_%s" %i
            try:
                epclass=globals()[key]
                self.export.append(epclass(self.conf['export'],log))
            except Exception as e:
                log.error("[ERROR] Fail create export obj with %s" %key)
                pass 
                
    def getfilter(self):
        self.dfilter={}
        if 'filter' not in self.conf:
            return
        for k,v in self.conf['filter'].items():
            self.dfilter[k]=self.conf['filter'][k].strip().split(';')
        #log.debug(self.dfilter)

    def clearhis(self,now,cleartime):
        if now-self.lastime <= cleartime: #2*60*60
            return
        pmap=self.pidmap
   
        #删除留存
        for host,info in pmap.items():
            pids=list(info.keys())
            for pid in pids:
                try:
                    if pid<1000 or info[pid]['ppid']<100: #对pid，和ppid靠前的进程不进行处理
                        continue            
                    if info[pid]['lastime']<=0 and now-info[pid]['time']>= cleartime:
                        info.pop(pid)
                        continue
                    if info[pid]['lastime']>0 and now-info[pid]['lastime']>=cleartime:
                        info.pop(pid)
                except KeyError:
                    pass
        self.lastime=now

    def rebuildppname(self,dt):
        #return the data for the special event
        if dt['cmd'] in ['fwrite','fread','rwrite','rread','nlisten','noutput']:
            return dt

        pmap=self.pidmap
        pmap.setdefault(dt['ip'],{})
        pmap[dt['ip']][dt['pid']]={'ppid':dt['ppid'],'ppname':dt['ppname'],'pname':dt['dst'],'pcmd':dt['cmd'],'time':dt['time'],'lastime':0}
        #===========
        if dt['ppname']=='NULL':
            if dt['ppid'] in pmap[dt['ip']]:
                ppinfo=pmap[dt['ip']][dt['ppid']]
                ppname=getvaildpname(ppinfo)
                if ree.match(ppinfo['pcmd']):
                    ppname=pmap[dt['ip']][dt['ppid']]['ppname']
                    if ppname=='NULL':
                        try:
                            ppid=pmap[dt['ip']][dt['ppid']]['ppid']
                            ppname=getvaildpname(pmap[dt['ip']][ppid])        
                        except KeyError:
                            pass
                    else:
                        pass
                #对ppname为空，且存在一个ppid映射关系的数据进行尝试重建ppname
                dt['ppname']= ppname #rebuild from the map

        #=============
        #过滤java和纯粹的shell进程
        if dt['cmd']!='java' and (not ree.match(dt['cmd'])):
            return dt

    def parseproc(self,tup):
        #统一预处理
        if tup['cmd'] in ['fwrite','fread']:
            tup['src']=libalg.parsewrpath(tup['src'],self.conf,self.userknowledge)
            return tup
        #处理shell 脚本命令中的随机字符串
        tup['cmd']=libalg.parsershell(tup['cmd'],self.userknowledge)
        tup['ppname']=libalg.parsershell(tup['ppname'],self.userknowledge)
        return tup
    
    def process(self, tup):
        # storm.ack(tup)
        try:
            host,tup=tup.values
            log.debug(f'dupfilter--->tup,{host},{tup["time"]}')
            #缓存数据，进行强行排序
            self.dsortlist.setdefault(host,libalg.sortlist(fcmp=libalg.dictcmp))
            self.dsortlist[host].append(tup) #添加到队列并自动排序
            log.info(f"time is {self.dsortlist[host].get(-1)['time'] - self.dsortlist[host].get(0)['time']}")
        except Exception as err:
            log.debug(f"ERROR,ERROR1, 错误是：{err}")
        #对排序后数据进行检测
        #self.dsortlist.setdefault(host,deque())
        #当强制排序队中队尾到队首时间差>=filtersort
        while self.dsortlist[host].get(-1)['time']-self.dsortlist[host].get(0)['time']>=self.conf['system']['filtersort']: #把排序队列中所有符合条件的弹出检测发送
            try:
                tup=self.dsortlist[host].pop(0)
                log.info(f"dupfilter is into succ :{tup}")
                host=tup['ip']

                if self.conf['system']['rebuilpp']:
                    if not self.lastime:self.lastime=tup['time']
                    tup=self.rebuildppname(tup) #重建ppname，并过滤java,bash,dash,sh,python,perl等进程
                    if not tup:continue #当输入数据时需要过滤的情况下，进入下一循环
                    self.clearhis(tup['time'],self.clearhistorytime) #清除映射表中的无效数据

                if self.confilter(tup):return #配置过滤
                #统一预处理转化
                tup=self.parseproc(tup)
                #配置下的去重过滤,指定的命令不进行去重过滤，目前暂时只有用户登录状态命令
                if self.conf['system']['dupfilter']==1 and (tup['cmd'] not in notdupfilter):
                    #注释掉去重代码
                    self.active.setdefault(host,{})
                    self.active[host].setdefault(tup['user'],deque([tup], maxlen=6))
                    if self.depcheck(host, tup):
                        #log.debug("[Dup:]"+str(tup))
                        return #判定重复
                    else:
                        self.active[host][tup['user']].append(tup)
                log.debug(str(tup))
                # list(map(lambda x:x.write(tup),self.export))
                log.debug(f"dupfilter into tup {host}")
            except Exception as err:
                log.debug(f"ERROR,ERROR2, 错误是：{err}")

            storm.emit((host,tup)) #常规数据发送到后续检测流
            log.debug(f"dupfllter into success!!!")


    def depcheck(self,host,tup):
        rs=[self.isequal(x, tup) for x in self.active[host][tup['user']]]
        if rs.count(True)>0:
            return True
        else:
            return False
        
    def isequal(self,tup1,tup2):
        if abs(tup1['time']-tup2['time'])<=0.5:
            if tup1['cmd']==tup2['cmd']:    
                if tup1['src']==tup2['src']:
                    if tup1['ppname']==tup2['ppname']:
                        return True
        return False

    def confilter(self,tup):
        #配置文件定义过滤
        for k,v in self.dfilter.items():
            for i in self.dfilter[k]:
                if not i:continue
                if tup[k].find(i)>=0:
                    return True
        return False

class contain:
    conf=None    
if __name__ == '__main__':
    sysconf=contain()
    sysconf.conf=json.loads(sys.argv[1])
    if 'log' in sysconf.conf['system']:
        syslog=sysconf.conf['system']['log']
    else:
        syslog='/tmp/sqlnisa'
        
    Bolt=DupfilterBolt()
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
        filename=os.path.join(syslog,'dupfilter.log'+taskid),
        format="%(message)s",
        filemode='w',
    )
    try:
        Bolt.run()
    except Exception as e:
        log.error("[Error] %s" %repr(e))
        log.error("[Error INFO] %s" %traceback.format_exc())
    
