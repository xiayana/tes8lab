#coding=utf8
import os
import sys
import json
import random
import time
import codecs

nisastr=u"%s INFO FSNamesystem.audit: allowed=%s  ugi=%s (auth:SIMPLE) ip=/%s  cmd=%s  src=%s  dst=%s  perm=%s"
def d2s(dt):
    if dt:
        ts=float(dt['time'])
        x = time.localtime(ts)
        dd=time.strftime('%Y-%m-%d %H:%M:%S',x)
        ms=int((ts-int(ts))*1000)
        dm="%s,%03d" %(dd,ms)
        rs= nisastr %(dm,dt['flag'],dt['user'],dt['ip'],dt['cmd'],dt['src'],dt['dst'],dt['ppname'])
        return rs
    
class export_redis:
    #导出数据到redis
    def __init__(self,conf,log):
        import redis
        self.rhost=conf['rhost']
        self.rport=conf['rport']
        self.rkey=conf['rkey']
        self.istr=conf['ristr']
        try:
            self.rds=redis.Redis(host=self.rhost,port=self.rport)
            log.debug("Redis 连接成功")
        except Exception,e:
            log.debug("Redis 连接失败")
            log.debug(repr(e))
            self.rds=None
            
    def write(self,dt):
        dt={'flag':'true','ppname':'null','user':dt['user'],'ip':dt['ip'],\
            'cmd':dt['cmd'],'src':dt['src'],'dst':dt['table'],'time':dt['time']}
        if self.istr:
            dt=d2s(dt)
        else:
            dt=json.dumps(dt)
        if dt:
            self.rds.lpush(self.rkey,dt)
    
class export_file:
    #导出数据到file
    #conf={'dir':'/tmp/abc','name':'nisalog'}
    def __init__(self,conf,log):
        try:
            self.istr=conf['fistr']
            self.log=log
            p=self.createlogfile(conf)
        except Exception,e:
            log.debug(repr(e))
    
    def write(self,dt):
        dt={'flag':'true','ppname':'null','user':dt['user'],'ip':dt['ip'],\
            'cmd':dt['cmd'],'src':dt['src'],'dst':dt['table'],'time':dt['time']}
        if self.istr:
            dt=d2s(dt)
        else:
            dt=json.dumps(dt)
        if dt:
            try:
                self.ef.write(dt+'\n')
            except Exception:
                self.log.error("Error :write date to file fail!!!")
    
    def createlogfile(self,conf):
        i=float(random.randint(1,3000))
        time.sleep(i/1000)
        if not os.path.isdir(conf['fdir']):
            os.mkdir(conf['fdir'])
        while True:
            p="%s/%s-%d.log" %(conf['fdir'],conf['fname'],random.randint(1,100))
            if os.path.isfile(p):
                pass
            else:
                break
        self.ef=codecs.open(p,'w','utf-8')
        return p
        
class export_kafka:
    def __init__(self,conf,log):
        try:
            self.iport=conf['kiport']
            self.topic=conf['ktopic']
            self.istr=conf['kistr']
            self.log=log
            self.producer=self.connectkafka()
        except Exception,e:
            log.error("[Error] have fail in init kafka export")
            log.error("[Error] %s" %repr(e))
            
    def connectkafka(self):
        from kafka import KafkaClient,SimpleProducer
        kafka=KafkaClient(self.iport)
        #kafak message product
        producer=SimpleProducer(kafka)
        return producer
    
    def write(self,dt):
        #{'time':1,'user':2,'ip':3,'cmd':4,'table':5,'src':6}
        self.log.debug("[export] %s" %(str(dt)))
        if not dt:return 
        rs={'flag':'true','ppname':'null','user':dt['user'],'ip':dt['ip'],\
            'cmd':dt['cmd'],'src':dt['src'],'dst':dt['table'],'time':dt['time']}
        try:
            if self.istr:
                rs=d2s(rs)
            else:
                rs=json.dumps(rs)
            self.producer.send_messages(self.topic,rs.encode('utf8'))
        except Exception,e:
            self.log.error("[Error] have fail in write to kafka export")
            self.log.error("[Error] %s" %repr(e))
            self.log.error("[Error} %s" %(self.topic))
            self.log.error("[Error] %s" %rs)
        
        
        