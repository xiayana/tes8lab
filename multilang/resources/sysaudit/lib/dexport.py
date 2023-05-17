#coding=utf8
import os
import json
import random
import time
import codecs

nisastr="%s INFO FSNamesystem.audit: allowed=%s  ugi=%s (auth:SIMPLE) ip=/%s  cmd=%s  src=%s  dst=%s  perm=%s"
def d2s(dt):
    if dt:
        ts=float(dt['time'])
        x = time.localtime(ts)
        dd=time.strftime('%Y-%m-%d %H:%M:%S',x)
        ms=int((ts-int(ts))*1000)
        dm="%s,%03d" %(dd,ms)
        rs= nisastr %(dm,dt['flag'],dt['user'],dt['ip'],dt['cmd'],dt['src'],dt['dst'],dt['ppname'])
        return rs

def data2str(dt):
    #输入数据转化为字符串
    if type(dt)==str:
        rs=dt
    elif type(dt)==dict:
        rs=json.dumps(dt)
    else:
        rs=str(dt)
    return rs

class export_redis:
    #导出数据到redis
    def __init__(self,conf,log):
        self.rhost = conf['rhost']
        self.rport = conf['rport']
        self.rkey = conf['rkey']
        self.rpassword = conf['rpassword']
        self.security = conf['security']
        self.log = log
        try:
            # if conf['redisclusterstatus'] == 'on':
            #     from rediscluster import StrictRedisCluster
            #     self.rds = StrictRedisCluster(startup_nodes=conf['rediscluster'])
            # else:
            import redis
            if self.security == 'on':
                self.rds = redis.Redis(host=self.rhost, port=self.rport, password=self.rpassword)
            else:
                self.rds = redis.Redis(host=self.rhost, port=self.rport)
            log.debug("Redis 连接成功")
        except Exception as e:
            log.debug("Redis 连接失败")
            log.debug(repr(e))
            self.rds=None
            
    def write(self,dt):
        try:
            dt=data2str(dt)
            if dt:
                self.rds.lpush(self.rkey,dt)
        except Exception as e:
            self.log.error("[Redis Export Error] %s" %repr(e))
    
class export_file:
    #导出数据到file
    #conf={'dir':'/tmp/abc','name':'nisalog'}
    def __init__(self,conf,log):
        try:
            self.log=log
            p=self.createlogfile(conf)
        except Exception as e:
            log.debug(repr(e))
    
    def write(self,dt):
        try:
            dt=data2str(dt)
            if dt:
                self.ef.write(dt+'\n')
        except Exception as e:
            self.log.error("[File Export Error] %s" %repr(e))
    
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
            self.log=log
            self.producer=self.connectkafka()
        except Exception as e:
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
        try:
            dt=data2str(dt)
            if dt:
                self.log.debug("[export] %s" %dt) 
                self.producer.send_messages(self.topic,dt.encode('utf8'))
        except Exception as e:
            self.log.error("[Kafka Export Error] %s" %repr(e))
 
