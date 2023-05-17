#coding=utf8
#import pickle
import os
import sys
import json
import base64
import time
#from hdfs3 import HDFileSystem



class opert:
    '''
    操作类，用于模型上传，下载，更新
    '''
    def __init__(self,conf={},mysqltable='models'):
        self.conf=conf
        self.stype=['hdfs','mysql']
        self.current=self.conf['system']['store']
        if self.current=='hdfs':
            self.store=opert_hdfs(conf)
        elif self.current=='mysql':
            self.store=opert_mysql(conf,mysqltable)
        else:
            print "Can not support this store type,tis is just %s" %(str(self.stype))
            exit()
            
    def putmodeljson(self,modeljson):
        if modeljson and self.store:
            self.store.putmodeljson(modeljson)
        else:
            print "Can't upload the model to remote"
    
    def getusermodel(self,log,account,sence,whiltlist=[],blacklist=[]):
        if self.store:
            return self.store.getusermodel(log,account,sence,whiltlist, blacklist)
        else:
            if log:log.error("Have not the store connect!!!")

class opert_hdfs:
    
    def __init__(self,conf):
        import hdfs
        self.conf=conf
        if self.conf.has_key('hdfs'):
            self.hdfs = hdfs.Client("http://%s:%d" %(self.conf['hdfs']['host'],int(self.conf['hdfs']['port'])))#(HDFileSystem(host=self.conf['hdfs']['host'], port=int(self.conf['hdfs']['port']))
            try:
                self.hdfs.list(self.conf['system']['hdfspath'])
            except Exception:
                self.hdfs.makedirs(self.conf['system']['hdfspath'])
                self.hdfs.set_permission(self.conf['system']['hdfspath'],"777")
            """采用hdfs3库操作代码，因依赖系统库，舍弃
            if not self.hdfs.exists(self.conf['system']['hdfspath']):
                self.hdfs.mkdir(self.conf['system']['hdfspath'])
                self.hdfs.chmod(self.conf['system']['hdfspath'],0o777)
            """
        else:
            print "Please config vaild hdfs"
            exit(1)
            
    def putmodeljson(self,modeljson):
        if modeljson:
            path='/tmp/userprofile.json'
            f=open(path,'w')
            [f.write(m+'\n') for m in modeljson]
            f.close()
            print "INFO: wirte  model json to tmp file: /tmp/userprofile.json"
            #self.hdfs.put('/tmp/userprofile.json',self.conf['system']['hdfspath']+'/userprofile.json')
            self.hdfs.write(self.conf['system']['hdfspath']+'/userprofile.json',data=open(path).read(),overwrite=True)
            print "INFO:put model json to hdfs %s/userprofile.json succfully" %(self.conf['system']['hdfspath'])

#----------------
    def getmodeljson(self,name,log=None):
        hdfs_path=self.conf['system']['hdfspath']+name
        #local_path="/tmp/out_userprofile.json"
        with self.hdfs.read(hdfs_path) as fs:
            content=fs.read()
            return content

    
    def getusermodel(self,log,account,sence,whiltlist=[],blacklist=[]): #黑白名单，基于算法名过滤
        models={}
        fjson=self.getmodeljson("/userprofile.json",log)
        for line in fjson.split('\n'):
            line=line.strip()
            if line:
                try:
                    #log.debug("json: "+line)
                    model=json.loads(line)
                    user=model['user']
                    name=model['name']
                    m_sence=model['sence']
                    m_account=model['account']
                    if sence!=m_sence or account!=m_account:
                        continue
                    if whiltlist:
                        if name not in whiltlist:
                            continue
                    elif blacklist:
                        if name in blacklist:
                            continue
                    if models.has_key(user):
                        models[user][name]=model
                    else:
                        models[user]={name:model}             
                except Exception:
                    log.error("Error:"+str(sys.exc_info()[1]))
        #models={'user':{'ai':modle,...},...}        
        return models
#===================
class opert_mysql:
    '''
        """
        
        "CREATE SCHEMA `nisa` DEFAULT CHARACTER SET utf8"
            
        CREATE TABLE `nisa`.`models` (
        `id` INT NOT NULL AUTO_INCREMENT,
        `account` VARCHAR(45) NULL,
        `user` VARCHAR(120) NULL,
        `alg` VARCHAR(45) NULL,
        `sence` VARCHAR(45) NULL,
        `ctime` DATETIME(6) NULL,
        `mtime` DATETIME(6) NULL,
        `model` LONGTEXT NULL,
        PRIMARY KEY (`id`));
        
        
        
        select id from nisa.models where user='xxx' and alg='xxx' and 'sence'='xxx'; 查询模型
        insert into nisa.models values (0,'test','alg_test','sence','1991-01-11 11:11:11','1991-01-11 11:11:11','xxxx'); 新增策略
        update nisa.models set mtime="xxx",model="xxx" where user='xx' and alg='xx' and sence='xx'; #更新策略
    '''    
    def __init__(self,conf,table):
        import MySQLdb
        self.conf=conf
        self.table=table
        try:
            self.db=MySQLdb.connect(**{'host':self.conf['mysql']['host'],\
                                             'user':self.conf['mysql']['user'],\
                                             'passwd':self.conf['mysql']['password'],\
                                             'db':self.conf['mysql']['db'],\
                                             'port':int(self.conf['mysql']['port'])})
            self.cursor=self.db.cursor()
        except Exception,e:
            print str(e)
            print "Connect mysql fail"
        
    def putmodeljson(self,modeljson):
        if not self.cursor:
            print "Can't put json,db is not connect!!!"
            exit()
        now=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        for m in modeljson:
            mm=self.parseModel(m)
            if self.Isexist(mm[0],mm[1],mm[2],mm[3]):
                self.cursor.execute("update %s set mtime='%s',model='%s' where account='%s' and user='%s' and alg='%s' and sence='%s'" %(self.table,now,mm[4],mm[0],mm[1],mm[2],mm[3]))
                print("update %s set mtime='%s',model='%s' where account='%s' and user='%s' and alg='%s' and sence='%s'" %(self.table,now,mm[4],mm[0],mm[1],mm[2],mm[3]))
            else:
                self.cursor.execute("insert into %s values (0,'%s','%s','%s','%s','%s','%s','%s')" %(self.table,mm[0],mm[1],mm[2],mm[3],now,now,mm[4]))
                print("insert into %s values (0,'%s','%s','%s','%s','%s','%s','%s')" %(self.table,mm[0],mm[1],mm[2],mm[3],now,now,mm[4]))
        self.db.commit()
        
    
    def parseModel(self,modeljson):#返回(账户名，用户名，算法名，场景，json)
        model=json.loads(modeljson)
        return model['account'],model['user'],model['name'],model['sence'],base64.b64encode(modeljson)
    
    def Isexist(self,account,user,name,sence):
        self.cursor.execute("select id from %s where account='%s' and user='%s' and alg='%s' and sence='%s'" %(self.table,account,user,name,sence))
        if len(self.cursor.fetchall())>0:
            return True
        return False
    
    def getusermodel(self,log,account,sence,whiltlist=[],blacklist=[]):
        self.cursor.execute("select id from %s where sence='%s'" %(self.table,sence))
        models={}
        ids=self.cursor.fetchall()
        for i in ids:
            sql="select user,alg,model from %s where id='%d' and sence='%s' and account='%s'" %(self.table,i[0],sence,account)
            self.cursor.execute(sql)
            rs=self.cursor.fetchall()
            user=rs[0][0]
            name=rs[0][1]
            model=json.loads(base64.b64decode(rs[0][2]))
            if whiltlist:
                if name not in whiltlist:
                    continue
            elif blacklist:
                if name in blacklist:
                    continue
            if models.has_key(user):
                models[user][name]=model
            else:
                models[user]={name:model}
        return models