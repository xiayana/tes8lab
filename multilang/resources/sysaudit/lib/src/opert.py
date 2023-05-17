#coding=utf8
#import pickle
import os
import sys
import json
import base64
import time
#from hdfs3 import HDFileSystem
import threading

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
            print("Can not support this store type,tis is just %s" %(str(self.stype)))
            exit()
            
    def putmodeljson(self,modeljson):
        if modeljson and self.store:
            self.store.putmodeljson(modeljson)
        else:
            print("Can't upload the model to remote")
    
    def getusermodel(self,log,account,sence,whiltlist=[],blacklist=[]):
        if self.store:
            return self.store.getusermodel(log,account,sence,whiltlist, blacklist)
        else:
            if log:log.error("Have not the store connect!!!")

class opert_hdfs:
    
    def __init__(self,conf):
        import hdfs
        self.conf=conf
        if 'hdfs' in self.conf:
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
            print("Please config vaild hdfs")
            exit(1)
            
    def putmodeljson(self,modeljson):
        if modeljson:
            path='/tmp/userprofile.json'
            f=open(path,'w')
            [f.write(m+'\n') for m in modeljson]
            f.close()
            print("INFO: wirte  model json to tmp file: /tmp/userprofile.json")
            #self.hdfs.put('/tmp/userprofile.json',self.conf['system']['hdfspath']+'/userprofile.json')
            self.hdfs.write(self.conf['system']['hdfspath']+'/userprofile.json',data=open(path).read(),overwrite=True)
            print("INFO:put model json to hdfs %s/userprofile.json succfully" %(self.conf['system']['hdfspath']))

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
                    if user in models:
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
        import pymysql
        self.lock = threading.RLock()
        self.conf=conf
        self.table=table
        try:
            self.db=pymysql.connect(**{'host':self.conf['mysql']['host'],\
                                             'user':self.conf['mysql']['user'],\
                                             'passwd':self.conf['mysql']['password'],\
                                             'db':self.conf['mysql']['db'],\
                                             'port':int(self.conf['mysql']['port']),'charset':'utf8'})
            self.cursor=self.db.cursor()
        except Exception as e:
            print(str(e))
            print("Connect pymysql fail")
        
    def putmodeljson(self,modeljson):
        if not self.cursor:
            print("Can't put json,db is not connect!!!")
            exit()
        now=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        for m in modeljson:
            mm=self.parseModel(m)
            with self.lock:
                if self.Isexist(mm[0],mm[1],mm[2],mm[3]):
                    self.cursor.execute("update %s set mtime='%s',model='%s' where account='%s' and user='%s' and alg='%s' and sence='%s'" %(self.table,now,mm[4],mm[0],mm[1],mm[2],mm[3]))
                else:
                    self.cursor.execute("insert into %s values (0,'%s','%s','%s','%s','%s','%s','%s')" %(self.table,mm[0],mm[1],mm[2],mm[3],now,now,mm[4]))
        with self.lock:
            self.db.commit()
        
    
    def parseModel(self,modeljson):#返回(账户名，用户名，算法名，场景，json)
        model=json.loads(modeljson)
        return model['account'],model['user'],model['name'],model['sence'],base64.b64encode(modeljson.encode('utf8'))
    
    def Isexist(self,account,user,name,sence):
        self.cursor.execute("select id from %s where account='%s' and user='%s' and alg='%s' and sence='%s'" %(self.table,account,user,name,sence))
        if len(self.cursor.fetchall())>0:
            return True
        return False

    def getusermodel(self,log,account,sence,whiltlist=[],blacklist=[],mulit=['core','dl','service']):
        with self.lock:
            self.cursor.execute("select id from %s where sence='%s'" %(self.table,sence))
            models={}
            ids=self.cursor.fetchall()
        for i in ids:
            sql = "select user,alg,model from %s where id='%d' and sence='%s' and account='%s'" % (self.table, i[0], sence, account)
            with self.lock:
                self.cursor.execute(sql)
                rs=self.cursor.fetchall()
            user=rs[0][0]
            name=rs[0][1]
            model=json.loads(base64.b64decode(rs[0][2]).decode('utf8'))#debug,decode
            if whiltlist:
                if name not in whiltlist:
                    continue
            elif blacklist:
                if name in blacklist:
                    continue
            if name in mulit: #当算法为指定算法时，支持多模型投票模型结构，即用户画像数据结构同一用户同一算法可以有多个模型
                if type(model['data'])==dict:
                    mobj=model
                else:
                    log.error("NotVaildModelData : the err model  " + model)
                    mobj = None
                    # raise Exception("NotVaildModelData")
            else:
                mobj=model
                
            if not mobj:continue #当getknowledgemodel返回空模型conn = pymysql.connect(host='192,128.1.210',port = 3306,user='8lab',password='8lab',db='nisabk')数据时，直接跳出此次循环

            models.setdefault(user, {})
            models[user].setdefault(name, [])
            models[user][name].append(mobj)
        self.merge_service_models(models)
        return models
    
    def getknowledgemodel(self,ids,log):
        models=[]
        for i in ids[:5]: #目前限制最多进行5个模型的集体决策
            try:
                with self.lock:
                    self.cursor.execute("select model from modelsknowledge where id=%d" %i)
                    result=self.cursor.fetchall()
                model=json.loads(base64.b64decode(result[0][0]).decode()) #debug
                models.append(model)
            except Exception as e:
                log.error("[Error] %s" %repr(e))
                log.error("[Error] have error in getknowledgemodel from opert_mysql，the knowledgemodel id is: %s" %str(ids))
                return
        return models

    def merge_service_models(self, models):
        for user in models:
            for alg in models[user]:
                if alg != 'service':
                    continue
                models[user][alg] = self.merge_service_model_list( models[user][alg] )

    def merge_service_model_list(self, model_list):
        if len(model_list) == 1:
            return model_list[0]

        dst = model_list[0]
        dst.setdefault('data', {})
        dst['data'].setdefault('servicemodel', {})
        dst['data'].setdefault('static', {})
        for index in range(1,len(model_list)):
            src = model_list[index]
            self.mergemodels_service_servicemodel(dst['data']['servicemodel'], src['data']['servicemodel'])
            self.mergemodels_service_static(dst['data']['static'], src['data']['static'])
        return dst

    def mergemodels_service_servicemodel(self, modelstruct, modeldata):
        # 融合servicemodel结构数据
        for block in list(modeldata.keys()):
            # 合并新出现的分区
            if block not in modelstruct:
                modelstruct[block] = modeldata[block]
                continue
            blockmodel = modelstruct[block]
            srcblockmodel = modeldata[block]

            # 当前合并方案：取并集
            # 合并cmd
            for pp in list(srcblockmodel[0].keys()):
                if pp not in blockmodel[0]:
                    blockmodel[0][pp] = srcblockmodel[0][pp]
                else:
                    for p in srcblockmodel[0][pp]:
                        if p not in blockmodel[0][pp]:
                            blockmodel[0][pp][p] = srcblockmodel[0][pp][p]

            # 合并file,net,reg
            for i in range(1, 4):
                typemodel = srcblockmodel[i]  # 遍历获取file，net,reg
                for key in list(typemodel.keys()):
                    for pp in list(typemodel[key].keys()):
                        if pp not in blockmodel[i][key]:
                            blockmodel[i][key][pp] = typemodel[key][pp]
                        else:
                            for p in list(typemodel[key][pp].keys()):
                                if p not in blockmodel[i][key][pp]:
                                    blockmodel[i][key][pp][p] = typemodel[key][pp][p]

    def mergemodels_service_static(self, modelstruct, modeldata):
        # 融合static结构数据
        for block in list(modeldata.keys()):
            # 合并新出现的分区
            if block not in modelstruct:
                modelstruct[block] = modeldata[block]
                continue
            blockmodel = modelstruct[block]
            srcblockmodel = modeldata[block]
            # 当前合并方案：取均值
            blockmodel[0] = sum([blockmodel[0], srcblockmodel[0]]) / 2
            blockmodel[1] = sum([blockmodel[1], srcblockmodel[1]]) / 2


