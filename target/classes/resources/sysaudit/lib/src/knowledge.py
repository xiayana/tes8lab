#coding=utf8
import os
import sys
#加载知识库模块
sys.path.append(sys.path[0]+r'/lib')
from knowbase import *


class knowledgeBase:
    def __init__(self,conf,userknowledge,log=None):
        self.conf=conf
        self.log=log
        self.userknowledge=userknowledge
      
    #{time,user,ip,cmd,src,dst,ppname}
    def servicemodeldecide(self,dt):
        try:
            commonknowledge(dt)
            self.checkwithTrustfwrite(dt)
            self.checkwithTrustfread(dt)
            self.checkwithTrustconnect(dt)
            self.checkwithTrustsub(dt)
            self.checkwithTrustPP(dt) #debug
            self.checkwithTrustPsub(dt)
            return True
        except ignore as e:
            #忽略告警
            self.log.info(repr(e))
            return False
        except Exception as e:
            self.log.error("[ERROR] %s" %repr(e))
            #对触发异常的数据进行告警操作
            return False

    def checkwithTrustfwrite(self,dt):
        if dt['cmd']=="fwrite":
            return self.checkwithuserknow(dt['src'],self.userknowledge['trustfwrite'],dt)
        return True
    
    def checkwithTrustfread(self,dt):
        if dt['cmd']=="fread":
            return self.checkwithuserknow(dt['src'],self.userknowledge['trustfread'],dt)
        return True            
    
    def checkwithTrustPP(self,dt):
        return self.checkwithuserknow(dt['ppname'],self.userknowledge['trustPP'],dt)
    
    def checkwithTrustsub(self,dt):
        return self.checkwithuserknow(dt['cmd'],self.userknowledge['trustsub'],dt)
    
    def checkwithTrustPsub(self,dt):
        if dt['ppname'] in self.userknowledge['trustPsub']:
            if dt['cmd'] in self.userknowledge['trustPsub'][dt['ppname']]:
                if self.userknowledge['trustPsub'][dt['ppname']][dt['cmd']]:
                    raise ignore("[IGNORE] %s" %(str(dt)))
        return True

    def checkwithTrustconnect(self,dt):
        #验证是否可信外联
        if dt['cmd']=="noutput":
            return self.checkwithuserknow(dt['src'],self.userknowledge['trustconnect'],dt)
        return True

    #针对输入数据和知识进行循环匹配
    def checkwithuserknow(self,dst,know,dt):
        for name,kv in know.items():
            if len(dst)>= kv['min']:
                self.log.debug(f"{kv['ree'].match(dst)}, {kv['ree']}, {dst}")
                if 'content' in kv and (dst in kv['content']):
                    raise ignore("[IGNORE],content %s" %(str(dt)))
                if 'ree' in kv and kv['ree'].match(dst):
                    raise ignore("[IGNORE] ree %s" %(str(dt)))
        return True
