#coding=utf8
import os
import sys
import time
import commands
import requests
import json

class eagleclient:
    """eagle服务类，实现通过REST API的各种远程调用"""
    
    def __init__(self,host,port,name,passwd):
        self.host=host
        self.port=port
        self.name=name
        self.passwd=passwd
        
    def post(self,url,postdata, log):
        """
        url:访问路径全url，含http(s)，string
        postdata:POST数据，string
        """
        # cmd="curl -silent -u %s:%s -X POST -H 'Content-Type:application/json' %s -d '%s'" %(self.name,self.passwd,url,postdata)
        # rs=commands.getstatusoutput(cmd)
        # if not rs[0]:
        #     return rs[1]
        log.info(type(postdata))
        response = requests.post(url, postdata)
        if response.status_code == 200:
            log.info("[INFO] 发送成功")
        else:
            log.info(f"发送状态码是：{response.status_code}")
        
    def get(self,url):
        """
        url:访问路径，包含http(s)和参数，string
        """
        cmd="curl -silent -u %s:%s %s" %(self.name,self.passwd,url)
        rs=commands.getstatusoutput(cmd)
        if not rs[0]:
            return rs[1]        
    
    def alert(self,info,log):
        url="http://%s:%d/eagle-service/rest/entities?serviceName=AlertService" %(self.host,self.port)
        pd=str(info)
        log.info("[INFO] POSTURL::%s" %url)
        log.debug("[DEBUG] POSTDATA::%s" %pd)
        self.post(url,pd, log)
        