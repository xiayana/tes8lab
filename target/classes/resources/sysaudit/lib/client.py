#coding=utf8
import os
import sys
import time
import subprocess
import json
import requests

class eagleclient:
    """eagle服务类，实现通过REST API的各种远程调用"""
    
    def __init__(self,host,port,name,passwd,qingcloudalert):
        self.host=host
        self.port=port
        self.name=name
        self.passwd=passwd
        self.qingcloudalert=qingcloudalert
        
    def post_with_user(self,url,postdata,log):
        """
        url:访问路径全url，含http(s)，string
        postdata:POST数据，string 
        """
        # cmd="curl -silent -u %s:%s -X POST -H 'Content-Type:application/json' %s -d '%s'" %(self.name,self.passwd,url,postdata)
        # rs=subprocess.getstatusoutput(cmd)
        # if not rs[0]:
        #     return rs[1]
        log.info(type(postdata))
        response = requests.post(url, postdata)
        if response.status_code == 200:
            log.info("[INFO] 发送成功")
        else:
            log.info(f"发送状态码是：{response.status_code}")

    def post(self, url, postdata, log):
        """
        url:访问路径全url，含http(s)，string
        postdata:POST数据，string
        """
        # cmd="curl -silent -X POST -H 'Content-Type:application/json' %s -d '%s'" %(url,postdata)
        # rs=subprocess.getstatusoutput(cmd)
        # log.debug('post result :: %s' %(str(rs)))
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
        rs=subprocess.getstatusoutput(cmd)
        if not rs[0]:
            return rs[1]        

    def alert(self,info,log):
        #告警函数，调用curl发起相关请求
        pd=info.replace('u\"','\"')
        url="http://%s:%d/eagle-service/rest/entities?serviceName=AlertService" %(self.host,self.port)
        log.info("[INFO] POSTURL::%s" %url)
        log.debug("[DEBUG] POSTDATA::%s" %pd)
        self.post_with_user(url, pd, log)

        # log.info('qingcloud alert url::%s' % self.qingcloudalert['url'])
        # self.post(self.qingcloudalert['url'], pd, log)
