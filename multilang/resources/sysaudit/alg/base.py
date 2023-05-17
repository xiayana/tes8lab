#coding=utf8
from abc import ABCMeta, abstractmethod
import time

"""
告警信息json格式化展示
    [
    {
        "timestamp": 1492751348786,
        "tags": {
            "alertExecutorId": "hdfsAuditLogAlertExecutor",
            "site": "sandbox",
            "application": "hdfsAuditLog",
            "policyId": "",
            "alertSource": "test@sandbox.eagle.apache.org",
            "sourceStreams": "hdfsAuditLogEventStream"
        },
        "alertContext": {
            "properties": {
                "src": "set you alert src",
                "sourceStreams": "hdfsAuditLogEventStream",
                "securityZone": "NA",
                "alertDetailUrl": "http://192.168.0.3:9099/eagle-service/ui/#/common/alertDetail/",
                "sensitivityType": "PRIVATE",
                "timestamp": "1490657206700",
                "dst": "NA",
                "cmd": "open",
                "site": "sandbox",
                "alertEventFields": "timestamp,allowed,cmd,host,sensitivityType,securityZone,src,dst,user",
                "application": "hdfsAuditLog",
                "host": "172.17.0.3",
                "alertMessage": "this is a test alert,you must change the text with devpment,alertMessage",
                "policyId": "set you policyId",
                "allowed": "true",
                "alertEvent": "this is a test alert,you must change the text with devpment,alertEvent",
                "policyDetailUrl": "http://192.168.0.3:9099/eagle-service/ui/#/common/policyDetail/?policy=viewPrivate&site=sandbox&executor=hdfsAuditLogAlertExecutor",
                "alertTimestamp": "2017-04-13 08:49:25",
                "user": "root"
            }
        }
    }
]
"""
 #抽象类
class base(object, metaclass=ABCMeta):
  def __init__(self):
    self.name="" #一定要设置此数据，标记支持对哪种训练算法进行支持，和train中算法名称一致即可
  #用户画像入口函数，实体算法必须实现此函数
  @abstractmethod
  def detection(self,user,windowlist,model):
    """
    user 用户
    windowlist 滑动窗口事件list，数据形式：[{'time':xx,'user':xxx,'ip':xxx,'cmd':xxx,'src':xxx,'dst':xxx},......]
    model 对应算法的用户画像数据
    在此函数中根据输入数据和用户画像数据进行异常判定，若有异常，返回self.alert，否则为空
    """
    
    """
    self.alert[0]['timestamp']=int(time.time()*1000)
    self.alert[0]['alertContext']['properties']['host']=windowlist[0]['ip']
    self.alert[0]['alertContext']['properties']['alertMessage']=message
    self.alert[0]['alertContext']['properties']['user']=user
    return ('alg_name',self.alert)
    """
    pass