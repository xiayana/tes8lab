#coding=utf8

'''
v0.3告警数据结构
[{
    "timestamp":int(time.time()*1000),
    "tags":{"site":"sandbox","alertSource":"test@sandbox.eagle.apache.org","application":"hdfsAuditLog","sourceStreams":"hdfsAuditLogEventStream","policyId":"UserProfile","alertExecutorId":"UserProfileExecutor"},
    "alertContext":{"properties":{
    "allowed":"true",
    "site":"sandbox",
    "application":"hdfsAuditLog",
    "host":"172.17.0.3",
    "alertEventFields":"timestamp,allowed,cmd,host,sensitivityType,securityZone,src,dst,user",
    "policyDetailUrl":"http://192.168.0.3:9099/eagle-service/ui/#/common/policyDetail/?policy=viewPrivate&site=sandbox&executor=hdfsAuditLogAlertExecutor",
    "securityZone":"NA",
    "dst":"NA",
    "alertMessage":"this is a test alert,you must change the text with devpment,alertMessage",
    "alertEvent":"this is a test alert,you must change the text with devpment,alertEvent",
    "timestamp":"1490657206700",
    "alertTimestamp":time.ctime(),
    "cmd":"open",
    "alertDetailUrl":"http://192.168.0.3:9099/eagle-service/ui/#/common/alertDetail/",
    "sourceStreams":"hdfsAuditLogEventStream",
    "policyId":"Userprofile",
    "sensitivityType":"PRIVATE",
    "src":"set you alert src",
    "user":"default_user"}
    }}]
    
v0.4告警数据结构
[
    {
        "timestamp": 1500460705407,
        "tags": {
            "site": "sandbox",
            "alertSource": "27644@sandbox.eagle.apache.org",
            "application": "hdfsAuditLog",
            "sourceStreams": "hdfsAuditLogEventStream",
            "policyId": "Userprofile",
            "alertExecutorId": "hdfsAuditLogAlertExecutor"
        },
        "alertContext": {
            "properties": {
                "allowed": "true",
                "site": "sandbox",
                "application": "hdfsAuditLog",
                "host": "172.17.0.2",
                "alertEventFields": "timestamp,allowed,cmd,host,sensitivityType,securityZone,src,dst,user",
                "policyDetailUrl": "http://192.168.0.3:9099/eagle-service/ui/#/common/policyDetail/?policy=test1&site=sandbox&executor=hdfsAuditLogAlertExecutor",
                "securityZone": "NA",
                "dst": "chrome.exe",
                "alertMessage": "this is a test alert message,you must change the text with devpment,alertMessage",
                "alertEvent": "this is a test alert event,you must change the text with devpment,alertMessage",
                "timestamp": "1499961520000",
                "alertTimestamp": time.ctime(),
                "cmd": "fwrite",
                "alertDetailUrl": "http://192.168.0.3:9099/eagle-service/ui/#/common/alertDetail/tv4MJX%5F%5F%5FqKlkpmAlXeMWIuAAAjHMWiXr7mdROsfe8qEr9wdADXfR28vvscgmSntBpJN31ykBVB3iZNS",
                "sourceStreams": "hdfsAuditLogEventStream",
                "policyId": "Userprofile",
                "sensitivityType": "NA",
                "src": "set you alert src",
                "user": "default_user"
            }
        }
    }
]
'''
import time
class alert(object):
  def __init__(self):
    self.alert=[{
    "timestamp":int(time.time()*1000),
    "tags":{"site":"sandbox","alertSource":"test@sandbox.eagle.apache.org","application":"hdfsAuditLog","sourceStreams":"hdfsAuditLogEventStream","policyId":"UserProfile","alertExecutorId":"UserProfileExecutor"},
    "alertContext":{"properties":{
    "allowed":"true",
    "site":"sandbox",
    "application":"hdfsAuditLog",
    "host":"x.x.x.x",
    "alertEventFields":"timestamp,allowed,cmd,host,sensitivityType,securityZone,src,dst,user",
    "policyDetailUrl":"http://x.x.x.x:9099/eagle-service/ui/#/common/policyDetail/?policy=viewPrivate&site=sandbox&executor=hdfsAuditLogAlertExecutor",
    "securityZone":"NA",
    "dst":"NA",
    "alertMessage":"this is a test alert,you must change the text with devpment,alertMessage",
    "alertEvent":"this is a test alert,you must change the text with devpment,alertEvent",
    "timestamp":"1490657206700",
    "alertTimestamp":time.ctime(),
    "cmd":"open",
    "alertDetailUrl":"http://x.x.x.x:9099/eagle-service/ui/#/common/alertDetail/",
    "sourceStreams":"hdfsAuditLogEventStream",
    "policyId":"set you policyId",
    "sensitivityType":"PRIVATE",
    "src":"set you alert src",
    "user":"default_user"}
    }}]

  def setAlertmsg(self,msg):
    self.alert[0]['alertContext']['properties']['alertMessage']=msg
  
  def setHost(self,host):
    self.alert[0]['alertContext']['properties']['host']=host
    
  def setUser(self,user):
    self.alert[0]['alertContext']['properties']['user']=user
  
  def setDate(self,dates):
      self.alert[0]['alertContext']['properties']['alertTimestamp']=dates
      
  def getAlert(self):
    return self.alert
