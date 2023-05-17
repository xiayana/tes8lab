#coding=utf8
from .base import *
from lib.alertbase import alert

class alg_detection(base):
    """
     样例检测算法类，类名不能变更
     必须设置self.name标明支持哪种离线训练算法进行在线测试
     必须实现函数detection,其输入参数为,用户名,窗口事件列表,对应用户和算法的模型数据
     conf为deletection.ini数据字典化
     
    """    
    def __init__(self,conf,lang,log=None):
        #输入参数：配置结构，语言结构，日志对象
        base.__init__(self)
        self.name="example"
 
    def detection(self, user, windowlist, model):
        """
        model 为train中getjson转化的字典值,如example的model为 {'name':'example','user':'test','data':[1,2,3,4,5]}
        此处自身随意实现检测评估算法
        [{'time':1325520027.123,'user':"test",'ip':"8.8.8.8",'cmd':"open",'src':"/tmp/test",'dst':"NULL"},...]
        """
        assert model['name']=='example'
        assert model['user']=='test'
        assert model['data']==[1,2,3,4,5]
        #返回告警信息元组（算法名，告警内容，生产环境为self,alert类）
        ac=alert()
        ac.setHost(windowlist[0]['ip'])
        ac.setUser(windowlist[0]['name'])
        ac.setAlertmsg(alertcontent)
        return ('example',alert.getAlert(),"None")

