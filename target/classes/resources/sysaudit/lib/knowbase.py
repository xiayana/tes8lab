#coding=utf8
import re
import os
#定义通用知识

class ignore(Exception):
    def __init__(self,err):
        Exception.__init__(self,err)

#描述常见的低中高敏感命令
cmdread=re.compile("cat|ls|cd|grep|ll|vim?|grep|tail|top|du|g?awk|find|sed|echo|sort|head")
cmdnet=re.compile("netstat|ifconfig|ping")
cmdsys=re.compile("date|run-parts|env|mesg|md5sum|locale|dpkg|xargs")
cmdknows=[cmdread,cmdnet,cmdsys]
#交互式程序,仅当父进程是以下进程时才触发
intershell=re.compile("bash|sh|dash|-dash|-bash|python(\S+)?|perl")


def commonknowledge(dt):
    if not intershell.match(os.path.split(dt['ppname'])[1]): #针对ppname不是交互式进程的异常告警，直接判定为异常 
        return True
    
    for ree in cmdknows:
        if len(dt['cmd'])<10 and ree.match(dt['cmd']): #系统通用命令长度较短，暂时使用10进行限制加快效率
            #基于知识，当前触发异常数据合法，后续不产生告警
            raise ignore("[IGNORE] %s" %(str(dt)))
    #不合法异常数据，告警
    return True