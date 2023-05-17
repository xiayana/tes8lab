#coding=utf8
import time
import os
import re
#import lib.lib_alg

vaildpname=re.compile('^(sh|bash|dash|python|perl|ruby|busybox)_')

def getvaildpname(tup):
    if vaildpname.match(tup['cmd']):
        return tup['cmd']
    return tup['dst']

def fromts2block(hour,part): #python3        
    div = 24 / int(part)
    return int(int(hour) / div)

def getmd4block(block,model):
    if block in model['service']['data']['servicemodel']:
        return model['service']['data']['servicemodel'][block]
    return None

def getblockmodel(tp,part,model):
        tstruct=time.localtime(tp)
        time_cur = tstruct.tm_hour #   从时间戳中取出小时

        time_part = fromts2block(time_cur,part)  #  小时转时间划分区域
        rs=getmd4block(str(time_part), model)
        if not rs:
             #若时间在小时的临界点上，尝试取相邻时区模型
            if tstruct.tm_min>=50:
                flag=1
            elif tstruct.tm_min <=10:
                flag=-1
            else:
                return rs,time_part
            time_cur+=flag
            if time_cur>23:time_cur=0
            elif time_cur<0:time_cur=23 
            time_part = fromts2block(time_cur,part)  #  小时转时间划分区域
            rs=getmd4block(str(time_part), model)
        return rs,time_part

def getalertrs(conf):
    alertrs={'account':conf['system']['account'],\
             'sence':conf['system']['sence'],\
             'gb':conf['parameter']['part']}
    return alertrs

def setalertrs(alertrs,value,msg):
    alertrs['cmd']=value['cmd']
    alertrs['src']=value['src']
    alertrs['ppname']=value['ppname']
    alertrs['dst']=value['dst']
    alertrs['msg']=msg
    return alertrs

#对随机路径进行检测验证的功能函数，由map高阶调用
ree1=re.compile('[0-9a-z]+\-[0-9a-z]+\-[0-9a-z]+\-[0-9a-z]+')
ree2=re.compile('[0-9a-z]+')
def isidpath(s):
    if len(s)>=36 and ree1.match(s):
        return 1
    elif len(s)==64 and ree2.match(s):
        return 1
    return 0

def Detection(value,model,conf,lang):
    #返回 告警类型，告警内容字典
    #{'name':'service','user':'$ip','servicemodel':{tb:(plist,nlist,flist,rlist),...}}
    #{time,user,ip,cmd,src,dst,ppname}
    #iguseract=["user_auth","user_acct","user_end"]
    #if value['cmd'] in iguseract:
    #return
    #获取对应的分区模型数据和分区
    md,tb=getblockmodel(value['time'],int(conf['parameter']['part']), model)
    '''
    {cmd,src,dst,ppname,gb,tb,account,user,alg,sence,msg}
    '''
    alertrs=getalertrs(conf)
    alertrs['tb']=tb
    alertrs['user']=value['user']
    alertrs['alg']='service'
    
    #当获取到对应的时间分片模型数据时，分别对不同的行为类型进行操作
    if md:
        if value['cmd']=="nlisten":
            if value['ppname'] in md[1]['nlisten']:
                if value['src'] not in md[1]['nlisten'][value['ppname']]:
                    msg = lang.service_listen_inet %(value['user'],value['ppname'],value['src'])
                    return "nlisten", setalertrs(alertrs,value,msg)
            else:
                msg=lang.service_listen_ipro %(value['user'],value['ppname'],value['src'])
                return 'nlisten',setalertrs(alertrs,value,msg)

        elif value['cmd']=='noutput':
            if value['ppname'] in md[1]['noutput']:
                if value['src'] not in md[1]['noutput'][value['ppname']]:
                    msg= lang.service_output_inet %(value['user'],value['ppname'],value['src'])
                    return 'noutput',setalertrs(alertrs,value,msg)
            else:
                msg= lang.service_output_ipro %(value['user'],value['ppname'],value['src'])
                return 'noutput',setalertrs(alertrs,value,msg)   
            
        elif value['cmd']=='fwrite':
            #pathhash=fpath[0] #lib.lib_alg.BKDRhash(fpath[0])
            if value['ppname'] in md[2]['fwrite']:
                if value['src'] not in md[2]['fwrite'][value['ppname']]:
                    msg= lang.service_fwrite_ipath %(value['user'],value['ppname'],value['src'])
                    return 'fwrite',setalertrs(alertrs,value,msg)
            else:
                msg= lang.service_fwrite_ipro %(value['user'],value['ppname'],value['src'])
                return 'fwrite',setalertrs(alertrs,value,msg)   
            
        elif value['cmd']=='fread':
            #pathhash=fpath[0] #lib.lib_alg.BKDRhash(fpath[0])
            if value['ppname'] in md[2]['fread']:
                if value['src'] not in md[2]['fread'][value['ppname']]:
                    msg= lang.service_fread_ipath %(value['user'],value['ppname'],value['src'])
                    return 'fread',setalertrs(alertrs,value,msg)
            else:
                msg= lang.service_fread_ipro %(value['user'],value['ppname'],value['src'])
                return 'fread',setalertrs(alertrs,value,msg)         

        elif value['cmd']=='rwrite':
            src=value['src'] #lib.lib_alg.BKDRhash(value['src'])
            if value['ppname'] in md[3]['rwrite']:
                if src not in md[3]['rwrite'][value['ppname']]:
                    msg= lang.service_rwrite_ipath %(value['user'],value['ppname'],value['src'])
                    return 'rwrite',setalertrs(alertrs,value,msg)
            else:
                msg= lang.service_rwrite_ipro %(value['user'],value['ppname'],value['src'])
                return 'rwrite',setalertrs(alertrs,value,msg)      
        
        elif value['cmd']=='rread':
            src=value['src'] #lib.lib_alg.BKDRhash(value['src'])
            if value['ppname'] in md[3]['rread']:
                if src not in md[3]['rread'][value['ppname']]:
                    msg= lang.service_rread_ipath %(value['user'],value['ppname'],value['src'])
                    return 'rread',setalertrs(alertrs,value,msg)
            else: 
                msg= lang.service_rread_ipro %(value['user'],value['ppname'],value['src'])
                return 'rread',setalertrs(alertrs,value,msg)       
        else:
            #转化脚本行为，当前指令为脚本执行时，取cmd值作为当前进程名，否则取dst值
            if vaildpname.match(value['cmd']):
                dst=value['cmd']
            else:
                dst=value['dst'] #lib.lib_alg.BKDRhash(value['dst'])
            
            #根据获取的dst（pname）进行检测
            if value['ppname'] in md[0]:
                if dst not in md[0][value['ppname']]:
                    msg =lang.service_pro_isub %(value['user'],value['ppname'],dst)
                    return 'proc',setalertrs(alertrs,value,msg)
            else: #当未在对应的父进程活动列表中找到合法状态时，从NULL中寻找，若再失败则告警 
                #if (not md[0].has_key('NULL')) or (not md[0]['NULL'].has_key(dst)): 
                msg= lang.service_pro_ipp %(value['user'],value['ppname'],dst)
                return 'proc',setalertrs(alertrs,value,msg)    
    else:
        msg= lang.service_notexist %str(value)
        return 'noexist',setalertrs(alertrs,value,msg)
