#coding=utf8
import time
import re
import json

#ree=re.compile("(?P<time>\S+ \S+) INFO FSNamesystem.audit: allowed\=(?P<flag>\S+?)\s+ugi\=(?P<user>\S+) \S+\s+ip\=/(?P<ip>\S+)\s+cmd\=(?P<cmd>\S+?)\s+src\=(?P<src>\S+?)\s+dst\=(?P<dst>\S+)\s+perm\=(?P<perm>\S+)")

def gettime(times):
    a,b=times.split(',')
    b=float(b)/1000
    return time.mktime(time.strptime(a,'%Y-%m-%d %H:%M:%S'))+b
        
def parsemsg(msg,log):
    #sys 场景数据解析成dict格式
    dt=json.loads(msg)
    # log.debug(f"{type(dt)}, 数据是：{dt}")
    if type(dt) != dict:
        try:

            dt = eval(dt)
        except Exception as e:
            log.debug(f"dt---string--->dict err:{e}")
    dt['time']=gettime(dt['time'])
    return dt
    '''
        msg=msg.strip()
        m=ree.match(msg)
        if m:
            #[time,user,ip,cmd,src,dst,ppname,flag]
            return {"time":gettime(m.groupdict()['time']),
                    "user":m.groupdict()['user'].decode('utf8'),
                    "ip":m.groupdict()['ip'],
                    "cmd":m.groupdict()['cmd'].decode('utf8'),
                    "src":m.groupdict()['src'].decode('utf8'),
                    "dst":m.groupdict()['dst'].decode('utf8'),
                    "ppname":m.groupdict()['perm'].decode('utf8'),
                    "flag":m.groupdict()['flag']}
    '''                                                                      
def syslog2dict(tups,log):
    try:
        return parsemsg(tups,log)
    except Exception as e:
        log.error("[ERROR] %s " %repr(e))
        log.error("[ERROR] Parse Error: %s " %tups)
        

    



