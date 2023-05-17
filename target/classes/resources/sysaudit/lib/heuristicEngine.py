#coding=utf8
from lib.alertbase import alert
from lib.lib_alg import sortlist,dictcmp
import traceback

class heuristicEngine:
    def __init__(self,userknowledge,log,conf,lang):
        self.userknowledge=userknowledge
        self.hostflags={}
        self.log=log
        self.conf=conf
        self.lang=lang
        
    def detection(self,tup):
        try:
            flags=self.setflag(tup)
            if flags:
                self.log.info("[flags] %s : %s" %(str(flags),str(tup)))
            return self.getrswithrule(tup, flags),flags
        except Exception as e:
            self.log.error("[ERROR] %s" %repr(e))
            self.log.error(traceback.format_exc())
            return None,None
    
    def setflag_act(self,flagstruct,tup):
        #根据知识和数据，设定标志
        self.hostflags.setdefault(tup['ip'],{})
        hostflag=self.hostflags[tup['ip']]
        if flagstruct['store']==1:
            for i in flagstruct['type']:
                hostflag[i]=tup['time']
        elif flagstruct['store']==2:
            hostflag.setdefault(flagstruct['type'][0],sortlist(imax=flagstruct['max'],fcmp=dictcmp))
            hostflag[flagstruct['type'][0]].append(tup)
            
    def setflag(self,tup):
        flagset=self.userknowledge['heuristic_flag']
        #用于存储此处设置的标志
        current=[]
        for v in list(flagset.values()):
            flag=True
            for key,model in v['condition'].items():
                if 'ree' in model:
                    flag=flag and (model['ree'].match(tup[key])!=None)
                elif 'content' in model:
                    flag=flag and (tup[key] in model['content'])
                else:
                    raise Exception("NotVaildCondition")
            if flag:
                current.extend(v['type']) #增加此处设置的标志位
                self.setflag_act(v, tup)
                
        return current
    
    def getrswithrule(self,tup,flags):
        rules=self.userknowledge["heuristic_rule"]
        if tup['ip'] not in self.hostflags:
            return
        hostflag=self.hostflags[tup['ip']]
        for name,conditionlist in rules.items():
            status=True
            msg="Have a attack in %s"
            for condition in conditionlist:
                key=condition['key']
                if key not in ['condition','msg']:
                    status=status and (key in flags)
                if not status:break
                for k,v in condition.items():
                    if k=='key':
                        pass
                    elif k=='minlen':
                        status=status and key in hostflag and (len(hostflag[key]) >= v)
                    elif k=='maxlen':
                        status=status and key in hostflag and (len(hostflag[key]) <= v)
                        
                    elif k=='tailhead<=':
                        status=status and key in hostflag and (hostflag[key][-1]['time']-hostflag[key][0]['time'] <= v)
                    elif k=='tailhead>=':
                        status=status and key in hostflag and (hostflag[key][-1]['time']-hostflag[key][0]['time'] >= v)                    
                    elif k=='tailhead==':
                        status=status and key in hostflag and (hostflag[key][-1]['time']-hostflag[key][0]['time'] == v)      
                    
                    elif k=='timedf<=':
                        status =status and v[0] in hostflag and v[1] in hostflag and (hostflag[v[0]]-hostflag[v[1]] <= v[2])
                    elif k=='timedf>=':
                        status =status and v[0] in hostflag and v[1] in hostflag and (hostflag[v[0]]-hostflag[v[1]] >= v[2])                        
                    elif k=='timedf==':
                        status =status and v[0] in hostflag and v[1] in hostflag and (hostflag[v[0]]-hostflag[v[1]] == v[2])    
                    
                    elif k=='message':
                        if v[0]=='$':   
                            if v[1:] in self.lang.objmap:
                                msg=self.lang.objmap[v[1:]] #从语言文件中获取输出
                        else:
                            msg=v

                    if not status:break
   
            if status:
                #匹配到一条规则，告警
                alg="heurist_%s" %name
                info=(msg %tup['ip'])
                info="[%s] %s" %(alg,info)
                self.log.warn("[Alert] %s " %(info))
                ac=alert(self.conf)
                ac.setHost(tup['ip'])
                ac.setMessagetp(tup['time'])
                ac.setUser(tup['user'])
                ac.setCmd(tup['cmd']) #设置cmd信息
                ac.setSrc(tup['src']) #设置src信息
                reason = f"{tup['ip']}在时间{str(ac.getAlertTimestamp())}触发命令{tup['cmd']}操作文件{tup['src']}"
                ac.setReason(reason) #设置reason信息
                ac.delPolicyId() #删除policyId信息
                ac.setDst(tup['dst']) #设置dst信息
                # ac.setAlertmsg(info)
                ac.setAlertmsg(reason)
                return (alg,ac.getAlert()) #返回一个告警
