#coding=utf8
import time
import re
import traceback
#取k=v中的v
def getValue(kv):
    r=kv.split('=')
    if len(r)==2:
        return r[1]
    return None

#转化成时间戳
def Froms2ts(date,tm,ms):
    return time.mktime(time.strptime(date+" "+tm,'%Y-%m-%d %H:%M:%S'))+(float(ms)/1000)

#获取小时数
def GetHour(time):
    return int(time.split(':')[0])

def list2dict(listdt):
    d=dict()
    for l in listdt:
        d[l[0]]=l[1]
    return d

def getblock(hour,unit=1):
    #unit [1,2,4,6,12,24]
    #return hour/(24/unit)
    return int(hour/(24/unit))

def chain2name(chains):
    i=1
    for u,chain in chains.items():
        for l,kv in chain[0].items():
            for k,v in kv.items():
                chain[0][l][k]="%s_%d_%d_%d" %(u,l,v,i)
                chain[1].append(chain[0][l][k])
                i+=1
            i=1
        chain[1].sort()
    return chains

########################################################################  
def linkstats(seq,ll):
    rs={}   
    seq=list(seq)
    lenght=len(seq)
    for i in range(lenght):
        end=i+ll
        if end==lenght:
            break
        current=','.join(seq[i:end])
        if current in rs:
            rs[current]+=1
        else:
            rs[current]=1
    return rs
    
def findlink(links,key):
    s=0
    for k,v in links.items():
        if key in k:
            s+=v
    return s
    
          
def GetAllStats(dlist,maxlen): 
    linkll=list(range(maxlen,1,-1)) #定义统计最长链长度为
    rslist=[]
    for i in linkll:
        rs=linkstats(dlist,i) #生成指定长度事件链集合
        rslist.append(rs)
    return rslist

def filterShort(rss,fre):
    link={}
    lenght=len(rss)
    for i in range(lenght):
        rs=rss[i]
        link[lenght-i+1]={}
        for k,v in rs.items():
            if i==0 and v>=fre[0]:
                link[i][k]=v
            elif i>0 and v>=fre[i]:
                f=findlink(link[lenght-i+2],k) #获取在长链中已经包含当前链的个数
                if v-f>=fre[i]:
                    link[lenght-i+1][k]=v
    return link

def GetCmdSet(dlist):
    cmdset=[]
    seq=list(dlist)
    for cmd in seq:
        if cmd in cmdset:
            pass
        else:
            cmdset.append(cmd)
    return cmdset


def Getlink(dlist,user):
    #设置链确定阀值
    ifre=[0.0004,0.0008,0.0032,0.005,0.01]
    fre=[]
    mlen=len(ifre)
    for i in ifre:
        f=int(i*len(dlist))
        if f<2:
            f=2
        fre.append(f)
    #长度为2的链至少5个
    if fre[-1]==2:
        fre[-1]==5
    cmdset=GetCmdSet(dlist)
    rss=GetAllStats(dlist,5)
    link=filterShort(rss,fre)
    return link,cmdset


#=====================================================
'''
unsigned int BKDRHash(char *str)
{
    unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
    unsigned int hash = 0;
 
    while (*str)
    {
        hash = hash * seed + (*str++);
    }
 
    return (hash & 0x7FFFFFFF);
}
'''
def BKDRhash(string):
    bkdr=0 
    for i in string:
        bkdr=bkdr*131+ord(i)
    return hex((bkdr & 0x7FFFFFFF))[2:] #把字符串通过bkrd哈希最终化成短字符串，后续作为dict的key

from functools import cmp_to_key
def dictcmp2(x,y):
    #定义对数据组进行排序的比较函数
    if x['time']>y['time']:return 1
    elif x['time']<y['time']:return -1
    return 0
dictcmp = cmp_to_key(dictcmp2)

#python3    
def cmp(x,y):
    return x-y
cmp = cmp_to_key(cmp)

#一个自动排序的list
class sortlist(object):
    def __init__(self,imax=0,fcmp=cmp):
        self.data=list()
        self.fcmp=fcmp
        self.imax=imax
        
    def  get(self,index):
        return self.data[index]
    
    def __len__(self):
        return len(self.data)
    
    def __str__(self):
        return str(self.data)
    
    def __getitem__(self,i):
        return self.data[i]
    
    
    def append(self,d):
        #根据配置指定排序函数
        self.data.append(d)
        self.data = sorted(self.data,key=self.fcmp) #python3,key,sorted
        if self.imax>0 and len(self.data)> self.imax:
            self.data.pop(0)
            
    def pop(self,index):
        return self.data.pop(index)
    
#恶意检测类,基于定义的可配置知识进行危险标识
class malware(object):
    def __init__(self,userknowlog,log):
        self.malflag={}
        self.userknowlog=userknowlog
        self.log=log
    
    def setflagwithrs(self,tup,knowdata):
        #设置更灵活的标识
        if 'type' in knowdata:
            keys=knowdata['type']
        else:
            keys=[tup['cmd']]
        for k in keys:
            self.malflag[tup['user']][k]={'tp':tup['time'],'vaild':60*knowdata['flag'],'args':tup['src']}
        
    def checkpathwithknowledge_act(self,tup,know):
        for name,kv in know.items():
            if len(tup['src'])>= kv['min']:
                if 'content' in kv and (tup['src'] in kv['content']):
                    self.setflagwithrs(tup, kv)
                    return True
                if 'ree' in kv and kv['ree'].match(tup['src']):
                    self.setflagwithrs(tup, kv)
                    return True
        return False
    
    def checkpathwithknowledge(self,tup):
        if self.checkpathwithknowledge_act(tup,self.userknowlog['sys_sensitivepath']):
            return True
        if self.checkpathwithknowledge_act(tup,self.userknowlog['user_sensitivepath']):
            return True
        return False
    
    def checkcmdwithknowledge_act(self,tup,know):
        if tup['cmd'] not in know:
            return False
        alist=tup['src'].split('+')
        cellknow=know[tup['cmd']]
        if "exclude" in cellknow:
            if 'content' in cellknow['exclude']:
                for i in alist:
                    if i in cellknow['exclude']['content']:return False
            elif 'ree' in cellknow['exclude']:
                for i in alist:
                    if re.match(cellknow['exclude']['ree'],i):return False
                
        if 'content' in cellknow:
            for i in alist:
                if i in cellknow['content']:
                    self.setflagwithrs(tup, cellknow)
                    return True
        elif 'ree' in cellknow:
            for i in alist:
                if cellknow['ree'].match(i):
                    self.setflagwithrs(tup, cellknow)
                    return True
        else:
            self.setflagwithrs(tup, cellknow)
            return True
        
    def checkcmdwithknowledge(self,tup):
        if self.checkcmdwithknowledge_act(tup,self.userknowlog['sys_sensitivecmd']):
            return True
        if self.checkcmdwithknowledge_act(tup,self.userknowlog['user_sensitivecmd']):
            return True
    
        return False
    def setflag(self,tup):
        try:
            self.malflag.setdefault(tup['user'],{})
            userflag=self.malflag[tup['user']]
            if tup['cmd']=='fwrite':
                isflag=self.checkpathwithknowledge(tup)
            else:
                isflag=self.checkcmdwithknowledge(tup)
                
            if isflag: #当有一个敏感标志被设置时
                self.log.info("[SetFlag] %s" %str(tup))
        except Exception as e:
            self.log.error("[ERROR] setflag error with %s" %repr(e))
            self.log.error('[traceback] %s' %traceback.format_exc())

    #根据策略返回是否风险状态
    def getflag(self,user,newtp):
        try:
            userflag=self.malflag[user]
            self.log.debug(f"userflag:{userflag}\n{newtp}")
            for k,v in userflag.items():
                if v['vaild']>0 and abs(newtp-v['tp'])<=v['vaild']:
                    self.log.warn("[MAL] have %s:%s malevolence behavior" %(k,str(v)))
                    v['vaild']=-1
                    return True
            for name,behavior in self.userknowlog['behavior_sensitive'].items():
                rs=True
                for k,v in behavior.items():
                    rs=rs and k in userflag and userflag[k]['vaild']>=0 and abs(newtp-userflag[k]['tp'])<=v*60
                    if not rs:
                        continue
                if rs:
                    for i in list(behavior.keys()):
                        self.log.warn("[MAL] have behavior %s:%s malevolence behavior" %(i,str(userflag[i])))
                        #设置为无效标识
                        userflag[i]['vaild']=-1
                    return True
            return False
     
        except Exception as e:
            self.log.error("[ERROR] get flag with %s" %repr(e))
            self.log.error('[traceback] %s' %traceback.format_exc())
            return False
#====================
def parseKnowledge(knowledge):
  for tp,kvv in knowledge.items():
    for name,kv in kvv.items():
      if 'ree' in kv:
        kv['ree']=re.compile(kv['ree'])
        
def israndom(s,rees):
    for name,kv in rees.items():
        if len(s)>=kv['min'] and kv['ree'].match(s):
            return kv['dst']
    return None

def parsewrpath(ps,conf,knowledge):
    #对长路径中包含随机字符串的路径进行切割，保留随机子串之前的路径
    plist=ps.split('/')
    i=-1
    rs=[israndom(x,knowledge['randompath']) for x in plist]
    rsindex=[x!=None for x in rs]
    try:
        i=rsindex.index(True)
        plist[i]=rs[i] #基于指定配置替换随机路径
    except Exception:
        pass
    if len(plist)<=conf['parameter']['pathrank']:
        rps='/'.join(plist)
    elif i>=0:
        rps='/'.join(plist[:i])
    else:
        rps='/'.join(plist[:-1])
    return rps

def parsershell(inputs,knowledge):
    plist=inputs.split('/')
    if len(plist)<2:
        return inputs
    rs=[israndom(x,knowledge['randomshell']) for x in plist]
    rsindex=[x!=None for x in rs]
    try:
        i=rsindex.index(True)
        plist[i]=rs[i] #基于指定配置替换随机路径
    except Exception:
        pass
    return '/'.join(plist)
