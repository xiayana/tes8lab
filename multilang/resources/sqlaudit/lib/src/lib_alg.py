#coding=utf8
import time
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
    return hour/(24/unit)

def chain2name(chains):
    i=1
    for u,chain in chains.iteritems():
        for l,kv in chain[0].iteritems():
            for k,v in kv.iteritems():
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
        if rs.has_key(current):
            rs[current]+=1
        else:
            rs[current]=1
    return rs
    
def findlink(links,key):
    s=0
    for k,v in links.iteritems():
        if key in k:
            s+=v
    return s
    
          
def GetAllStats(dlist,maxlen): 
    linkll=range(maxlen,1,-1) #定义统计最长链长度为
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
        for k,v in rs.iteritems():
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