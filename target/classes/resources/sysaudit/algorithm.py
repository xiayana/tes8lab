#coding=utf8
import importlib
import traceback
import lib.lib_alg as libalg 

class dispatch:
    def __init__(self,conf,models,lang,log):
        self.algclass=dict() #在这添加算法，并在后面实现相关class
        self.log=log
        self.models=models
        self.conf=conf
        self.lang=lang
        self.loadeletetionalg()
        # self.vote=[[3,5,7,100],[1,2,3,4]] #定义的正反投票比
        self.vote=eval(self.conf['vote']['vote'])
        self.userflag={}
        self.window = {} #存储待检测队列
        
    def loadeletetionalg(self):
        for k,v in self.conf['deleteclass'].items():
            md=importlib.import_module(v)
            self.algclass[k]=md.alg_detection(self.conf,self.lang,self.log)
            
    def IsDetection(self,user,k):
        lenght=len(self.window[user][k])
        self.log.debug(f"任务个数统计为：{lenght}")
        if lenght>=self.conf['window']['maxlen']: #或者在时间窗口内事件数超过maxlen个，直接开始异常检测
            self.log.debug("send window with event window")
            self.userflag[user][k]['wintype']=1 #maxlen 类型触发
            return True
        #去掉时间窗口
        elif lenght >= (self.conf['window']['minlen']/2) and self.conf['window']['issec'] and (self.window[user][k][-1]['time']-self.window[user][k][-2]['time']>=self.conf['window']['sec']): #当开启时间窗口 且，消息队列符合时间要求时(相邻有效用户操作间隔一定时间）
            self.log.debug("send window with time window")
            self.userflag[user][k]['wintype']=2 #sec win 类型触发
            return True
        return False
    
    #调试状态下，打印检测窗口
    def printwindowlist(self,user,winlist):
        #if not self.log.isEnabledFor("DEBUG"):
        #    return
        self.log.info("%s %d sum" %(user,len(winlist)))

    def pushtup(self,user,tup,tb):
        self.log.debug(str(tup)) 
        self.tb = tb
        active=[]
        for k in list(self.models[user].keys()):
            if not self.algclass[k].inspect(tup,self.models[user][k],tb):
                continue #检查未通过
            
            self.window.setdefault(user,{})
            self.window[user].setdefault(k,[])
            self.userflag.setdefault(user,{})
            self.userflag[user].setdefault(k,{})
           
            self.window[user][k].append(tup)
            #self.window[user][k].sort(cmp=libalg.dictcmp) #排序，确保消息队列
            self.window[user][k] = sorted(self.window[user][k],key=libalg.dictcmp) #debug,python3
            #存储当前用户最新的消息时间戳
            self.userflag[user][k]['newest']=self.window[user][k][-1]['time']
            
            if self.IsDetection(user,k): #未触发检测，添加数据队列后直接返回
                self.printwindowlist(user,self.window[user][k])
                active.append(k)
        return active
        
        
    def start(self,user,active,userdf):
        rss=[]
        #rss.append(list(usermodel))
        usermodel=self.models[user]
        for name in active:
            alg=self.algclass[name]
            windowlist=self.window[user][name]
            #if usermodel.has_key(alg.name):
            cellrs=[]
            for cellmodel in usermodel[name]:
                self.log.debug("Detection %s with %s on %d windows" %(user,name,len(windowlist)))
                try:
                    rs=alg.detection(user,windowlist,cellmodel,userdf)
                except KeyError as e:
                    self.log.warn("[Warn] %s in %s" %(repr(e),alg.name))
                    self.log.error(traceback.format_exc())
                    continue
                except Exception as e:
                    self.log.error("[Error] %s in %s" %(repr(e),alg.name))
                    self.log.error(traceback.format_exc())
                    continue
                if rs:
                    self.log.debug(f"Detection alert context num{len(rs)},content:{rs}\n")
                    cellrs.append(rs)
                else:
                    cellrs.append("Normal") #未报警

            #重构告警信息
            import time
            starttime = time.time()
            # 1.  构造告警时间
            div = 4
            alarmmodel = '{}点到{}点'
            if self.tb == 0:
                alarmtime = alarmmodel.format(1, 4)
            else:
                starttime = int(self.tb) * div
                endtime = starttime + div
                alarmtime = alarmmodel.format(starttime, endtime)
            self.log.debug(f"告警的时间是：{alarmtime}")
            # 2. 当前时间分区下,实时数据对应的数据集
            from collections import Counter
            current_cmds_r = Counter([x['cmd'] for x in windowlist])  # .most_common(5)
            # current_cmds_r
            # 3. 当前时间分区下获取当前模型数据
            clusters = []
            model_data = cellmodel['data']
            label = 0
            if 'clusterpoints' in model_data:
                try:
                    clusters= model_data['clusterpoints'][self.tb] #取出聚类中心点数据
                except Exception as e:
                    self.log.debug(f"出现错误，错误原因是：{e}")
                else:
                    label = 1
            alarmmessage_dl = ""
            if 'dlcenters' in model_data:
                try:
                    result = sorted(list(zip(dict(current_cmds_r).keys(),dict(current_cmds_r).values())),key=lambda x: x[1],reverse=True)[0]
                except Exception as e:
                    self.log.debug(f"出现错误，错误原因是：{e}")
                else:
                    label = 2
                    alarmmessage_dl = "窗口大小:{}个， 其中{}命令出现频次{}个".format(len(windowlist), result[0], result[1])

            # 4. 构造告警数据
            alarmmessage_core = ""
            if label==1:
                freq_cmds = []  # 多出的命令及频次保存到freq_cmds列表中
                diff_cmds = []  # 不同的命令集汇总到diff_cmds列表中
                for c_n in clusters:
                    index_cmds_r = Counter(c_n)  # .most_common(5) #模型表中对应分区下的一个数集统计
                    index_set = set(dict(index_cmds_r).keys())  # 过滤出对应的命令集合
                    current_set = set(dict(current_cmds_r).keys())  # 实时数据集中对应的命令集合
                    current_diff = current_set.difference(index_set)  # 查找实时数据集中不同于模型表中的命令集合
                    diff_cmds.extend(list(current_diff))  # 不同的命令集汇总到diff_cmds列表中

                    current_union = current_set.intersection(index_set)  # 统计模型表中对应分区下一个命令集合实时数据命令集取交集
                    freq_cmds_index = []
                    for k in current_union:
                        if dict(current_cmds_r)[k] > dict(index_cmds_r)[k]:  # 统计交集中，命令个数大于模型表中命令集对应命令的频次的所有命令
                            freq_cmds_index.append(
                                [k, dict(current_cmds_r)[k] - dict(index_cmds_r)[k]])  # 将多出的命令及频次保存到freq_cmds列表中
                    freq_cmds.extend(freq_cmds_index)
                freq_cmds.sort(key=lambda x: x[1], reverse=True)  # 对多出的命令频次统计的数据排序，按照由大到小
                self.log.debug(f'diff_cmds：{diff_cmds}')
                self.log.debug(f'freq_cmds：{freq_cmds}')

                # 5. 构造告警格式
                if diff_cmds:
                    alarm_diff_str = 'top3对比历史中未出现过命令信息有：{}'.format(tuple(set(diff_cmds)))
                    # alarm_diff_str
                else:
                    alarm_diff_str = ''
                if list(set([x[0] for x in freq_cmds])):
                    alarm_freq_str = 'top3对比历史中命令出现频次差异信息有：'
                    for i in list(set([x[0] for x in freq_cmds]))[:3]:
                        freq_cmds_str = '命令：{}，相比历史使用频次增加{}个'
                        alarm_freq_str += freq_cmds_str.format(i, dict(freq_cmds)[i])
                else:
                    alarm_freq_str = ''
                alarmmessage_core = '用户在{}出现集合异常值，具体有：{}；{}'.format(alarmtime, alarm_diff_str, alarm_freq_str)
                self.log.debug(alarmmessage_core)
                self.log.debug(f"重构告警格式耗时：{time.time() - starttime}")


            #添加告警信息到rss
            if self.isexcept(cellrs):

                if alarmmessage_core!="":
                    rss.append((name,'\n'.join(cellrs),alarmmessage_core))
                elif alarmmessage_dl!="":
                    rss.append((name, '\n'.join(cellrs), alarmmessage_dl))
                else:
                    rss.append((name,'\n'.join(cellrs),",".join([x['cmd'] for x in windowlist])))
            else:
                self.log.debug(f"无添加告警信息")
                
            #清理对应用户算法的检测队列
            if self.userflag[user][name]['wintype']==1:
                self.window[user][name]=self.window[user][name][int(len(windowlist)/self.conf['window']['divisor']):] #待检测事件队列更新,删除队列中的前1/divisor事件
            elif self.userflag[user][name]['wintype']==2: #时间窗口触发
                self.window[user][name]=self.window[user][name][-1:] #更新队列，只保留历史队列中最后一项新数据
            

        #返回的报警数据结构，[(alg.name,all alertmsg),...]
        return rss
    
    def isexcept(self,cellrs):
        #当投票决定是异常时，返回真，否则为假
        #目前对于投票机制没有很好的设想
        #暂时使用默认的数据[[3,5,7],[1,2,3]]，即当模型数<=3时，正常数>=1为正常，以此类推
        total=len(cellrs)
        if total<1:
            return False
        normal=cellrs.count("Normal")#vote:[[3,5,7,100],[1,2,3,4]]
        self.log.debug(f"默认的投票决策异常数据是：{self.vote},类型：{type(self.vote)}\ntotal:{total},normal:{normal}")
        for i in range(len(self.vote[0])):
            if total<=self.vote[0][i] and normal>=self.vote[1][i]: #使用的模型总数<=指定值 且 正常返回数量>=指定值 时，函数返回假，即对此次综合判定为正常
                return False
        return True    
        


        
