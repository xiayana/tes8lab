#coding=utf8
from .base import *
import math
import numpy as np
import time
import sys

from lib.lib_event_similarity import *
from lib.alertbase import alert

def islinuxp(s):
    if s[0]=='/':
        return
    return False


#   混合算法类
class alg_detection(base):
    """
    混合算法检测
    """    
    def __init__(self,conf,lang,log=None):
        base.__init__(self)
        self.log=log
        self.name="core"
        self.conf=conf
        self.lang=lang
        self.parameter = conf['parameter']  #  需要调的参数
        self.simalg=globals()[self.parameter['simalg']] #
        
    def path_split(self,s):
        #if islinuxp(s):
        plist=s.split('/')
        #else:
        #plist=s.split('\\')
        return '/'.join(plist[:self.parameter['pathrank']])
    
    def inspect(self,tup,model,tb):
        #对待检测数据进行合法性校验，根据返回判断是否放入检测窗口
        #model 包含一个或多个同用户，算法的模型数据
        return True

    def getblock(self,tp,part):
        tstruct=time.localtime(tp)
        time_cur = tstruct.tm_hour #   从时间戳中取出小时
        self.log.debug(str(tstruct))
        #若时间在小时的临界点上，尝试取相邻时区模型
        if tstruct.tm_min>=50:
            flag=1
        elif tstruct.tm_min <=10:
            flag=-1
        else:
            flag=0
        time_part1 = self.transform_time(time_cur,part)  #  小时转时间划分区域
        time_cur+=flag
        if time_cur>23:time_cur=0
        elif time_cur<0:time_cur=23 
        time_part2 = self.transform_time(time_cur,part)  #  计算替补数据索引
        return (str(time_part1),str(time_part2)),tstruct.tm_mday
    
    def detection(self, user, windowlist, model,userdf):
        """
        此处自身随意实现检测评估算法
        """
        #存储异常标识
        execflag={}
        cmd = []
        model_data = model['data']  #  取出模型中的数据
        #time_stack=[]  # 存放窗口里的小时的数字
        time_sec = []  # 存放时间戳，为了计算窗口命令持续时间
        #part = algconf.conf['parameter']['part']
        cmd_list = []   #   保存命令列表
        cmd_intev = []  #  命令之间的时间间隔，以秒为单位
        res = []  #告警提示消息结果
        parameter = self.parameter  #  需要调的参数
        #  windowlist的命令数
        length = len(windowlist)
        #   path-cmd频数测试
        #file_cmd_frequency = model_data['file_cmd_frequency']
        #   命令集合
        cmd_set = model_data['cmdset']
        #   取出窗口数据时可以边进行路径命令检测
        
        for item in windowlist:
            time_sec.append(item['time'])
            if self.parameter['core_comm']:
                #判断cmd是否在命令集当中********************
                if item['cmd'] not in cmd_set:
                    res.append('Cmd not exist abnormal with %s;' %item['cmd'])    
            #time_stack.append(time_cur)
            cmd_list.append(item['cmd'])
        
        #取出相应时间块的模型数据，包括相应的命令转移矩阵、概率分布、词袋概率分布、时间间隔统计量
        block1_2,mday=self.getblock(windowlist[0]['time'],parameter['part'])
        self.log.debug(self.lang.detection_debug_mmblock %(block1_2[0],block1_2[1]))
        if block1_2[0] not in model_data['syscall']:
            if block1_2[1] not in model_data['syscall']:
                if not self.conf['system']['notblockalert']: #对空模型数据进行立即返回
                    return
                res.append(self.lang.detection_block_notexist %(user,block1_2[0],block1_2[1])) # 若模型中没有这个区间时间，返回异常
                return '\n'.join(res)  #不存在此时间区模型，直接返回
            else:
                blockindex=block1_2[1]
        else:
            blockindex=block1_2[0]
        
        self.log.info("detection is start with %s in %s block" %(self.name,str(blockindex)))
        try:
            malcov = model_data['malcov'][blockindex]  #取出马尔科夫相关数据（转移矩阵，扩散系数）transform_matrix,diffuse
            compute_static_intev = model_data['compute_static_intev'][blockindex] # 取出命令时间间隔的统计量
            frequency = model_data['frequency'][blockindex]   #   取出命令概率分布
            compute_ngram = model_data['compute_ngram'][blockindex]   #   取出词袋概率分布
        except Exception as e:
            self.log.debug(f"core_alg detection error is {e}")
            return None
        # = model_data['static'][blockindex] #    取出每天时间块内命令的均值和方差 
        #数据调整功能一律转移到detection主模块的初始化函数中
        #if static[1]==0:static[1]=int(static[0]*0.3) #当方差为0，重置方差为（0.01*期望）
        #if static[1]<self.parameter['ministd']:static[1]=self.parameter['ministd'] #当方差<ministd，,设置
        '''
        #计算平均速度，基于分片静态统计评估异常
        #若静态统计超过对应均值的3sigma，则认为异常
        try:
            staticstats="%d mean:%d std:%d" %(userdf[mday][int(blockindex)]['sum'],static[0],static[1])
            self.log.info("Cmd static stats:%s;" %staticstats)
            if userdf[mday][int(blockindex)]['sum']-static[0] > 3*static[1]:
                res += "Cmd static stats abnormal:%s;" %staticstats
        except KeyError:
            pass
        except Exception,e:
            self.log.error("[ERROR] %s" %repr(e))
        '''
        #计算间差，判定异常
        #compute_static_intev
        #关于时间间隔的异常判定，后期再考虑
        '''
        time_intev = []  #  命令时间间隔
        for i in range(len(time_sec)-1):
            cur_intev = time_sec[i+1]-time_sec[i]
            if cur_intev>=0.02 and cur_intev<=30:
                time_intev.append(cur_intev)
        p=np.asarray(time_intev,np.float)
        intev_mean=p.mean()
        if abs(intev_mean-compute_static_intev[0])> 2*compute_static_intev[1]:
            res += "Cmd intev abnormal:%f mean:%f std:%f;" %(intev_mean,compute_static_intev[0],compute_static_intev[1])
        '''
        #===============================================================
        #计算markov状态转移的对数概率

        cur_prob = 0
        min_prob = 0
        transform_matrix=malcov['transform_matrix']
        diffuse=0
        sort_prob,sum_min_prob = self.sort_transform_matrix(transform_matrix)
        #基于训练数据生成两两命令之间状态转移的概率，计算当前检测窗口中事件序列出现的概率，即连续事件状态转移概率相乘
        for i in range(len(cmd_list)-1):
            #计算相邻事件转移概率累计乘机，此处取对数相加
            #   若cmd不存在转移矩阵中，用最小概率平滑
            if cmd_list[i] not in list(transform_matrix.keys()):
                cur_prob += np.log(sum_min_prob)
                diffuse +=sum_min_prob
            elif cmd_list[i+1] not in list(transform_matrix[cmd_list[i]].keys()):
                cur_prob += np.log(sort_prob[cmd_list[i]][0])
                diffuse +=sort_prob[cmd_list[i]][0]
            else : 
                cur_prob += np.log(transform_matrix[cmd_list[i]][cmd_list[i+1]]) 
                diffuse += transform_matrix[cmd_list[i]][cmd_list[i+1]]
                
            #  低概率截止点
            if cmd_list[i] in sort_prob:
                low_prob_node = int(self.parameter['malcov_transform']*len(sort_prob[cmd_list[i]])) 
                min_prob += np.log(sort_prob[cmd_list[i]][low_prob_node])
            else: min_prob += np.log(sum_min_prob)
            # print(f"diffuse:{diffuse}")
        #   低概率判断    马尔科夫链异常判定暂不启用
        #if cur_prob<=min_prob: 
        #    res += 'Markov low prob abnormal;'

        #===================================================================
        
        if self.parameter['core_exec'] and len(windowlist)>=self.conf['window']['minlen']: #当检测窗口数据量过小,不进行异常系数计算
            #扩散系数异常检测
            self.log.debug(f"diffuse:{diffuse},len(cmd_list):{len(cmd_list)},abs:{abs(diffuse-malcov['diffuse'])}"
                           f"")
            diffuse/=len(cmd_list) #扩散系数
            self.log.info(self.lang.detection_log_diff %(diffuse,malcov['diffuse']))
            diffvalue=abs(diffuse-malcov['diffuse'])
  
            #  计算词袋的字典概率分布
            ngram_frequency = self.cal_ngram_frequency_dict(cmd_list)
            self.log.debug(f"ngram_frequency:{ngram_frequency}")
            #  计算当前词袋概率与模型词袋概率的相似度
            simularity_ngram = self.cosine_dic(ngram_frequency,compute_ngram)
      
            #**计算概率分布并进行异常预测
            window_data_frequency = self.cal_frequency_dict(cmd_list)
            self.log.debug(f"window_data_frequency:{window_data_frequency}")
            #   计算两个概率分布词典的相似度
            simularity_dic = self.cosine_dic(window_data_frequency,frequency)
            clusters = None
            if 'clusterpoints' in model_data:
                try:
                    clusters= model_data['clusterpoints'][blockindex] #取出聚类中心点数据
                except Exception as e:
                    pass
            #计算最大通用聚类模式相似度
            if clusters != None:
                simularity_cluster=self.cal_cluster_except(clusters, windowlist,self.simalg)
            else:
                simularity_cluster = 0
            #simularity_cluster dic ng 基于以下三个计算出的相似度，判定是否异常
            #计算综合异常评判系数
            normalsim=max(simularity_dic,simularity_ngram,simularity_cluster)
            
            execsim=self.parameter['frequency_weight']*simularity_dic+\
                self.parameter['ngram_weight']*simularity_ngram+\
                self.parameter['clster_weight']*simularity_cluster 
                
            simlog=self.lang.detection_log_sim %(simularity_dic,simularity_ngram,simularity_cluster,execsim)
            self.log.info(f"扩散系数:{diffvalue}")
            self.log.info(f"计算综合异常评判系数:{normalsim}")
            self.log.info(f"计算权重异常评判系数:{execsim}")
            self.log.info(simlog)
            #要求扩散系数>最小值 且 最大相似度<正常阈值 且 综合判断系数<异常阈值 
            if diffvalue < self.parameter['minidiff'] and normalsim<self.parameter['threshold_normal'] \
                    and execsim<self.parameter['threshold_exec']:
                res.append(self.lang.detection_user_expsim %(user,''))#simlog))
                execflag['sim']=True

            #扩散系数>参数定义，且 聚类行为相似度<0.9 时，返回扩散系数异常
            if (malcov['diffuse'] >0 and diffvalue > self.parameter['execdiff'] and simularity_cluster<0.9):  
                res.append(self.lang.detection_diff_exp %(user,diffuse,malcov['diffuse']))
                if 'sim' not in execflag: #扩散系数异常但行为检测不异常时，添加行为检测信息输出
                    res.append(self.lang.detection_user_status %(user,simlog))
        #===============================================================        
        if len(res)>0:
            res='\n'.join(res)
            return res
        return None
    
    #   计算概率分布词典
    def cal_frequency_dict(self,cmd_list):
        res = {}
        #  累计与归一化共同计算
        length = len(cmd_list)
        for cmd in cmd_list:
            res.setdefault(cmd,0)
            res[cmd] += 1.0/length
        return res
    #   计算两个归一化词典概率的余弦相似度    
    def cosine_dic(self,dic1,dic2):
        #增加重合度系数计算过程
        psum = 0.0
        dic_sum1 = 0.0
        dic_sum2 = 0.0
        interset = 0.0 #交集计数
        for key in list(dic1.keys()):
            if key in list(dic2.keys()): 
                interset += 1
                psum += dic1[key] * dic2[key]
                dic_sum1 += dic1[key]**2
                dic_sum2 += dic2[key]**2
        unionset=len(dic1)+len(dic2)-interset #并集计数
        
        if interset<=0:
            return 0
        try:
            return (interset/unionset)*(psum / (np.sqrt(dic_sum1)*np.sqrt(dic_sum2))) #惩罚系数×余弦相似度
        except Exception:
            #分母防止出现0
            return 0 
    #   小时划分到相应的时间片    
    def transform_time(self,s,part):
        div = 24 / int(part)   
        #return int(s) / div     #python3
        return int(int(s) /div)
    
    #   概率转移矩阵对每个命令的转移概率进行排序    
    def sort_transform_matrix(self,transform_matrix):
        sort_prob = {}
        sum_min_prob = 1.0  #  当某个命令不存在时，用最小命令进行平滑
        for key1 in list(transform_matrix.keys()):
            sort_prob.setdefault(key1,[])
            for key2 in list(transform_matrix[key1].keys()):
                sort_prob[key1].append(transform_matrix[key1][key2])
            sort_prob[key1].sort()
            if sum_min_prob > sort_prob[key1][0] :
                sum_min_prob = sort_prob[key1][0]
        return sort_prob,sum_min_prob
    #   计算ngram的词典概率分布    
    def cal_ngram_frequency_dict(self,cmd_list):
        res = {}
        #  累计与归一化共同计算
        length = len(cmd_list)
        for i in range(len(cmd_list)-1):
            cur_ngram = cmd_list[i]+cmd_list[i+1]
            res.setdefault(cur_ngram,0)
            res[cur_ngram] += 1.0/(length-1)
        return res

    def calcMaxProbWin(self,wins):
        #判定是否是高重复窗口，根据信息熵思路，当其中某一占比>0.9时，信息熵较低
        #返回符合条件的最高概率key
        d=dict()
        l=float(len(wins))
        for item in wins:
            d.setdefault(item, 0)
            d[item] += 1
        mprob=0
        index=None 
        for k in d:
            d[k]/=l
            if d[k]>mprob:
                mprob=d[k]
                index=k
        if mprob>=0.9:
            return index
    
    #计算实时相似度
    def cal_cluster_except(self,clusters,winlist,simalg):
        winvect=[x['cmd'] for x in winlist] #向量化
        maxkey=self.calcMaxProbWin(winvect)# 计算符合条件的最高概率key
        simlist=[]
        for cluster in clusters:
            #当cluster长度为1，意味着训练数据中存在100%命令执行模式
            if maxkey and len(cluster)==1:
                if cluster[0]==maxkey:
                    self.log.debug(f"maxkey:{maxkey}")
                    sim=0.9
                else:
                    sim=0
            else:
                sim=simalg(cluster, winvect)

            simlist.append(sim)
        #-----------------------
        if not len(simlist): 
            #当前没有一个有效性的聚类点，对此类情况统一设置相似度0.3
            simlist.append(0.3)
        distc=np.array(simlist)
        if self.log:
            self.log.debug(self.lang.detection_debug_sim_maxmin %(distc.min(),distc.max()))
        return distc.max()


    