#coding=utf8
from sklearn import preprocessing
from base import *
import math
import numpy as np
from scipy import linalg
from scipy.stats import pearsonr
import time
import sys

from lib.lib_event_similarity import *

def islinuxp(s):
    if s[0]=='/':
        return
    return False


#   混合算法类
class alg_detection(base):
    """
    混合算法检测
    1.判定cmd，table是否出现在【cmdset】和【tableset】中
    2.判定用户连接ip是否正常
    3.基于实时传递的实时统计量和【cmdstatic】【tablestatic】判定异常
    4.基于fre和ng概率计算余弦相似度
    """    
    def __init__(self,conf,log=None):
        base.__init__(self)
        self.log=log
        self.name="user_alg"
        self.winsize=float(conf['window']['maxlen'])
        self.parameter = conf['parameter']  #  需要调的参数
        #self.simalg=globals()[self.parameter['simalg']] #
        
    def getblockmodel(self,tp,part,model):
        tstruct=time.localtime(tp)
        time_cur = tstruct.tm_hour #   从时间戳中取出小时
        #若时间在小时的临界点上，尝试取相邻时区模型
        if tstruct.tm_min>=50:
            flag=1
        elif tstruct.tm_min <=10:
            flag=-1
        else:
            flag=0
        time_part = self.transform_time(time_cur,part)  #  小时转时间划分区域
        if str(time_part) not in model['data'] :
            time_cur+=flag
            if time_cur>23:time_cur=0
            elif time_cur<0:time_cur=23 
            time_part = self.transform_time(time_cur,part)  #  小时转时间划分区域
            if str(time_part) not in model['data']:
                return None
        cal_data=model['data'][str(time_part)]
        return cal_data
    
    def detection(self, user, windowlist, model,userdf):
        """
        此处自身随意实现检测评估算法
        """
        model_data = model['data']  #  取出模型中的数据
        #part = algconf.conf['parameter']['part']
        cmd_list = []   #   保存命令列表
        res = ''  # 返回字符串，用于测试
        parameter = self.parameter  #  需要调的参数
        #  windowlist的命令数
        #length = len(windowlist)
        #   取出窗口数据时可以边进行路径命令检测
        
        
        cal_data=self.getblockmodel(windowlist[0]['time'],parameter['part'], model)
        if cal_data==None:
            res += 'Time Block Model not exist abnormal;' # 若模型中没有这个区间时间，返回异常
            at=self.getAlert(windowlist[0]['ip'], user, 'table_alg', res,res)
            return at  #不存在此时间区模型，直接返回
        
        for item in windowlist:
            cmd_list.append([item['time'],item['cmd'],item['table'],item['src']])
            if item['cmd'] not in cal_data['cmdset']:
                res += "Have ill cmd with %s in %s; " %(item['cmd'],user)
            if item['ip'] not in cal_data['common_ip']:
                res += "Have ill client ip with %s in %s; " %(item['ip'],user)
            if item['table']!='null' and (item['table'] not in cal_data['tableset']):
                res += "Have ill table with %s in %s; " %(item['table'],user)              
                
        cmd_list.sort()
        cmd_marix=np.asmatrix(cmd_list)
        del cmd_list
        static = cal_data['statistic'] #    取出时间块内命令和table的均值和方差 
        if static[1]==0:static[1]=max(5,int(static[0]*0.01)) #当方差为0，重置方差为（0.01*期望）
        if static[3]==0:static[3]=max(5,int(static[2]*0.01)) #当方差为0，重置方差为（0.01*期望）

        #计算平均速度，基于分片静态统计评估异常
        #若静态统计超过对应均值的3sigma，则认为异常
        if userdf['cmdsum']-static[0] > 3*static[1]:
            res += "Cmd static stats abnormal:%d mean:%d std:%d;" %(userdf['cmdsum'],static[0],static[1])

        if userdf['tablesum']-static[2] > 3*static[3]:
            res += "table static stats abnormal:%d mean:%d std:%d;" %(userdf['tablesum'],static[2],static[3])
            
        if len(windowlist)/self.winsize>0.15: #当检测窗口数据量过小,不进行异常系数计算
            #  计算词袋的字典概率分布
            cmdlist=cmd_marix[:,1].T.tolist()[0]
            tablelist=cmd_marix[:,2].T.tolist()[0]

            ngram_cmd_frequency = self.cal_ngram_frequency_dict(cmdlist)
            ngram_table_frequency = self.cal_ngram_frequency_dict(tablelist)
    
            #  计算当前词袋概率与模型词袋概率的相似度
            simularity_cmd_ngram = self.cosine_dic(ngram_cmd_frequency,cal_data['cmdng'])
            simularity_table_ngram = self.cosine_dic(ngram_table_frequency,cal_data['tableng'])
      
            #**计算概率分布并进行异常预测
            window_data_cmd_frequency = self.cal_frequency_dict(cmdlist)
            window_data_table_frequency = self.cal_frequency_dict(tablelist)
            #   计算两个概率分布词典的相似度
            simularity_dic_cmd = self.cosine_dic(window_data_cmd_frequency,cal_data['cmd_fre'])
            simularity_dic_table = self.cosine_dic(window_data_table_frequency,cal_data['table_fre'])
            
            #simularity_cluster dic ng 基于以下三个计算出的相似度，判定是否异常
            #计算综合异常评判系数
            execsim=self.parameter['frequency_cmd_weight']*simularity_dic_cmd+\
                self.parameter['frequency_table_weight']*simularity_dic_table+\
                self.parameter['ngram_cmd_weight']*simularity_cmd_ngram+\
                self.parameter['ngram_table_weight']*simularity_table_ngram
            simlog=u"CMD概率分布相似度 %f,CMD NG相似度 %f,Table概率分布相似度 %f,TableNG相似度 %f,综合异常评判系数 %f;" %(simularity_dic_cmd,\
                                                                                                                simularity_cmd_ngram,\
                                                                                                                simularity_dic_table,\
                                                                                                                simularity_table_ngram,\
                                                                                                                execsim)
            self.log.debug(simlog)
            if execsim<self.parameter['threshold_exec']:
                res += "User Behavior abnormal: %s" %simlog
        #===============================================================        
        if len(res)>0:
            at=self.getAlert(windowlist[0]['ip'], user, 'user_alg', res,res)      
            return at
        return None
    
        #获取一个告警结构
    def getAlert(self,host,user,algname,alertcontent,msg="None"):
        self.alert[0]['timestamp']=int(time.time()*1000)
        self.alert[0]['alertContext']['properties']['host']=host
        self.alert[0]['alertContext']['properties']['alertMessage']= alertcontent
        self.alert[0]['alertContext']['properties']['user']=user
        return (algname,self.alert,msg)
    
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
        if len(dic1)==0:return 0.5
        psum = 0.0
        dic_sum1 = 0.0
        dic_sum2 = 0.0
        interset = 0.0 #交集计数
        for key in dic1.keys():
            dic_sum1 += dic1[key]**2
            if key in dic2.keys(): 
                interset += 1
                psum += dic1[key] * dic2[key]
                dic_sum2 += dic2[key]**2
        #unionset=len(dic1)+len(dic2)-interset #并集计数
        #   分母防止出现0
        if dic_sum1==0: dic_sum1 = 1e-32
        if dic_sum2==0: dic_sum2 = 1e-32
        return (interset/len(dic1))*(psum / (np.sqrt(dic_sum1)*np.sqrt(dic_sum2))) #重合系数×余弦相似度
       

    
    #   小时划分到相应的时间片    
    def transform_time(self,s,part):
        div = 24 / int(part)
        return int(s) / div
    #   概率转移矩阵对每个命令的转移概率进行排序    
    def sort_transform_matrix(self,transform_matrix):
        sort_prob = {}
        sum_min_prob = 1.0  #  当某个命令不存在时，用最小命令进行平滑
        for key1 in transform_matrix.keys():
            sort_prob.setdefault(key1,[])
            for key2 in transform_matrix[key1].keys():
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
        unit=1.0/(length-1)
        for i in range(len(cmd_list)-1):
            cur_ngram = cmd_list[i]+cmd_list[i+1]
            res.setdefault(cur_ngram,0)
            res[cur_ngram] += unit
        return res
    
    def cal_cluster_except(self,clusters,winlist,simalg):
        if len(winlist)/float(len(clusters[0]))<0.25:
            return 0.5 #检测窗口数据过少，返回中间值判定
        winvect=map(lambda x:x['cmd'],winlist) #向量化
        simlist=[]
        for cluster in clusters:
            sim=simalg(cluster, winvect)
            if self.log:
                self.log.debug("vm:%d vt:%d 相似度：%f" %(len(cluster),len(winvect),sim))
            simlist.append(sim)
        return np.array(simlist).max()
        
    