#coding=utf8
import numpy as np
import scipy.spatial as sp

'''
计算两个事件的雅阁比相似度（保留两位小数），任意事件行为集合为空，相似度为0
输入：
event1 = ['cp', 'mv', 'ls']
event2 = ['cp', 'mv']
输出：
sim(event1, event2): [0.00, 1.00]
'''
#在输入数据中，重复数据是有意义的，但通过集合处理后其信息会丢失
def similarity_jaccard(event1, event2):
    event1 = set(event1)
    event2 = set(event2)
    if len(event1) == 0 or len(event2) == 0:
        return 0.0
    else:
        return round(float(len(event1 & event2)) / len(event1 | event2), 3)
 
    
#基于雅阁比思想，优化关于重复次数忽略问题
def similarity_jaccard2(event1, event2):
    if len(event1) == 0 or len(event2) == 0:
        return 0.0
    event2t=event2[:]
    inter=list()
    union=list()
    for i in event1:
        if i in event2t:
            inter.append(i)
            event2t.remove(i)
        else:
            union.append(i)       
    return round(float(len(inter)) / (len(inter)+len(event2t)+len(union)) , 3)
    
'''
计算两个事件的字符串矩阵相似度（保留两位小数），任意事件行为集合为空，相似度为0
输入：
event2 = ['ls', 'cp', 'mv', 'ls']
event1 = ['cp', 'mv', 'll']
输出：
sim(event1, event2): [0.00, 1.00]
'''
def similarity_string_matrix(event1, event2):
    event1 = list(event1)
    event2 = list(event2)
    if len(event1) == 0 or len(event2) == 0:
        return 0.0
    else:
        # 当两个事件序列长度不一致时候，确定采用最长还是最短？
#         strLen = min(len(event1), len(event2))
        strLen = max(len(event1), len(event2))
        # 保持event1行为序列长度大于等于event2
        if strLen == len(event1):
            pass
        else:
            tempEvent = event1
            event1 = event2
            event2 = tempEvent
        # event1 序列不变，单步滑动event2序列，求两个事件行为序列的最大相似度
        maxSimilarity = 0
        for i in range(len(event1)): 
            # 计算两个序列重叠率
            if len(event2) + i <= len(event1):
                # 计算序列重叠率
                L = len(event2) / float(strLen)
            else:
                # 计算序列重叠率
                L = (len(event1) - i) / float(strLen)

            # 计算两个序列匹配率，注意边界
            count = 0
            for j in range(len(event2)):
                if i + j <= len(event1) -1:
                    if event1[i + j] == event2[j]:
                        count += 1
                    else:
                        pass
                else:
                    break
            M = count /float(strLen)
            # 计算两个序列相似度
            Q = M * M * L
            maxSimilarity = max(maxSimilarity, Q)
        return round(maxSimilarity, 3)

#基于雅阁比相似度是顺序无关而矩阵相似度则顺序强相关，加权混合上述算法
def similarity_jaccard_matrix(event1,event2,w1=0.5,w2=0.5):
    sim_jaccard=similarity_jaccard2(event1,event2)
    sim_matrix=similarity_string_matrix(event1, event2)
    return round((w1*sim_jaccard+w2*sim_matrix)/2,3)

'''   
计算命令转移矩阵（基于邓松代码，调整方法输入）
输入：
event = ['ls', 'cp', 'mv', 'ls', 'cd']
输出：
{'mv': {'ls': 1.0}, 'cp': {'mv': 1.0}, 'ls': {'cp': 0.5, 'cd': 0.5}}
'''
def compute_transform_matrix(event):
    event = list(event)
    transform_matrix = {}
    for i in range(len(event)-1):
        transform_matrix.setdefault(event[i],{})
        transform_matrix[event[i]].setdefault(event[i+1],0)
        transform_matrix[event[i]][event[i+1]] += 1
    for key1 in list(transform_matrix.keys()):
        sum_key1 = 0.0
        for key2 in list(transform_matrix[key1].keys()):
            sum_key1 += transform_matrix[key1][key2]
        for key2 in list(transform_matrix[key1].keys()):
            transform_matrix[key1][key2] /= float(sum_key1)   
    return transform_matrix

'''
计算某个图所有边的权重和
输入：
{'mv': {'ls': 1.0}, 'cp': {'mv': 1.0}, 'ls': {'cp': 0.5, 'cd': 0.5}}
输出：
sum_weight
'''
def calculate_graph_edge_weight(event_transform_matrix):
    sum_weight = 0.0
    for start_node in list(event_transform_matrix.keys()):
        for end_node in list(event_transform_matrix[start_node].keys()):
            sum_weight += event_transform_matrix[start_node][end_node]
    return sum_weight

'''
计算图边维度的相似度
输入：
{'mv': {'ls': 1.0}, 'cp': {'mv': 1.0}, 'ls': {'cp': 0.5, 'cd': 0.5}}
{'mv': {'ll': 1.0}, 'cp': {'mv': 1.0}}
输出：
sim(G1(E),G2(E)): [0.0, 1.0]
'''
def similarity_edge(event1_transform_matrix, event2_transform_matrix):
    print(event1_transform_matrix)
    print(event2_transform_matrix)
    start_node_intersection = set(event1_transform_matrix.keys()) & set(event2_transform_matrix.keys())
    print(start_node_intersection)
#     same_edge_count = 0  # 总共有多少边相同
    sum_same_edge_weight = 0.0 #相同边的权重和
    sum_total_edge_weight = 0.0 #两张图全部的边权重和
    for start_node in start_node_intersection:
        end_node_intersection = set(event1_transform_matrix[start_node].keys()) & set(event2_transform_matrix[start_node].keys())
        for end_node in end_node_intersection:
            sum_same_edge_weight += event1_transform_matrix[start_node][end_node] + event2_transform_matrix[start_node][end_node]
    sum_total_edge_weight = calculate_graph_edge_weight(event1_transform_matrix) + calculate_graph_edge_weight(event2_transform_matrix)
    
    return sum_same_edge_weight / float(sum_total_edge_weight)

'''
计算两个事件的图结构相似度（保留两位小数），任意事件行为集合为空，相似度为0
输入：
event2 = ['ls', 'cp', 'mv', 'ls']
event1 = ['cp', 'mv', 'll']
输出：
sim(event1, event2): [0.00, 1.00]
'''
def similarity_graph(event1, event2, alpha=0.7, beta=0.3):
    event1 = list(event1)
    event2 = list(event2)
    if len(event1) == 0 or len(event2) == 0:
        return 0.0
    else:
        event1_transform_matrix = compute_transform_matrix(event1)
        event2_transform_matrix = compute_transform_matrix(event2)
        node_dimension = similarity_jaccard(event1, event2)
        edge_dimension = similarity_edge(event1_transform_matrix, event2_transform_matrix)
        return alpha * node_dimension + beta * edge_dimension
    
    
#========
def string_distance(s1,s2): #编辑距离度量
    len1 = len(s1)
    len2 = len(s2)
    if len1==0 :return len2
    if len2==0 :return len1
    # initial
    help = np.zeros((len1+1,len2+1))
    help[0,:] = list(range(len2+1))
    help[:,0] = list(range(len1+1))
    for i in range(1,len1+1):
        for j in range(1,len2+1):
            if s1[i-1]==s2[j-1]:
                help[i][j] = help[i-1][j-1]
            else:
                help[i][j] = 1+min(help[i-1][j-1],min(help[i][j-1],help[i-1][j]))
    return help[len1][len2]
#==================================
def simbehavior_euclidean(X,Y):
    return 1/(1+sp.distance.euclidean(X,Y)) #normalization the dist with euclidean

def simbehavior_cosine(X,Y):
    dot_product = 0.0    
    normA = 0.0    
    normB = 0.0    
    for a,b in zip(X,Y):    
        dot_product += a*b    
        normA += a**2    
        normB += b**2    
    if normA == 0.0 or normB==0.0:    
        return 0    
    else:    
        return  0.5 + 0.5 * dot_product / ((normA*normB)**0.5) #normalization the dist with cosine 


