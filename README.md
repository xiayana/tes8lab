### 项目介绍和说明

通过storm内置的KafkaSpout直接对接kafka中的流数据，然后，依次经过GetFieldBolt => DupfilterBolt => HeuristicBolt => ServiceModelBolt => DetectionBolt => AlertBolt各个bolt，
最终形成检测结果。其中HeuristicBolt、ServiceModelBolt、DetectionBolt三个bolt分别利用不同的算法完成对数据的检测，如果前面的bolt已检测到异常，数据仍然会流入后续的bolt，但不会再进行检测而是直接向后传递，直到AlertBolt。

### 分支介绍

测试部署暂使用项目开发分支jynisa-refactor
https://bitbucket.org/8labteam/jynisa/src/jynisa-refactor/

master: 项目主分支
jynisa-refactor : 项目开发分支

..

### 依赖

1. 操作系统
   Ubuntu 18.04.2 LTS *暂无特殊需求*
2. python 版本 Python 3.6.9
3. 系统依赖包  
   sudo apt-get install liblzma-dev
4. 服务依赖包  
   pip3 install -r requirements.txt
5. 本项目依赖哪些项目，有什么关联
   本项目会用到pynisa 训练生成的模型数据，中间通过mysql数据库进行关联
   本项目会依赖pynisa rpc服务，
   启动方式如下
   python3 thrift_main.py conf/SysAudit_train.ini conf/JySysAudit_detection.ini 9898 &
6. 依赖中间件，以及中间件的版本，某些中间件特殊的需求（某个配置，是否为集群等）
   redis==3.5.3
   ZooKeeper 3.4.6 及其以上版本
   storm-2.1.0  (分布式集群)
   kafka_2.11-2.2.1 (数据源)

测试环境部署文档和配置文件解释：
https://pm.8lab.cn/projects/xs004/wiki/Jynisa%E7%9B%B8%E5%85%B3%E7%8E%AF%E5%A2%83%E9%83%A8%E7%BD%B2%E5%8F%8A%E5%85%B6%E6%89%A7%E8%A1%8C


### 部署运行

运行前确认所需中间件已启动
1. 打包
   mvn clean package
   target目录下已经有打包好的jar文件 文件名：JyNISA-3.2.0.jar
2. 上传集群 执行jar
   strom jar ${topologyName} ${SysAudit_topology.json} ${JySysAudit_detection.ini}




配置文件位置
conf下
配置项说明
需要将conf目录在集群中的所有节点相同的目录下都上传一份（实时流检测的Bolt要用）
注意： redis如果集群配置，需要设置iscluster为1， 有密码设置需要设置security为on,无密码设置需要设置为off
redis如果为单点配置， 需要设置iscluster为0， 有密码设置需要设置security为on,无密码设置需要设置为off


- 前端：浏览器访问
  http://192.168.3.104:7070/
- 脚本验证方法
  https://pm.8lab.cn/projects/xs004/wiki/%E8%AE%AD%E7%BB%83%E6%A8%A1%E5%9E%8B%E9%AA%8C%E8%AF%81%E6%96%B9%E6%B3%95

### changlog

#### 2022-02-09
### operating_record

添加一些注释
topoConfig 添加优化参数 （消息超时时间，spout等待机制）
Bolt执行Python环境修改为虚拟环境
解决storm横向扩展的问题
SysAudit_topology.json中参数适当的修改
v3.2.0做的修改内容
------（fqm）start 2022年1月6日修复bug如下：

eagleearte.py文件中修改一下，报错参数不匹配，修改添加,self.conf['qingcloudalert']参数，
self.client=client.eagleclient(self.server['host'],self.server['port'],self.server['name'],self.server['passwd'],self.conf['qingcloudalert'])
JySysAudit_detection.ini 配置文件中[export][alert]redis配置修改 100redis没有密码需要设置security:off
getfield.py中添加日志自动创建路径的功能
opert.py中 当读取的models表中的数据为（）空时候，自动过滤功能
增加debug日志打印功能
修改日志打印不匹配问题
调整kafka入库数据要求格式问题
将JyNISA core_dl.py中 blockindex为时间块，提取模型数据时候添加try catch捕获异常
修改sysaudit storm.py 40行 并过滤读取数据为空的情况功能
-----end-----

#pyc打包方法
python3 -m compileall *.py -b
