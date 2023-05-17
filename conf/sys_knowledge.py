#coding=utf8
import re
import traceback

currentknow=None
sensitiveflag=[]
heuristicflag=[]
#////////////////////////////////////////////////////////////////

#仅支持正则表达式
#随机路径,在文件读写操作路径相关的随机替换
randompath={"ansible_tmp1":{"ree":'ansible\-tmp[\d\-\.]+',"min":25,'dst':'ansible-random'},
            "ansible_tmp2":{"ree":'ansible_\w+',"min":10,'dst':'ansible-random'},
            "random64":{"ree":"[0-9a-z]+","min":64,'dst':'random64'},
            "random32":{"ree":"[0-9a-z]+\-[0-9a-z]+\-[0-9a-z]+\-[0-9a-z]","min":36,'dst':'random32'},
            "mtab":{"ree":"mtab\S?\.?\w+",'min':5,'dst':'mtab-random'},
            "usergroup":{"ree":"(group|gshadow|passwd|shadow)\.\S+","min":10,"dst":"usergroup.tmp"},
            "oracle":{"ree":"\w{16}\.timestamp","min":26,'dst':'oracle.timestamp'}}


#随机shell相关路径处理-涉及到cmd,ppname
randomshell={"ansible_tmp1":{"ree":'ansible\-tmp[\d\-\.]+',"min":25,'dst':'ansible-random'},
           "ansible_tmp2":{"ree":'ansible_\w+',"min":10,'dst':'ansible-random'}}

#==============================
#可信父进程-数据来源perm
#同时支持正则和内容匹配语法
trustPP={"kubelet":{"content":["/usr/bin/kube-proxy","/usr/local/kubernetes-client/bin/kube-proxy","/usr/bin/kubelet"],"min":15},
         "apt":{"ree":"/usr/bin/dpkg|(/usr/bin/)?apt-(get|config)","min":7},
         "re_8lab":{"ree":"\S*(8lab|blackbox|octa|tagent|BlackBox|ima_verify)","min":8},
         "runparts":{"ree":"(/bin/)?run-parts","min":5},
         "init.d":{"ree":"(/bin/)?(bash|dash|sh)(_|\+)/etc/init\.d/(BlackBox|dtamper|tagent|start-tpmd)","min":15},
         "docker":{"ree":"(/usr/bin/)?docker(\S+)?","min":6},
         "libapp":{"content":["/lib/systemd/systemd-udevd","/usr/sbin/logrotate","erl_child_setup","/nginx-ingress-controller","dash_/unix:cmd","/usr/local/bin/forego","/usr/local/bin/tpmd","/usr/bin/basename"],"min":10},
         "libapp2":{"ree":"(/usr)?/bin/(nc\.openbsd|cat|who|wc|file|find|gzip|xauth|env|kill|ionice|date|flock|df|mktemp|nohup)","min":8},
         "libapp3":{"ree":"(bash|dash)_(/sbin/on_ac_power|/usr/bin/apt-key|/usr/bin/savelog|/usr/sbin/service)","min":15},
         "sbin":{"ree":"/sbin/(startpar-upstart-inject|ifup|start-stop-daemon|xtables-multi)","min":8},
         "toys":{"content":["git","/sbin/init","[tagent]","dash_/sbin/hwclock","[start-tpmd]","/usr/sbin/keepalived","/sbin/hwclock"],"min":3},
         "mount":{"ree":"/bin/u?mount|\[u?mount\]|/sbin/mount\.ceph","min":7},
         "pythonAPP":{"ree":"/usr/bin/python\S{0,4}?\+(/usr/sbin/update|/tmp/ansible|/usr/bin/supervisord|/usr/lib)","min":30},
         "shAPP":{"ree":"(/bin/)?(sh|bash|dash|busybox)\+(-(c|e)\+)?(/bin/sh\+)?(/etc/cron.daily|/etc/default/createplist|/proc/self|/data|/usr/local/(zabbix|mongodb)|/usr/lib|/var/lib|/opt/intel|/usr/share|/usr/bin/env|/8lab)","min":25},
         "shAPP2":{"ree":"((python|bash|dash|sh|perl|busybox)_)?(/usr/local/(zabbix|mongodb)|/etc/default/createplist|/etc/cron.daily|/proc/self|/data|/lib/resolvconf|/usr/lib|/var/lib|/opt/intel|\S+?/ansible-random|/usr/share|/8lab)","min":10}
         }

#可信子进程-数据来源cmd
trustsub={"zabbix_script":{"ree":"\w+?_/usr/local/zabbix/","min":30},
          "createplist":{"ree":"(ba|da)?sh_/etc/default/createplist\.sh","min":25},
          "mysqlalive":{"ree":"(ba|da)?sh_/data/script/MysqlAlive\.sh","min":25},
          "ansible_shell":{"ree":"\w+?_\S+/ansible-random/\S+","min":30},
          "rsyn":{"ree":"(ba|da)?sh_/root/rsynclogs\.sh","min":20},
          "discovery":{"content":["discovery_mongo","discovery_redis"],"min":15},
          "dj_xxx":{"content":["dj_tcp_status.s","dj_mongodb_stat"],"min":15},
          "zabbix_scmd":{"ree":"zabbix_\w+","min":10},
          "ansible_cmd":{"ree":"ansible\-\S+","min":10},
          "re_8lab":{"ree":"\S*(8lab|blackbox|octa|tagent|BlackBox|ima_verify)","min":8},
          "exclpath":{"ree":"(ba|da)?sh_(/var/lib)","min":10},
          "docker":{"ree":"docker(\S+)?","min":6},
          "shell":{"ree":"(bash|dash|sh)_/sbin/(hwclock|ldconfig)","min":15},
          'sys':{'content':['grep','rsync','awk','apport','wc','nice','ss',\
                            'egrep','date','ip','echo','sort','xargs','sed','chattr','xauth',\
                            'ldconfig.real','du','env','who','file','tcsd','nohup','tpmd','nc',\
                            'hwclock','basename'],'min':2},
          "app":{"content":["mandb","kubectl","mongod","MysqlAlive.sh","keepalived","mongo",\
                            "NIARL_TPM_Modul"],"min":5}
          }


#可信写路径
trustfwrite={"auditlog":{"content":["/var/log/audit"],"min":12},
             "null":{"ree":"/root/null","min":8},
             "8lab":{"ree":"\S*(OCTA|octa|8lab|8LAB)\S*","min":15},
             "cloudsecurity":{"ree":"\S*/cloudsecurity\S*","min":20}}

#可信读路径
trustfread={}

#不支持知识语法，使用单纯的k-v结构
#可信父子关系pp-cmd {pp:{sub1:1,sub2:1},...}
trustPsub={"CRON":{"cat":1}}


#可信连接输出
#uwsgi 目前运维测试环境的对外访问情况比较杂乱，14天的数据无法记录全所有正常固定ip，导致告警，目前暂时对改进程进行可信处理
trustconnect={"/usr/bin/python3.4":{"ree":"91\.189\.\S+","min":7},
              "/usr/local/bin/uwsgi":{"ree":"(123\.58\.177\.199|183\.192\.199\.148|117\.185\.30\.190|223\.252\.213\.13\d)","min":7}}

#数据预解析
parse_userknowledge={"randompath":randompath,
                     "randomshell":randomshell}

#检测知识
detection_userknowledge={"trustPP":trustPP,
                         "trustsub":trustsub,
                         "trustPsub":trustPsub,
                         "trustfwrite":trustfwrite,
                         "trustfread":trustfread,
                         "trustconnect":trustconnect}
#=================================================================================

#此类知识下的falg参数指定当条件命中时危险标记维持的有效时间，例如，当falg：5，则当标记对应标记后，若5分钟之内产生行为异常，则告警，否则忽略
#当flag设为0时，意味着单条的标志永远无法触发告警，主要用来用户敏感行为定义中进行聚合检测需要，
#type 定义用户设定的状态标准，可以把多种命令设为同一type,可以有多个类型，如'type':['a','b']
sys_sensitivepath={'etc':{'ree':'/etc/.*','min':5,"flag":0,'type':['fetc']},
           'service1':{'ree':'/etc/init\.d/.*','min':10,"flag":10,'type':['fservice']},
           'service2':{'ree':"/etc/rc\d\.d/.*",'min':10,'flag':10,'type':['fservice']},
           'cron':{'ree':'/etc/cron.*','min':10,"flag":10,'type':['fcron']},
           'passdow':{'ree':'/etc/(passwd|shadow)','min':10,"flag":10,'type':['passdow']},
           'sysbin1':{'ree':'/usr/s?bin/.*','min':10,"flag":6,'type':['sysbin']},
           'sysbin2':{'ree':'/usr/local/s?bin/.*','min':15,"flag":6,'type':['sysbin']},
           'sysbin3':{'ree':'/s?bin/.*','min':10,"flag":7,'type':['sysbin']},
           'web':{'ree':'/var/www/.*','min':10,"flag":5,'type':['web']}
           }

user_sensitivepath={}

#目前支持参数全量获取的命令['scp','cp','tar','mv','rm','pptp','ssh','curl','wget','apt-get','yum','ping','ls','cat','tail','ssserver','sslocal','mysql','mysqladmin','mysqldump','vi','vim','exp']
#当知识内部包含content或ree时，则需要在命令参数列表中匹配命中才会进行危险标记，对应知识变量为behavior_sensitive
#当有exclude时，相关命令若带有此匹配参数，不进行危险标记
sys_sensitivecmd={"mount":{"flag":0,"ree":"/(mnt|media)/\S+",'type':['mount']},
                   "pptp":{"flag":5,'type':['pptp']},
                   "ssh":{"content":["-D"],"flag":10,'type':['ssh']},
                   "ssserver":{"flag":10,'type':['ssocks']},
                   "sslocal":{"flag":10,'type':['ssocks']},
                   "apt-get":{"content":["install"],"flag":0,'type':['sysinstall']},
                   "python_yum":{"content":["install"],"flag":0,'type':['sysinstall']},
                   "tar":{"exclude":{'content':["--warning=no-timestamp"]},"flag":0,'type':['tar','pack','file']},
                   "cp":{"flag":0,'type':['cp','copymove','file']},
                   "mv":{"ree":"/(etc|mnt|media|root|home|bin)/\w+","flag":0,'type':['mv','copymove','file']},
                   "scp":{"flag":0,'type':['scp','copymove','file']},
                   "mysqldump":{"flag":15,'type':['mysqldump']},
                   "wget":{"flag":0,'type':['wget','netdown']},
                   "curl":{"flag":0,'type':['curl','netdown']},
                   "ping":{"flag":0,'type':['ping','net']}}

user_sensitivecmd={}

#组合敏感行为behavior
#{gname:{type:vaild_flag,type:vaild_flag}}
behavior_sensitive={"mount_file":{'mount':30,'file':5},
                    "pack_cm":{"pack":10,"copymove":5},
                    "down_cm":{"netdown":10,"copymove":5}}

sensitive_knowledge={"sys_sensitivepath":sys_sensitivepath,
                     "user_sensitivepath":user_sensitivepath,
                     "sys_sensitivecmd":sys_sensitivecmd,
                     "user_sensitivecmd":user_sensitivecmd,
                     "behavior_sensitive":behavior_sensitive}


#==============================================================
#启发式规则知识
#store 设置启发式知识标记模式，
#1 孤立标记存储，新状态会刷新历史状态，
#2 队列模式，按照设定排序存储,max设定存储长度,不支持多标记
heuristic_flag={'auth_succ':{'store':1,'condition':{'cmd':{'content':['user_auth']},'flag':{'content':['true']}},'type':['auth_succ']},
                'auth_fail':{'store':2,'max':10,'condition':{'cmd':{'content':['user_auth']},'flag':{'content':['false']}},'type':['auth_fail']},
                'login_succ':{'store':1,'condition':{'cmd':{'content':['user_acct']}},'type':['login_succ']},
                'download':{'store':1,'condition':{'cmd':{'content':['curl','wget']}},'type':['download']},
                'service':{'store':1,'condition':{'cmd':{'content':['fwrite']},'src':{'ree':'/etc/(init\.d|rc\w\.d)/'}},'type':['service','startup']},
                'tmovecp':{'store':1,'condition':{'cmd':{'content':['cp','move']},'src':{'ree':'\S*/(etc|var)/\S+/(mnt|media)/\S+'}},'type':['tmovecp']},
                'ttar':{'store':1,'condition':{'cmd':{'content':['tar']},'src':{'ree':'\S*c\S*/(etc|var)/\S+'}},'type':['ttar']},
                'trm':{'store':1,'condition':{'cmd':{'content':['rm']},'src':{'ree':'\S*/(var|etc)/\S*'}},'type':['trm']},
                'tmysql':{'store':1,'condition':{'cmd':{'content':['mysqldump']}},'type':['tmysql']}
                }

#启发式规则
#minlen 存储队列最小长度
#maxlen 存储队列最大长度
#tailhead<= 存储结构尾首时间差<=
#tailhead>= 存储结构尾首时间差>=
#tailhead== 存储结构尾首时间差==
#timedf<= 传递两个flag参数,一个时间参数，当前一个和后一个标志的时间差<=时间设定时，返回真
#timedf<= 传递两个flag参数,一个时间参数，当前一个和后一个标志的时间差>=时间设定时，返回真
#timedf== 传递两个flag参数,一个时间参数，当前一个和后一个标志的时间差==时间设定时，返回真

#key 只允许三类内容,"condition","msg"和其他预定义的启发式标志

#message:这种告警输出信息，其中的格式化内容符合不能修改，当以$开头时，对应字符串从语言文件中获取
heuristic_rule={'sshbrute':[{'key':'auth_fail','minlen':5,'tailhead<=':60},{'key':'msg','message':"$heuristic_sshbrute"}],
                'backdoor1':[{'key':'download'},{'key':'condition','timedf<=':['download','auth_succ',5]},{'key':'msg','message':"$heuristic_backdoor"}],
                'backdoor2':[{'key':'service'},{'key':'condition','timedf<=':['service','auth_succ',5]},{'key':'msg','message':"$heuristic_backdoor"}],
                'stealdata1':[{'key':'tmovecp'},{'key':'msg','message':'$heuristic_stealdata1'}],
                'stealdata2':[{'key':'ttar'},{'key':'msg','message':'$heuristic_stealdata2'}],
                'stealdata3':[{'key':'tmysql'},{'key':'msg','message':'$heuristic_stealdata3'}],
                'removedata':[{'key':'trm'},{'key':'msg','message':'$heuristic_removedata'}]
                }


heuristic_knowledge={'heuristic_flag':heuristic_flag,
                     'heuristic_rule':heuristic_rule}

#======================================================
globalknowledge={"parse_userknowledge":parse_userknowledge,
                 "detection_userknowledge":detection_userknowledge,
                 "sensitive_knowledge":sensitive_knowledge,
                 "heuristic_knowledge":heuristic_knowledge}

objmap=locals()


#/////////////////////////////////////////////////////////////////////////////
def checkrandom(oneknowledge):
    global currentknow
    currentknow=oneknowledge
    assert 'min' in oneknowledge and type(oneknowledge['min'])==int
    assert 'dst' in oneknowledge and type(oneknowledge['dst'])==str
    assert 'ree' in oneknowledge
    assert re.compile(oneknowledge['ree'])

def checkcommontrust(oneknowledge):
    global currentknow
    currentknow=oneknowledge
    assert 'min' in oneknowledge and type(oneknowledge['min'])==int
    if 'ree' in oneknowledge:
        assert re.compile(oneknowledge['ree'])
    else:
        assert 'content' in oneknowledge and type(oneknowledge['content'])==list


def checktrustPsub(oneknowledge):
    global currentknow
    currentknow=oneknowledge
    assert type(oneknowledge)==dict

def checksensitivepath(oneknowledge):
    global currentknow
    currentknow=oneknowledge
    assert 'ree' in oneknowledge
    assert re.compile(oneknowledge['ree'])
    assert 'min' in oneknowledge and type(oneknowledge['min'])==int
    assert 'flag' in oneknowledge and type(oneknowledge['flag'])==int
    assert 'type' in oneknowledge and type(oneknowledge['type'])==list
    sensitiveflag.extend(oneknowledge['type']) #addition the sensitive flag

def checksensitivecmd(oneknowledge):
    global currentknow
    currentknow=oneknowledge
    assert 'flag' in oneknowledge and type(oneknowledge['flag'])==int
    if 'ree' in oneknowledge:
        assert re.compile(oneknowledge['ree'])
    if 'content' in oneknowledge:
        assert type(oneknowledge['content'])==list
    if "exclude" in oneknowledge:
        assert 'ree' in oneknowledge['exclude'] or 'content' in oneknowledge['exclude']
        if 'ree' in oneknowledge['exclude']:
            assert re.compile(oneknowledge['exclude']['ree'])
        if 'content' in oneknowledge['exclude']:
            assert type(oneknowledge['exclude']['content'])==list
    assert 'type' in oneknowledge and type(oneknowledge['type'])==list
    sensitiveflag.extend(oneknowledge['type']) #addition the sensitive flag

def checksensitivebehavior(oneknowledge):
    global sensitiveflag
    global currentknow
    currentknow=oneknowledge
    if type(sensitiveflag)!=set:
        sensitiveflag=set(sensitiveflag)
    for k,v in oneknowledge.items():
        assert k in sensitiveflag
        assert type(v)==int

def checkheuristicflag(oneknowledge):
    global currentknow
    currentknow=oneknowledge
    assert 'store' in oneknowledge
    if oneknowledge['store']==1:
        pass
    elif oneknowledge['store']==2:
        assert 'max' in oneknowledge and type(oneknowledge['max'])==int
    else:
        raise Exception("NotVaildStoreType")
    assert 'condition' in oneknowledge
    for k,v in oneknowledge['condition'].items():
        assert 'ree' in v or 'content' in v
        if 'ree' in v:
            assert re.compile(v['ree'])
        if 'content' in v:
            assert type(v['content'])==list
    assert 'type' in oneknowledge and type(oneknowledge['type'])==list
    heuristicflag.extend(oneknowledge['type'])

def checkheuristicrule(oneknowledge):
    global heuristicflag
    global currentknow
    currentknow=oneknowledge
    if type(heuristicflag)!=set:
        heuristicflag=set(heuristicflag)
    assert type(oneknowledge)==list
    for tup in oneknowledge:
        assert 'key' in tup and (tup['key'] in heuristicflag)

def checkparse_userknowledge(knowledges):
    for ktype in list(knowledges.values()):
        list(map(checkrandom,list(ktype.values())))

def checkdetection_userknowledge(knowledges):
    for k,v in knowledges.items():
        if k=="trustPsub":
            list(map(checktrustPsub,list(v.values())))
        else:
            list(map(checkcommontrust,list(v.values())))

def checksensitive_knowledge(knowledges):
    global sensitiveflag
    for k,v in knowledges.items():
        if (k in ["sys_sensitivepath","user_sensitivepath"]):
            list(map(checksensitivepath,list(v.values())))
        elif (k in ["sys_sensitivecmd","user_sensitivecmd"]):
            list(map(checksensitivecmd,list(v.values())))
    list(map(checksensitivebehavior,list(knowledges['behavior_sensitive'].values())))
    sensitiveflag=[]

def checkheuristic_knowledge(knowledges):
    global heuristicflag
    list(map(checkheuristicflag,list(knowledges['heuristic_flag'].values())))
    heuristicflag.extend(["condition","msg"])
    list(map(checkheuristicrule,list(knowledges['heuristic_rule'].values())))
    heuristicflag=[]

def checknowledgesytax():
    try:
        checkparse_userknowledge(globalknowledge['parse_userknowledge'])
        checkdetection_userknowledge(globalknowledge['detection_userknowledge'])
        checksensitive_knowledge(globalknowledge['sensitive_knowledge'])
        checkheuristic_knowledge(globalknowledge['heuristic_knowledge'])
        print("The knowledge is vaild!!!")
    except Exception:
        print("Found error sytax knowledge!")
        print("Error Sytax Knowledge:",currentknow)
        print(traceback.format_exc())

if __name__ == "__main__":
    #run the check code when the main py file is not this
    checknowledgesytax()
