#coding=utf8
#根据当前语法自定义编辑输出字符串，对于%s符号禁止修改
######################################################
#Bolt with heuristic
#alert_ip
heuristic_sshbrute="发现一个ssh暴力破解攻击：%s"
heuristic_backdoor="发现一个后门攻击：%s"
heuristic_stealdata1="发现一个数据窃取攻击(拷贝数据到移动介质)：%s"
heuristic_stealdata2="发现一个数据窃取攻击(打包数据)：%s"
heuristic_stealdata3="发现一个数据窃取攻击(非法导出数据库数据)：%s"
heuristic_removedata="发现一个删除数据攻击：%s"
######################################################
#Bolt with service
#alert_ip, stat_now stat_model_mean stat_model_var
service_statexp="[统计异常] %s 发现时块行为次数统计异常，相关参数 %f %f %f"
#alert_user ppname src&args
service_listen_inet="[异常监听端口][service] 用户 %s 执行了程序 %s 开启了一个非法端口 %s"
service_listen_ipro="[异常监听程序][service] 用户 %s 非法执行了程序 %s 开启了一个端口 %s"
service_output_inet="[异常网络连接][service] 用户 %s 执行的程序 %s 发生了一次异常连接 %s"
service_output_ipro="[异常网络进程][service] 用户 %s 非法执行了程序 %s 发生了一次接 %s"
service_fwrite_ipath="[异常文件写][service] 用户 %s 执行的程序 %s 非法的写了文件 %s"
service_fwrite_ipro="[异常进程写][service] 用户 %s 非法执行了程序 %s 写了文件 %s"
service_fread_ipath="[异常文件读][service] 用户 %s 执行的程序 %s 非法的读了文件 %s"
service_fread_ipro="[异常进程读][service] 用户 %s 非法执行了程序 %s 读了文件 %s"
service_rwrite_ipath="[异常注册表写][service] 用户 %s 执行的程序 %s 非法的写了注册表 %s"
service_rwrite_ipro="[异常程序注册表写][service] 用户 %s 非法执行了程序 %s 写了注册表 %s"
service_rread_ipath="[异常注册表读][service] 用户 %s 执行的程序 %s 非法的读了注册表 %s"
service_rread_ipro="[异常程序注册表读][service] 用户 %s 非法执行了程序 %s 读了注册表 %s"
#alert_user ppname exepath_with_absolute_path_from_dst
service_pro_isub="[非法子进程][service]  %s 父进程 %s 非法执行了 %s"
service_pro_ipp="[非法父进程][service]  %s 非法父进程 %s 执行了 %s"
#alert_tup_to_string
service_notexist="[缺少时块][service]  历史训练数据中没有相关时块数据，当前检测数据是： %s"
#alert_cmd
service_cmdnotexist="[未知父进程且全局不存在的命令异常] 未知父进程执行了一个全局不存在的未知命令 %s"
######################################################
#Bolt with detection
#alert_user block1,block2
detection_block_notexist="[不存在的时块]%s 在时块 %s %s 没有有效的训练数据;"
detection_log_diff="当前扩散系数:%f,%f"
detection_log_sim="概率分布相似度 %f,NG相似度 %f,聚类行为异常最大相似度 %f,综合判定系数 %f"
detection_log_dlsim="概率分布相似度 %f,NG相似度 %f,深度学习行为相似度 %f,综合判定系数 %f"
detection_diff_exp="[扩散系数异常]%s 扩散系数异常，相关数据： %f,%f;"
detection_user_expsim="[Core行为异常]%s 用户行为特征异常； %s;"
detection_user_status="[行为信息]%s 用户行为相似度状态: %s;"
detection_debug_sim_maxmin="最大行为相似度：%f, 最小行为相似度：%f"
detection_debug_mmblock="主时块 %s,副时块 %s;"
detection_dl_status="基于深度学习的最大相似度为 %f"
detection_dl_exp="[DL行为异常]%s %s ，检测阈值为 %f;"
######################################################
#Bolt with alert
#login_user login_addr login_time
alert_login_remote="[地址]%s 从远程地址 %s 登录，时间：%s"
#alert_user
alert_login_local="[地址]%s 在本地操作"
######################################################
#放置在最后一行，不能修改，用来获取语言变量的动态映射
objmap=locals()
