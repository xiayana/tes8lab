#coding=utf8
#language file with english,you edit this document must base the syntax
######################################################
#Bolt with heuristic
#alert_ip
heuristic_sshbrute="Have a attack with sshbrute in %s"
heuristic_backdoor="Have a attack with backdoor in %s"
heuristic_stealdata1="Have a attack with stealdata in %s"
heuristic_stealdata2="Have a attack with stealdata in %s"
heuristic_stealdata3="Have a attack with stealdata in %s"
heuristic_removedata="Have a attack with remove import data in %s"
######################################################
#Bolt with service
#alert_ip, stat_now stat_model_mean stat_model_var
service_statexp="[Static Stats EXP] %s have stats exp with %f %f %f"
#alert_user ppname src&args
service_listen_inet="[Illegal Network Listen]%s %s have illegality net listen with %s"
service_listen_ipro="[Illegal Process]%s %s have illegality net listen with %s"
service_output_inet="[Illegal Network Output]%s %s have illegality net output with %s"
service_output_ipro="[Illegal Process]%s %s have illegality net output with %s"
service_fwrite_ipath="[Illegal Path]%s %s have illegality file write with %s"
service_fwrite_ipro="[Illegal Process]%s %s have illegality file write with %s"
service_fread_ipath="[Illegal Path]%s %s have illegality file read with %s"
service_fread_ipro="[Illegal Process]%s %s have illegality file read with %s"
service_rwrite_ipath="[Illegal Path]%s %s have illegality reg write %s"
service_rwrite_ipro="[Illegal Process]%s %s have illegality file reg write %s"
service_rread_ipath="[Illegal Path]%s %s have illegality reg read %s"
service_rread_ipro="[Illegal Process]%s %s have illegality file reg read %s"
#alert_user ppname exepath_with_absolute_path_from_dst #中文测试
service_pro_isub="[Illegal subProcess]%s %s have illegality launch %s"
service_pro_ipp="[Illegal PProcess]%s %s have illegality launch %s"
#alert_tup_to_string
service_notexist="[Not Block Model]Have not time black model; The data is %s"
#alert_cmd
service_cmdnotexist="[UnknowPPNotexistcmd] Illegal cmd %s from unknow ppname opert"
######################################################
#Bolt with detection
#alert_user block1,block2
detection_block_notexist='[NotExist] %s Time Block %s %s have not exist model data;'
detection_log_diff="current diffuse:%f,%f"
detection_log_sim="similarity with probability distribution %f,similarity with NG %f,similarity general behavior %f,comprehensive predicate %f"
detection_log_dlsim="similarity with probability distribution %f,similarity with NG %f,similarity with dl behavior %f,comprehensive predicate %f"
detection_diff_exp="[DiffUse EXP]%s diffuse exp： %f,%f;"
detection_user_expsim="[Core Behavior EXP]%s User Behavior abnormal; %s;"
detection_user_status="[Behavior Info]%s User Behavior status: %s;"
detection_debug_sim_maxmin="max similarity：%f, min similarity：%f"
detection_debug_mmblock="main block %s,minor block %s;"
detection_dl_status="The Max similarity with deep learn %f"
detection_dl_exp="[DL Behavior EXP]%s %s ，threshold value is %f;"
######################################################
#Bolt with alert
#login_user login_addr login_time
alert_login_remote="[Addr]%s login from %s in %s"
#alert_user
alert_login_local="[Addr]%s operate with localhost"
######################################################
#放置在最后一行，不能修改，用来获取语言变量的动态映射
objmap=locals()
