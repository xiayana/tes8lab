#coding=utf8
import logging
import sys
import os
import time
import re
from collections import namedtuple
import storm
import traceback
reload(sys)
sys.setdefaultencoding('utf-8')
import json
import re
import md5

#import lib.conf as nisacf
import json

log = logging.getLogger('getfield')


class GetFieldBolt(storm.BasicBolt):
    
    '''
    Time：时间戳
    User：执行sql语句用户
    ip：连接到sql服务的地址
    Cmd：操作命令（select,select_join,select_select)
    Table：操作表对象表
    Src：操作条件（包括列选择，限制条件）
    '''
    def process(self, tup):
        #{'time':1,'user':2,'ip':3,'cmd':4,'table':5,'src':6}
        tup=tup.values[0]
        log.debug(str(tup))
        try:
            rs=self.parseSQL(tup)
            storm.emit((rs['table'],rs))
        except Exception,e:
            log.error("[Error] %s" %repr(e))
            log.error("[Error] Parse SQL fail : %s" %tup)


    def getsrc(self,sql,cmd):
        sql=re.sub('\/\*.*\*\/',' ',sql) #去除注释
        if cmd=='insert':
            i=sql.find('values')
            sql=sql[:i]
        sql=re.sub("(=|>|<|>=|<=|like)\s*[\'\"]?\S+[\'\"]?",'',sql) #去除参数
        sql=sql.replace(' ','')
        return md5.md5(sql.encode('utf8')).hexdigest()

    def parseSQL(self,auditsql):
        '''
        初版
        1.管理语句
        2.有目标增删改查
        3.无目标增删改查
        '''
        fieldsql=json.loads(auditsql.lower())
        cmd=fieldsql['cmd']    
        time=float(fieldsql['date'])/1000
        user=fieldsql['user']
        if fieldsql['ip']=='':
            ip='localhost'
        else:
            ip=fieldsql['ip']
        if fieldsql.has_key('type_ip'):
            type_ip=fieldsql['type_ip']
        else:
            type_ip="x.x.x.x"
        if fieldsql.has_key('objects'):
            table=''
            for obj in fieldsql['objects']:
                if obj['db']=='':
                    pass
                elif obj['name'].find('/tmp/')>=0: #过滤本地操作
                    table += "%s.tmp" %(obj['db'])
                else:
                    table += "%s.%s" %(obj['db'],obj['name'])
            if table=='':table='null'
        else:
            table='null'
        #行数
        if fieldsql.has_key('rows'):
            rows=int(fieldsql['rows'])
        else:
            rows=0
        src=self.getsrc(fieldsql['query'],cmd)
        return {'time':time,'user':'.'.join((type_ip,user)),'ip':ip,'cmd':cmd,'table':table,'src':src,'rows':rows}
    
    def gettime(self,times):
        a,b=times.split(',')
        b=float(b)/1000
        return time.mktime(time.strptime(a,'%Y-%m-%d %H:%M:%S'))+b
        
class contain:
    conf=None     
    
if __name__ == '__main__':
    sqlconf=contain()
    sqlconf.conf=json.loads(sys.argv[1])
    log.info("[INFO] config info: %s" %str(sqlconf.conf))
    if sqlconf.conf['system'].has_key('log'):
        sqlog=sqlconf.conf['system']['log']
    else:
        sqlog='/tmp/sqlnisa'
    if not sqlconf.conf['system'].has_key('level'):
        pylog=logging.INFO
    elif sqlconf.conf['system']['level']=='debug':
        pylog=logging.DEBUG
    elif sqlconf.conf['system']['level']=='info':
        pylog=logging.INFO
    elif sqlconf.conf['system']['level']=='error':
        pylog=logging.ERROR
    else:
        pylog=logging.INFO
        
    logging.basicConfig(
        level=pylog,
        filename=os.path.join(sqlog,'getfield.log'),
        format="%(message)s",
        filemode='w',
    )
    log.debug(os.getcwd())
    log.debug(sys.argv)
    log.debug(sys.path)
    try:
        GetFieldBolt().run()
    except Exception,e:
        log.error("[Error] %s" %repr(e))
        log.error("[Error INFO] %s" %traceback.format_exc())
    
