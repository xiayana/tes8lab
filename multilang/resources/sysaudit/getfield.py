#coding=utf8
import logging
import sys
import os
import re
from collections import namedtuple
import storm
import traceback
import json


from lib.tup2dict import *

log = logging.getLogger('getfield')


class GetFieldBolt(storm.BasicBolt):

    #[time,user,ip,cmd,src,dst,ppname,flag]11
    def process(self, tup):
        # storm.ack(tup)
        try:
            tup=tup.values[0]
            log.debug(str(tup))
            dt=syslog2dict(tup,log)
        except Exception as err:
            log.debug(f"ERROR,ERROR, 错误是：{err}")
        if dt:
            log.debug('into emit')
            storm.emit((dt['ip'],dt))


class contain:
    conf=None

if __name__ == '__main__':
    sysconf=contain()

    sysconf.conf=json.loads(sys.argv[1])

    log.info("[INFO] config info: %s" %str(sysconf.conf))

    if 'log' in sysconf.conf['system']:
        syslog=sysconf.conf['system']['log']
    else:
        syslog='/tmp/sqlnisa'

    Bolt=GetFieldBolt()
    taskid=Bolt.getaskid()

    if 'level' not in sysconf.conf['system']:
        pylog=logging.INFO
    elif sysconf.conf['system']['level']=='debug':
        pylog=logging.DEBUG
    elif sysconf.conf['system']['level']=='info':
        pylog=logging.INFO
    elif sysconf.conf['system']['level']=='warn':
        pylog=logging.WARN
    elif sysconf.conf['system']['level']=='error':
        pylog=logging.ERROR
    else:
        pylog=logging.INFO


    path = os.path.join(syslog, 'getfield.log' + taskid)
    if not os.path.exists(path):
        try:
            os.makedirs(os.path.dirname(path))
        except:
            pass
        os.mknod(path)
    logging.basicConfig(
        level=logging.DEBUG,
        filename=path,
        format="%(message)s",
        filemode='w',
    )
    log.info(os.getcwd())
    log.info(sys.argv)
    log.info(sys.path)

    try:
        Bolt.run()
    except Exception as e:
        log.error("[Error] %s" %repr(e))
        log.error("[Error INFO] %s" %traceback.format_exc())
