#!/usr/bin/python3
#coding=utf8
from distutils.core import setup
from Cython.Build import cythonize
import os
import sys
import re
import time
s=time.time()
dirs=[{'dir':'multilang/resources/sqlaudit/alg/src','rule':".*\.py$"},
      {'dir':'multilang/resources/sqlaudit/lib/src','rule':".*\.py$"},
      {'dir':'multilang/resources/sysaudit/alg/src','rule':".*\.py$"},
      {'dir':'multilang/resources/sysaudit/lib/src','rule':".*\.py$"}]




for d in dirs:
    for pp,p,names in os.walk(d['dir']):
        for name in names:
            if re.match(d['rule'],name):
                print(pp,name)
                if name=="__init__.py":
                    continue
                setup(
                    ext_modules = cythonize(os.path.join(pp,name))
                )


def isnew(fpath):
    lastc=os.stat(fpath).st_ctime
    if lastc-s>=0: #最后修改时间在编译之后
        return True
    else:
        return False

def copyso2dst(src,dst):
    for pp,p,names in os.walk(src):
        for name in names:
            fpath=os.path.join(pp,name)
            name_slice = name.split('.')
            file_name = name_slice[0]+'.'+name_slice[-1]
            if isnew(fpath):
                cmd="cp %s %s" %(fpath,dst) #+'/'+file_name)
                print(cmd,'python3.5')
                os.system(cmd)


copyso2dst("build/lib.linux-x86_64-3.6/sqlaudit/alg/src","multilang/resources/sqlaudit/alg")
copyso2dst("build/lib.linux-x86_64-3.6/sqlaudit/lib/src","multilang/resources/sqlaudit/lib")
copyso2dst("build/lib.linux-x86_64-3.6/sysaudit/alg/src","multilang/resources/sysaudit/alg")
copyso2dst("build/lib.linux-x86_64-3.6/sysaudit/lib/src","multilang/resources/sysaudit/lib")
