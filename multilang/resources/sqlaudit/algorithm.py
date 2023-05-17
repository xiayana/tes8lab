#coding=utf8
import importlib

class startcheck:
    def __init__(self,algconf,log):
        self.algclass=[] #在这添加算法，并在后面实现相关class
        self.log=log
        self.loadeletetionalg(algconf)
        
        
    def loadeletetionalg(self,algconf):
        for k,v in algconf.conf['deleteclass'].iteritems():
            md=importlib.import_module(v)
            self.algclass.append(md.alg_detection(algconf.conf,self.log))

    def start(self,user,windowlist,usermodel,userdf):
        rss=[]
        #rss.append(list(usermodel))
        for alg in self.algclass:
            if usermodel.has_key(alg.name):
                self.log.debug("Detection %s with %s on %d windows" %(user,alg.name,len(windowlist)))
                rs=alg.detection(user,windowlist,usermodel[alg.name],userdf)
                if rs:
                    #rs.append(alg.name)
                    rss.append(rs)
        return rss


        
