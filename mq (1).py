#!/usr/bin/python  
# -*- coding: utf-8 -*-
import string
import random
import argparse
import re
import os
import time
from channel import Channel
import hashlib
from vitMachine import vitMachine
from apscheduler.schedulers.blocking import BlockingScheduler
import datetime
import threading
from redisAD import RedisHelper
import sys
import Queue
from redis import StrictRedis
ret = Queue.Queue()
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))
def getfile_Md5(file):
    m = hashlib.md5()
    
    m.update(file)
    
    return m.hexdigest()

class MQStar():
    """ MQStar is a Message Queue with a star topology. There's a server and multiple clients.
    Each mqstar is identified by a session, which is the name of the underlining redis channels.
    A server can send messages to clients on different channels, but receives answers on one channel: channel_to_server

    """
    session = ""
    channels = {}
    """MQStar is a MessageQueue with a star topology based on Redis"""

    def __init__(self, host, session=None):
        self.host = host
        if not session:
            self.session = id_generator()
        else:
            self.session = session

        self.set_session(session)

    def set_session(self, session):
        channel_server = "%s" % self.session
        self.channel_to_server = Channel(self.host, channel_server)

    def _make_channel(self, channal):
        #name = "%s" % (self.session)
        channel = Channel(self.host, channal)
        return channel

    def notify_connection(self, av):
        print("notify_connection %s" % av)
        redis = self.channel_to_server.redis
        name = "MQ_%s_connection" % (self.session)
        redis.sadd(name,av)

    def reset_connection(self, av):
        print("reset_connection %s" % av)
        redis = self.channel_to_server.redis
        name = "MQ_%s_connection" % (self.session)
        redis.srem(name,av)

    def check_connection(self, av):
        print("check_connection %s" % av)
        redis = self.channel_to_server.redis
        name = "MQ_%s_connection" % (self.session)
        return redis.sismember(name,av)

    def clean(self, av=None):
        """ Cleans all the redis keys related to the used channels
        """
        if av:
            key = "MQ_*_server_%s" % av
        else:
            key = "MQ_*"

        for k in self.channel_to_server.redis.keys(key):
            print(" MQ clean %s" % k)
            self.channel_to_server.redis.delete(k)

            #assert not self.channel_to_server.redis.keys("MQ_*")

    def add_client(self, client):
        if client not in self.channels.keys():
            ch = self._make_channel(to=client)
            #chRight = self.channelToServer
            self.channels[client] = ch

    def add_clients(self, clients):
        for c in clients:
            self.add_client(c)

    def send_server(self, client, message):
        
        ch = self.channel_to_server
        payload = (client, message)
        ch.write(payload)

    def receive_server(self, blocking=False, timeout=10):
        #logging.debug(" MQ receive_server")
        payload = self.channel_to_server.read(blocking, timeout)

        if not payload:
            logging.error("TIMEOUT")
            return None

        p = re.compile("\('(\w+)', (.+)\)")
        m = p.match(payload)
        assert m, "wrong format: %s" % m

        cmd, args = m.group(1), m.group(2)
        #logging.debug(" MQ read: %s args: %s" % (str(cmd), str(args)))
        #client, message = payload
        return cmd, args

    def send_client(self, client, message):
        if client not in self.channels.keys():
            print(" MQ error, sendClient, client not found: %s" %
                          self.channels)
        ch = self.channels[client]
        ch.write(message)

    def receive_client(self, client, blocking=False, timeout=60):
        assert (isinstance(client, str))
        if client not in self.channels.keys():
            print(" MQ error, receiveClient, client (%s) not found: %s" % (client, self.channels))
        ch = self.channels[client]
        message = ch.read(blocking, timeout)
        if not message:
            print("TIMEOUT")
        return message
    def make_iso(self, path):
        try:
            ret=os.system('mkisofs '+'-o /home/lee/win7-iso/win7.iso '+'-v '+path)
            if(ret):                
                os.system('chmod 777 /home/lee/win7-iso/win7.iso')
                return True
        except PermissionError:
            print('need admin')
            # network flags   
# VIR_CONNECT_LIST_NETWORKS_INACTIVE  =   1
# VIR_CONNECT_LIST_NETWORKS_ACTIVE    =   2
# VIR_CONNECT_LIST_NETWORKS_PERSISTENT    =   4
# VIR_CONNECT_LIST_NETWORKS_TRANSIENT =   8
# VIR_CONNECT_LIST_NETWORKS_AUTOSTART =   16
# VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART  =   32

#列出虚拟机状态标志位
# VIR_CONNECT_LIST_DOMAINS_ACTIVE =   1
# VIR_CONNECT_LIST_DOMAINS_INACTIVE   =   2
# VIR_CONNECT_LIST_DOMAINS_PERSISTENT =   4
# VIR_CONNECT_LIST_DOMAINS_TRANSIENT  =   8
# VIR_CONNECT_LIST_DOMAINS_RUNNING    =   16
# VIR_CONNECT_LIST_DOMAINS_PAUSED =   32
# VIR_CONNECT_LIST_DOMAINS_SHUTOFF    =   64
# VIR_CONNECT_LIST_DOMAINS_OTHER  =   128
# VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE    =   256
# VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE =   512
# VIR_CONNECT_LIST_DOMAINS_AUTOSTART  =   1024
# VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART   =   2048
# VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT   =   4096
# VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT    =   8192

#磁盘快照
# VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE =   1   
# 恢复或更改元数据
# VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT  =   2   
# 通过重新定义，使快照成为当前
# VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA  =   4   
# 制作快照而不记住它
# VIR_DOMAIN_SNAPSHOT_CREATE_HALT =   8   
# 快照后停止运行guest
# VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY    =   16  
# 磁盘快照，而不是系统检查点
# VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT    =   32  
# 重用任何现有的外部文件
# VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE  =   64  
# 使用来宾代理来停顿域中所有已挂载的文件系统
# VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC   =   128 
# 原子地避免部分变化
# VIR_DOMAIN_SNAPSHOT_CREATE_LIVE =   256 
# 在guest虚拟机运行时创建快照
#传送样本并校验，超过三次返回false
class send_file():
    def __init__(self):
        pass
    def send_file_agin(self,ip, channal, filepath):
        #print("3")
        virtual = vitMachine("null", "qemu:///system")
        #print("1")
        name = virtual.get_active_domian(1)
        print(name)
        #print("2")
        redis = StrictRedis("127.0.0.1", socket_timeout=None)
        for vitname in name: 
            print(vitname)   
            sendaginchannal = vitname + 'send_agin'
            while True:
                if redis.exists(sendaginchannal):       
                    mq_recive_agin = MQStar("127.0.0.1", sendaginchannal)
                    msg = mq_recive_agin.channel_to_server.read()
                    message = "".join(msg.split(',')[1:])
                    print(msg)
                    if message[2:-2] == "ok":            
                        ret.put("ok")
                        print("retput ok")  
                    elif message[2:-2] is not 'ok':
                        filemd5 = None
                        with open(filepath,'rb') as file:
                            filedata = file.read()
                            filemd5 = getfile_Md5(filedata)
                        if filemd5 == None:
                            ret.put("md5")
                        md5channal = channal + "MD5"
                        mq_file = RedisHelper(channal, ip)  
                        mq_file.publish(filedata)
                        mq_hash = RedisHelper(md5channal, ip)
                        mq_hash.publish(filemd5)            
            
                    else:
                        ret.put("error")
                    break

    def file_send_excute(self, usercmd, ip, channal, filepath, storefilepath):
                    
        if usercmd == 'client':
            print("start")
            filemd5 = None
            filedata = None
            with open(filepath,'rb') as file:
                filedata = file.read()
                filemd5 = getfile_Md5(filedata)
                
                file.close()
            if filemd5 == None:
                return False
            md5channal = channal + "MD5"
            print("s2")
            mq_file = RedisHelper(channal, ip)  
            mq_file.publish(filedata)
            print(filedata)
            mq_hash = RedisHelper(md5channal, ip)
            mq_hash.publish(filemd5)
            while True:
                client_thread = threading.Thread(target = self.send_file_agin, args=(ip, channal, filepath))
                client_thread.start()
            
                rets = None
                #print("ret")
                rets = ret.get()
                if rets == "ok":
                   # print(channal)
                    #return True
                   pass
                if rets  == "errors":
                    return False
                

        elif usercmd == 'server':
            sendaginchannal = channal + 'send_agin'
            md5channal = channal + "MD5"
            mq_server_file = RedisHelper(channal, ip)
            mq_server_fileMd5 = RedisHelper(md5channal, ip)
            file = mq_server_file.subscribe()
            filemd5 = mq_server_fileMd5.subscribe()
        
            while True:
                filedata = file.parse_response()
                filemd5data = filemd5.parse_response()
                if filedata and filemd5data:                
                    filemd5_check = getfile_Md5(filedata)
                    if filemd5 == filemd5_check:
                        mq_client = MQStar(ip, sendaginchannal)
                        mq_client.send_server(sendaginchannal, 'ok')
                        with open(storefilepath,'w') as fl:
                            fl.write(file)            
                        fl.close()
                    else:
                        print("file is bad,开始重传")
                   
                        id = 0
                        mq_client = MQStar(ip, sendaginchannal)
                        mq_client.send_server(sendaginchannal, id)
                        id += 1
                        if id >2:
                            return False
#发送和读取报告，主从模式


def send_report_info(ip ,channal, send_file_path):
    mq_client = MQStar(ip, channal)
    report = open(send_file_path,'rb').read()
    mq_client.send_server(channal, report)
def readinfo(channal, filepath):
    redis = StrictRedis("127.0.0.1", socket_timeout=None)
    
    if redis.exists(channal):
        mq_recive_update = MQStar("127.0.0.1", channal)
        message = mq_recive_update.channel_to_server.read()
        if message:
            with open(filepath,'w') as fl:
                fl.write(message)            
            fl.close()
def recieve_report(channal, filepath):
    
    client_thread = threading.Thread(target = readinfo, args=( channal, filepath))
    client_thread.start()
    while True:
        pass
        #if client_thread.get_result() == False:
          #  return False
        #else:
          #  return True
#对导入的虚拟机进行配置

def importvirtual_config(virtualname, connect, netflag,nettype, networkname, snapshotname, snaptype):
    importvirtual = vitMachine(virtualname, connect)
    importvirtual.destory_all_network(netflag)
    importvirtual.nat_network(networkname, 'vlan')
    importvirtual.is_powered_on()
    netset.create_snapshot(snapshotname, snaptype)




#更新类
class update_virtual():
    def __init__(self):
        parser = argparse.ArgumentParser(description='get help')   
        parser.add_argument('-updatevirtual', action="store_true", help='update_time at clock')
        parser.add_argument('-update_time', nargs='*', help='update_time at clock')
        parser.add_argument('-update_ip', nargs='?', help='the virtualmachine you want update')
        #parser.add_argument('-networkflags', type = int,nargs='?', help='flag of network')
        #parser.add_argument('-networkname', nargs='?', help='update_time at clock')
        parser.add_argument('-virtualname', nargs='*', help='the update virtual ')
        parser.add_argument('-connection', nargs='?', help='connect the virtual machine')
        parser.add_argument('-snapname', nargs='?', help='the snapshot name')
        parser.add_argument('-snaptype', nargs='?', type = int,help='the snapshot type')
        
        args = parser.parse_args()
        self.updatevirtual = args.updatevirtual
        self.update_time = "".join(args.update_time[0])+" "+"".join(args.update_time[1])
        self.update_ip = args.update_ip
        #self.networkflags = args.networkflags
        #self.networkname = args.networkname
        self.virtualname = args.virtualname
        self.connection = args.connection
        self.snapname = args.snapname
        self.snaptype = args.snaptype
        print(self.updatevirtual)
        print(self.update_time)
        print(self.update_ip)
        #print(self.networkflags)
        #print(self.networkname)
        print(self.virtualname)
        print(self.connection)
        print(self.snapname)
        print(self.snaptype)
        print("over")
    def excute(self):
        channal = "update_over"
        if self.updatevirtual:
            self.update_virtualmachine(self.update_time, self.update_ip, channal,  self.virtualname, self.connection)
            
    def delay(self):
        a = None
        
    def update_virtualmachine(self, date, ip , channal,virtualname, connect): 
        for machine in virtualname: 
            machinestr="".join(machine)         
            netset = vitMachine(machinestr, connect)
        #runningmachine = netset.get_active_domian(16)
            netset.change_network("test8")

        #netset.destory_all_network(netflags)
        
        scheduler = BlockingScheduler()
        job = scheduler.add_job(func=self.update_machine, trigger='date', run_date=date, args=[ip, channal, virtualname])
        
        scheduler.start()
        
        print("eeee")
        return True
    def update_machine(self, ip, channal,virtualname):
        print("开始更新")
        print("over")
        channal = "update_over"
        redis = StrictRedis("127.0.0.1", socket_timeout=None)
        while True:            
            
            if redis.exists(channal):
                mq_recive_update = MQStar("127.0.0.1", channal)
                msg = mq_recive_update.channel_to_server.read()
                print(msg)
                message = "".join(msg.split(',')[1:])
                print(message[2:-2])
                if message[2:-2] == "ok":
                    for machine in virtualname: 
                        machinestr="".join(machine)         
                        netset = vitMachine(machinestr, self.connection)
                    #netset = vitMachine(self.virtualname, self.connection)
                    #print("jinqu ok")
                        netset.is_powered_off()
                    time.sleep(10)    
                    print("dely over")
                    #if virtualname == "win7":
                    for machine in virtualname: 
                        machinestr="".join(machine)         
                        netset = vitMachine(machinestr, self.connection)
                        netset.change_network("test10")
                    #elif virtualname == "win7-copy1":
                       # netset.change_network("test11")
                   # elif virtualname == "win7-copy2":
                       # netset.change_network("test12")
                    #time.sleep(20)
                        #netset.create_snapshot(self.snapname, self.snaptype)
                    
                    #snapnum = netset.get_snapshots()
                    
                    #if len(snapnum) > 2:
                        #netset.delete_snapshot(snapnum[0])
                    #
                    
                    
                    #change_network("test9")
                    return True
def update_over(): 
    channal = "update_over"
    message = 'ok'
    mq_update = MQStar(ip, channal)
    mq_update.send_server(channal,message)
        
    


if __name__ == '__main__':
    #parser = argparse.ArgumentParser(description='get help') 
    #parser.add_argument('-ip', nargs='?', help='connect the virtual machine')
    #parser.add_argument('-usercmd', nargs='?', help='connect the virtual machine') 
    #parser.add_argument('-chnnal', nargs='*', help='connect the virtual machine')
    #parser.add_argument('-filepath', nargs='?', help='connect the virtual machine')
    #parser.add_argument('-storefilepath', nargs='?', help='connect the virtual machine')
    #args = parser.parse_args()
    #print(args.chnnal)
    #for vitualNumber in args.chnnal:
      #  print(vitualNumber)
       # test = send_file()
        #test.file_send_excute(args.usercmd, args.ip, vitualNumber, args.filepath, args.storefilepath)
    #cmd = tuple(sys.argv[1:])
    #print(cmd)
    #if len(cmd) != None:
        #test = send_file()
        #test.file_send_excute(*cmd)
    virtual = vitMachine("null", "qemu:///system")
        #print("1")
    name = virtual.get_active_domian(1)
    
    recieve_report("report", "/home/lee/report.txt")
    #test = update_virtual()
    #test.excute()
    #f = open('test.txt','rb').read()
    #mq = MQStar("127.0.0.1", '2')
    #s = mq._make_channel()
    #mq.send_server('client1',f)
    #recive=s.read()
    #print(recive)
    #mq2 = MQStar("192.168.2.139", '2')
    #mq2.send_server('client2',recive)
    



