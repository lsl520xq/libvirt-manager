#!/usr/bin/env python  
#-*- coding:utf-8 -*-  
import redis  
  
class RedisHelper(object):  
    def __init__(self,chansl,ip):  
        self.__conn = redis.Redis(host=ip,port=6379)#连接Redis  
        self.channel = chansl #定义名称  
  
    def publish(self,msg):#定义发布方法  
        self.__conn.publish(self.channel,msg)  
        return True  
  
    def subscribe(self):#定义订阅方法  
        pub = self.__conn.pubsub()  
        pub.subscribe(self.channel)  
        pub.parse_response()  
        return pub
if __name__ == '__main__':
    obj = RedisHelper()  
    obj.publish('hello')#发布    
    