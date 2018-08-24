#!/usr/local/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from xml.dom import minidom
from vitMachine import vitMachine
import datetime
import libvirt
import sys

import os

class virtual_execute(object):
    """docstring for virtual_execute"""
    def __init__(self):
        pass
    def execute(self, vm_name, connect, cmd, *args):

        vmachine_cmds = ["startup", "shutdown", "reboot",
                     "get_snapshots", "revert_last_snapshot", "revert_to_snapshot", "create_snapshot","list_definenetwork","network_DefineXML","update_network","list_allnetwork",
                     "destory_all_network","get_active_domian","mount_disk_file",
                      "update_netinteface","change_network",
                     "delete_snapshot","nat_network","list_networks","destory_network",
                     "is_powered_on", "is_powered_off", "get_status",
                     "list_directory", "make_directory", "get_file", "send_file", "list_processes"]
        print(cmd)
        try:
            vm = vitMachine(vm_name, connect)
            if cmd in vmachine_cmds:
                fuc = getattr(vm, cmd)
                if not args:
                    fuc()
                else:
                    fuc(*args)
            else:
            #logging.error("command not found: %s" % cmd)
                raise Exception("Command not found")
        except AssertionError as ae:
        #l#ogging.error("Assertion found: %s" % ae)
            raise 
        except Exception as e:
        #logging.error("Exception found. %s" % e)
            raise  
        




if __name__ == '__main__':
	#logging.debug("args: %s" % str(sys.argv[1:]))
    t = tuple(sys.argv[1:])
    test = virtual_execute()
    ret = test.execute(*t)







