#!/usr/local/bin/python
# -*- coding: utf-8 -*-
from xml.dom import minidom
from time import sleep
from datetime import datetime
import libvirt
from libvirt import virNetwork
import os
import xml.etree.ElementTree as ET
class ConetSphere:
    """docstring for ConetSphere"""
    def __init__(self, vm_connection,):
        self.vm_connection = vm_connection
        
    def __enter__(self):
        self.conn = libvirt.open(self.vm_connection)
        if self.conn == None:
            print ('Failed to open connection to the hypervisor')
            raise Exception("Failed to open connection")
       
        return self.conn

    def __exit__(self, type, value, traceback):
        assert self.conn
        try:
            self.conn.close()
        except :
            #logging.debug("Problem in disconnection. Fault is: %s" % e.fault)
            print ('Problem in disconnection') 
            pass
        
        
class vSphere:
    def __init__(self, vm_connection, vm_name):
        self.vm_connection = vm_connection
        self.vm_name = vm_name
        

    def __enter__(self):
        self.conn = libvirt.open(self.vm_connection)
        if self.conn == None:
            print ('Failed to open connection to the hypervisor')
            raise Exception("Failed to open connection")
        try:
            vm_dom = self.conn.lookupByName(self.vm_name)
        except:
            print ('Failed to find the main domain')                
            raise
        return vm_dom

    def __exit__(self, type, value, traceback):
        assert self.conn
        try:
            self.conn.close()
        except :
            #logging.debug("Problem in disconnection. Fault is: %s" % e.fault)
            print ('Problem in disconnection') 
            pass
class vitMachine:
    def __init__(self, name, connection):
        self.name = name
        self.connection = connection
    def __str__(self):
        return "%s" % self.name

   #   TASKS
    def mount_disk_file(self,flag):
        disk = """<disk type='file' device='cdrom'>
                     <driver name='qemu' type='raw'/>
                    <source file='/home/lee/win7-iso/win7.iso'/>
                   <target dev='hdc' bus='ide'/>
                 <readonly/>
                     <address type='drive' controller='0' bus='1' target='0' unit='0'/>
                 </disk>"""
        disk2="""<disk type='file' device='disk'>
                   <driver name='qemu' type='qcow2' cache='writeback'/>
              <source file='/home/lee/win7-iso/win7.img'/>
                 <target dev='vdc' bus='virtio'/>
              <address type='pci' domain='0x0000' bus='0x00' slot='0x08' function='0x0'/>
              </disk> """
        with vSphere(self.connection, self.name) as vm_dom:
            #self._run_vm(vm_dom, 'attachDeviceFlags',disk,int(flag))
        #with vSphere(self.connection, self.name) as vm_dom:
            self._run_vm(vm_dom, 'attachDeviceFlags',disk,int(flag))
    def list_allnetwork(self, flag):
        with ConetSphere(self.connection) as conet:
            print(self._run_vm(conet, 'listAllNetworks', int(flag)))
    def destory_all_network(self, flag):
        with ConetSphere(self.connection) as conet:
            vir_network = self._run_vm(conet, 'listAllNetworks', int(flag))
            for net in vir_network:
                self._run_vm(net, 'destroy')
    def update_network(self, networkname, type, command, updatesection, updateflag):
        natnetworkxml = """ <network>
                           <name>%s</name>
                              <bridge name="virbr2" />
                          <forward mode="nat"/>
                        <ip address="10.0.100.1" netmask="255.255.255.0">
                             <dhcp>
                          <range start="10.0.100.2" end="10.0.100.254" />
                        </dhcp>
                      </ip>
                       </network> """ % (networkname)
        with open(networkname + '.xml','w') as fl:
            if type == "nat":
                print("open successful")
                fl.write(natnetworkxml)
            
            fl.close()
            netxml = open(networkname + '.xml','rb').read()
            print(netxml)
            with ConetSphere(self.connection) as conet:
                iface = self._run_vm(conet, 'interfaceLookupByName', networkname)
                net = virNetwork(conet, iface)
                self._run_vm(net, 'update', int(command), int(updatesection),-1, netxml, updateflag)
    def network_DefineXML(self,networkname, type):
        natnetworkxml = """ <network>
                           <name>%s</name>
                              <bridge name="vr" />
                          <forward mode="nat"/>
                        <ip address= "10.0.100.2"s netmask="255.255.255.0">
                             <dhcp>
                          <range start="10.1.100.2" end="10.1.100.254" />
                        </dhcp>
                      </ip>
                       </network> """ % (networkname)
        vlannetworkxml = """ <network>
                     <name>%s</name>
                  <bridge name="v778"/>
                 <forward mode="route" dev="eth1"/>
                <ip address="10.0.100.2" netmask="255.255.255.0">
                 <dhcp>
                        <range start="10.0.100.2" end="10.0.100.254"/>
                   </dhcp>
                         </ip>
                 <ip family="ipv6" address="2001:db8:ca2:2::1" prefix="64"/>
                      </network>""" % (networkname)
        with open(networkname + '.xml','w') as fl:
            if type == "nat":
                print("open successful")
                fl.write(natnetworkxml)
            elif type == "vlan":
                fl.write(vlannetworkxml)
            fl.close()
            netxml = open(networkname + '.xml','rb').read()
            #print(netxml)
            with ConetSphere(self.connection) as conet:
                network = self._run_vm(conet, 'networkDefineXML', netxml)
            assert network
            if network.isActive() != 1:
                network.create()
                #self._run_vm(network, 'update', int(command), int(updatesection),-1, netxml, updateflag)
                        #if network.isActive() == 1:
                            #network.destroy()
            else:
                print("network is activty")
                        #net = virNetwork(conet,self, network)
    def list_definenetwork(self):
        with ConetSphere(self.connection) as conn:
            print(self._run_vm(conn, 'listDefinedNetworks'))
    def update_netinteface(self, netname):
        xml = """"
         <interface type='ethernet' name='eth0'>
  <start mode='onboot'/>
  <mac address='aa:bb:cc:dd:ee:ff'/>
  <protocol family='ipv4'>
    <ip address="192.168.0.5" prefix="24"/>
    <route gateway="192.168.0.1"/>
  </protocol>
</interface>"""
        print(xml)
        with ConetSphere(self.connection) as conn:
            iface = self._run_vm(conn, 'interfaceDefineXML', xml, 0)
            assert iface
            iface.create(0)
    def destory_network(self, networkname):
        with ConetSphere(self.connection) as conn:
            iface = self._run_vm(conn, 'interfaceLookupByName', networkname)
            assert iface
            self._run_vm(iface, 'destroy')
    def nat_network(self, networkname, type,command, updatesection, updateflag):
        natnetworkxml = """ <network>
                           <name>%s</name>
                              <bridge name="vir2" />
                          <forward mode="nat"/>
                        <ip address="10.0.100.1" netmask="255.255.255.0">
                             <dhcp>
                          <range start="10.0.100.2" end="10.0.100.254" />
                        </dhcp>
                      </ip>
                       </network> """ % (networkname)

        vlannetworkxml = """
                 <name>%s</name>
                  <bridge name="route1"/>
                 <forward mode="route" dev="eth1"/>
                <ip address="10.0.100.1" netmask="255.255.255.0">
                 <dhcp>
                        <range start="10.0.100.2" end="10.0.100.254"/>
                   </dhcp>
                         </ip>
                 <ip family="ipv6" address="2001:db8:ca2:2::1" prefix="64"/>
                      </network>""" % (networkname)
        with open(networkname + '.xml','w') as fl:
            if type == "nat":
                fl.write(natnetworkxml)
            if type == "vlan":
                fl.write(vlannetworkxml)
            fl.close()
            netxml = open(networkname + '.xml','rb').read()
            #print(netxml)
            with ConetSphere(self.connection) as conet:
                network = self._run_vm(conet, 'networkCreateXML', netxml)
                if network is None:
                    print("create natnetwork faild")
                else:
                    if network.isActive() != 1:
                        network.create()
                        #if network.isActive() == 1:
                            #network.destroy()
                    else:
                        print("network is activty")
                        #net = virNetwork(conet,self, network)
                        print(int(command))
                        self._run_vm(network, 'update', int(command), int(updatesection),-1, netxml, updateflag)
                

    def list_networks(self):
        with ConetSphere(self.connection) as conn:
            print(self._run_vm(conn, 'listNetworks'))
 
    def revert_last_snapshot(self):
        try:
            with vSphere(self.connection, self.name) as vm_dom:
                currentsnapobj = _run_vm(vm_dom, 'snapshotCurrent')
                if currentsnapobj is None:
                    if _run_vm(vm_dom, 'revertToSnapshot', currentsnapobj) is None:
                        return True
                    else:
                        return False
                else:
                    return False
        except:
            raise
    def list_ChildrenSnapshot_Name(self):
        try:
            with vSphere(self.connection, self.name) as vm_dom:
                snapobj = _run_vm(vm_dom, 'snapshotLookupByName', snapshotname, flags = None)
                if snapobj is None:
                    retname = _run_vm(vm_dom, 'listChildrenNames', snapobj)
                    if retname is not None:
                        print(retname)
                    else:
                        print('None')
                else:
                    return False
        except:
            raise

    def delete_snapshot(self, snapshotname):
        try:
            with vSphere(self.connection, self.name) as vm_dom:
                snapobj = _run_vm(vm_dom, 'snapshotLookupByName', snapshotname, flags = None)
                if snapobj is None:
                    if _run_vm(vm_dom, 'delete', snapobj) is None:
                        return True
                    else:
                        return False
                else:
                    return False
        except:
            raise
    def get_status(self):
        info = self._run_cmd("info")
        print(info)
    def change_network(self, netname):
        try:           
            with vSphere(self.connection, self.name) as vm_dom:
                xmldesc = vm_dom.XMLDesc(0)
                with open('main.xml','w') as fl:           
                    fl.write(xmldesc)
                    fl.close()
                tree = ET.parse('main.xml')
                root = tree.getroot()
                for neighbor in root.iter("source"):
                    if neighbor.attrib.has_key("network"):
                        neighbor.set("network", netname)
                tree.write("xmltest.xml")
                snapxml = open("xmltest.xml",'rb').read()               
            conn = libvirt.open(self.connection)
            dom = self._run_vm(conn, 'defineXML', snapxml)
            if self._run_vm(dom, 'create') < 0:
                conn.close()
                return False
            else:
                conn.close()
                return True
        except:
            raise
    def is_powered_off(self):
        if self._run_cmd("shutdown") is None:
            return True
        else:
            return False
    def get_active_domian(self, Id):
        runmachine = []
        with ConetSphere(self.connection) as conn:
            domians=self._run_vm(conn, 'listAllDomains', int(Id))
            if len(domians) != 0:
                for domian in domians:
                    runmachine.append(domian.name())
                return runmachine

    def get_snapshots(self, Id):
        return self._run_cmd("snapshotListNames", int(Id))
    def create_snapshot(self, snapshotname, snapshottype):

        try:
            with vSphere(self.connection, self.name) as vm_dom:
                xmldesc = vm_dom.XMLDesc(0)
                doc = minidom.parseString(xmldesc)
                disks = doc.getElementsByTagName('disk')
                diskfile = []
                for disk in disks:
                    if disk.getAttribute('device') == 'disk':
                        diskfile = disk.getElementsByTagName('source')[0].getAttribute('file') 
                xml = """<domainsnapshot>               
                <name>%s</name>                
                <description>libvirtapi</description>                       
                <disk   name='%s'>                
                </disk>               
                </domainsnapshot>""" % (snapshotname,diskfile)
                
                with open(snapshotname + '.xml','w') as fl:                
                    fl.write(xml)
                snapxml = open(snapshotname + '.xml','rb').read()
                return self._run_vm(vm_dom, 'snapshotCreateXML', snapxml, int(snapshottype)) 
        except Exception as e:
            raise
    def revert_to_snapshot(self, snapshotname):
        try:
            with vSphere(self.connection, self.name) as vm_dom:
                snapobj = _run_vm(vm_dom, 'snapshotLookupByName', snapshotname, flags = None)
                if snapobj is None:
                    if _run_vm(vm_dom, 'revertToSnapshot', snapobj) is None:
                        return True
                    else:
                        return False
                else:
                    return False
        except:
            raise

    def _run_vm(self, vm, func, *params):
        print(params)
        try:
            f = getattr(vm, func)

            if len(params) is None:
                return f
            else:
                return f(*params)
        except Exception as e:
            #logging.exception("%s, ERROR: Problem running %s" % (self.name, func))
            raise

    def _run_cmd(self, fuc, *params):
        try:
            with vSphere(self.connection, self.name) as vm_dom:
                f = getattr(vm_dom, fuc)
                if len(params) is None:
                    return f
                else:

                    return f(*params)
        except Exception as e:
            raise

    def _run_task(self, func, *params):

        def wait_for(task):
            s = task.wait_for_state(['success', 'error'])

            if s == 'error':
                logging.error("ERROR: problem with task %s: %s" % (func, task.get_error_message()))
                return False
            return True

        try:
            with vSphere(self.connection, self.name) as vm_dom:
                f = getattr(vm_dom, func)
                if len(params) is None:
                    task = f()
                else:
                    task = f(*params)
                return wait_for(task)
        except Exception as e:
            logging.error("%s, ERROR: Problem running %s. Reason: %s" % (self.name, func, e))
            raise
		




