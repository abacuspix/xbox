 #!/usr/bin/env python 
# -*- coding: utf-8 -*-
#
# @author: wei.yang <wei.yang@jinmuinfo.com>
# Created on 2017/06/22
#    raid模块:
#    1、查看raid卡信息(包括控制器状态、Cache状态、电池状态) (raid_card)
#    2、查看raid详细信息 （raid_detail）
#    3、查看raid状态 (raid_status)
#    4、查看物理硬盘状态 (raid_status)
#    5、创建raid (create_raid)
#    6、删除raid (delete_raid)

from ops.sshapi import remote_cmd
from .models import Disk
import re

class RAIDAPI(object):
    def __init__(self,obj,addr,user='root',passwd='P@ssw0rd'):
        self.user = user
        self.passwd = passwd
        self.addr = addr
        self.obj = obj
    
    def raid_card(self):
        # 查看raid卡信息(包括控制器状态、Cache状态、电池状态)
        ret = {'status':False,'result':''}
        if self.obj.vendor in ['HP','Hewlett-Packard']:
            cmd = "/opt/ssacli/bin/ssacli ctrl all show status"
            try:
                ret = remote_cmd(cmd,self.addr,user=self.user,passwd=self.passwd)
            except Exception as e:
                ret['result'] = str(e)
        else:
            ret['result'] = "暂时不支持该品牌，请联系管理员，我们会尽快加入支持。"
        return ret
    
    def raid_detail(self):
        # 查看raid详细信息
        ret = {'status':False,'result':''}
        if self.obj.vendor in ['HP','Hewlett-Packard']:
            cmd = "/opt/ssacli/bin/ssacli ctrl slot=%s show config detail"%(self.obj.raid_adapter_slot)
            try:
                ret = remote_cmd(cmd,self.addr,user=self.user,passwd=self.passwd)
            except Exception as e:
                ret['result'] = str(e)
        else:
            ret['result'] = "暂时不支持该品牌，请联系管理员，我们会尽快加入支持。"
        return ret

    def raid_status(self):
        # 查看raid状态
        ret = {'status':False,'result':''}
        if self.obj.vendor in ['HP','Hewlett-Packard']:
            cmd = "/opt/ssacli/bin/ssacli ctrl slot=%s ld all show"%(self.obj.raid_adapter_slot)
            try:
                ret = remote_cmd(cmd,self.addr,user=self.user,passwd=self.passwd)
            except Exception as e:
                ret['result'] = str(e)
        else:
            ret['result'] = "暂时不支持该品牌，请联系管理员，我们会尽快加入支持。"
        return ret

    def raid_disk(self):
        # 查看物理硬盘状态
        ret = {'status':False,'result':''}
        if self.obj.vendor in ['HP','Hewlett-Packard']:
            cmd = "/opt/ssacli/bin/ssacli ctrl slot=%s pd all show"%(self.obj.raid_adapter_slot)
            try:
                ret = remote_cmd(cmd,self.addr,user=self.user,passwd=self.passwd)
            except Exception as e:
                ret['result'] = str(e)
            if self.obj.disk_set.all():
                self.obj.disk_set.all().delete()
            if ret.find('physicaldrive'):
                cmd1 = "/opt/ssacli/bin/ssacli ctrl slot=%s pd all show status"%(self.obj.raid_adapter_slot)
                ret = remote_cmd(cmd1,self.addr,user=self.user,passwd=self.passwd)
                ph_drivers = ret1.strip('\n').split('\n')
                for driver in ph_drivers:
                    item = driver.split()
                    disk = Disk.objects.create(name=item[1],server_id=self.obj.id,size=item[6],status=item[8])
                    disk.save()            
        else:
            ret['result'] = "暂时不支持该品牌，请联系管理员，我们会尽快加入支持。"    
        return ret

    def create_raid(self,drivers,raid_type):
        # 创建raid
        ret = {'status':False,'result':''}
        if self.obj.vendor in ['HP','Hewlett-Packard']:
            cmd = "/opt/ssacli/bin/ssacli ctrl slot=%s create type=ld drives=%s raid=%s forced"%(self.obj.raid_adapter_slot,drivers,raid_type)
            try:
                ret = remote_cmd(cmd,self.addr,user=self.user,passwd=self.passwd)
                if re.search('Error',ret['result']):
                    ret = {'status':False,'result':ret['result']}
            except Exception as e:
                ret['result'] = str(e)
        else:
            ret['result'] = "暂时不支持该品牌，请联系管理员，我们会尽快加入支持。"      
        return ret

    def delete_raid(self,array):  
        # 删除raid
        ret = {'status':False,'result':''}
        if self.obj.vendor in ['HP','Hewlett-Packard']:
            cmd = "/opt/ssacli/bin/ssacli ctrl slot=%s array %s delete forced"%(self.obj.raid_adapter_slot,array)
            try:
                ret = remote_cmd(cmd,self.addr,user=self.user,passwd=self.passwd)
                if re.search('Error',ret['result']):
                    ret = {'status':False,'result':ret['result']}                
            except Exception as e:
                ret['result'] = str(e)
        else:
            ret['result'] = "暂时不支持该品牌，请联系管理员，我们会尽快加入支持。"         
        return ret
