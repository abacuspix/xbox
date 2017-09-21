# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from opsdb.models import Cabinet,Contacter

class ServerStatus(models.Model):
    id                 = models.AutoField(primary_key=True,db_column="server_status_id")
    status_type        = models.CharField(max_length=50,blank=True,null=True,db_column="server_status_type")
    name               = models.CharField(max_length=100,blank=True,null=True,db_column="server_status_name")
    class Meta:
        db_table = 'server_status'

    def __unicode__(self):
        return self.status_type

class Tag(models.Model):
    id                 = models.AutoField(primary_key=True,db_column="tag_id")
    tag_type           = models.CharField(max_length=10,blank=True,null=True)
    description        = models.CharField(max_length=30,blank=True,null=True)

    class Meta:
        db_table = 'tag'

    def __unicode__(self):
        return self.tag_type           

class Server(models.Model):
    id                 = models.CharField(max_length=100,primary_key=True,db_column="server_id")
    sn                 = models.CharField(max_length=100,blank=True,null=True)
    cpu_model          = models.CharField(max_length=100,blank=True,null=True)
    cpu_sockets        = models.IntegerField(blank=True,null=True)
    cpu_cores          = models.IntegerField(blank=True,null=True)
    cpu_threads        = models.IntegerField(blank=True,null=True)
    mem_size           = models.IntegerField(blank=True,null=True)
    mem_total_slots    = models.IntegerField(blank=True,null=True)
    mem_free_slots     = models.IntegerField(blank=True,null=True)
    raid_adapter       = models.CharField(max_length=200,blank=True,null=True)
    raid_adapter_slot  = models.CharField(max_length=20,blank=True,null=True)
    cabinet            = models.ForeignKey(Cabinet,blank=True, null=True,on_delete=models.PROTECT)
    serverstatus       = models.ForeignKey(ServerStatus,blank=True, null=True,on_delete=models.PROTECT)
    ipmi_ip            = models.GenericIPAddressField(blank=True,null=True)
    ipmi_user          = models.CharField(max_length=30,blank=True,null=True)
    ipmi_pass          = models.CharField(max_length=30,blank=True,null=True)
    tag                = models.ForeignKey(Tag,blank=True, null=True,on_delete=models.PROTECT)
    unit               = models.IntegerField(blank=True,null=True)
    contacter          = models.ForeignKey(Contacter,blank=True, null=True,on_delete=models.PROTECT)
    pxe_mac            = models.CharField(max_length=30,blank=True,null=True)
    pxe_ip             = models.GenericIPAddressField(blank=True,null=True)
    vendor             = models.CharField(max_length=30,blank=True,null=True)
    model              = models.CharField(max_length=30,blank=True,null=True)
    prod_ip            = models.GenericIPAddressField(blank=True,null=True)
    power              = models.CharField(max_length=10,blank=True,null=True,default='on')
    create_time        = models.DateTimeField(auto_now_add=True)
    update_time        = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'server'
        ordering = ['-create_time']

    def __unicode__(self):
        return self.id

class Disk(models.Model):
    id                 = models.AutoField(primary_key=True,db_column="disk_id")
    path               = models.CharField(max_length=30,blank=True,null=True,db_column="disk_name")
    dtype              = models.CharField(max_length=30,blank=True,null=True,db_column="disk_model")
    server             = models.ForeignKey(Server)
    raid_name          = models.CharField(max_length=100,blank=True,null=True)
    raid_type          = models.CharField(max_length=100,blank=True,null=True)
    size               = models.CharField(max_length=30,blank=True,null=True,db_column="disk_size")

    class Meta:
        db_table = 'disk'

    def __unicode__(self):
        return self.path

class Nic(models.Model):
    id                 = models.AutoField(primary_key=True,db_column="nic_id")
    name               = models.CharField(max_length=20,blank=True,null=True,db_column="nic_name")
    mac                = models.CharField(max_length=50,blank=True,null=True,db_column="mac")
    model              = models.CharField(max_length=100,blank=True,null=True,db_column="nic_model")
    server             = models.ForeignKey(Server)

    class Meta:
        db_table = 'nic'
    
    def __unicode__(self):
        return self.mac

class PreSystem(models.Model):
    ip                 = models.GenericIPAddressField(blank=True,null=True,unique=True)
    name               = models.CharField(max_length=50,blank=True,null=True)
    hostname           = models.CharField(max_length=50,blank=True,null=True)
    mac                = models.CharField(max_length=50,blank=True,null=True)
    profile            = models.CharField(max_length=50,blank=True,null=True)
    progress           = models.IntegerField(blank=True,null=True,default=-1)
    server             = models.OneToOneField(Server)
    create_time        = models.DateTimeField(auto_now_add=True)
    update_time        = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'pre_system'
        ordering = ['-create_time']
    
    def __unicode__(self):
        return self.profile

class Vcenter(models.Model):
    name               = models.CharField(max_length=50,blank=True,null=True)
    ip                 = models.GenericIPAddressField(blank=True,null=True,unique=True)
    port               = models.CharField(max_length=10,default='443')
    user               = models.CharField(max_length=50,blank=True,null=True)
    password           = models.CharField(max_length=50,blank=True,null=True)

    class Meta:
        db_table = 'vcenter'
    
    def __unicode__(self):
        return self.name

class Datastore(models.Model):
    name               = models.CharField(max_length=50,blank=True,null=True)
    capacity           = models.CharField(max_length=50,blank=True,null=True)
    free_space         = models.CharField(max_length=50,blank=True,null=True)
    provisioned        = models.CharField(max_length=50,blank=True,null=True)
    uncommitted        = models.CharField(max_length=50,blank=True,null=True)
    hosts              = models.IntegerField(blank=True,null=True,default=0)
    vms                = models.IntegerField(blank=True,null=True,default=0)
    vcenter            = models.ForeignKey(Vcenter,blank=True, null=True)

    class Meta:
        db_table = 'vm_datastore'
    
    def __unicode__(self):
        return self.name

class Datacenter(models.Model):
    name               = models.CharField(max_length=50,blank=True,null=True)
    vcenter            = models.ForeignKey(Vcenter,blank=True,null=True)

    class Meta:
        db_table = 'vm_datacenter'
    
    def __unicode__(self):
        return self.name
          
class Cluster(models.Model):
    name               = models.CharField(max_length=50,blank=True,null=True)
    datacenter         = models.ForeignKey(Datacenter,blank=True, null=True)

    class Meta:
        db_table = 'vm_cluster'
    
    def __unicode__(self):
        return self.name

class VmHost(models.Model):
    ip                 = models.GenericIPAddressField(blank=True,null=True,unique=True)    
    cluster            = models.ForeignKey(Cluster,blank=True, null=True)
    server             = models.OneToOneField(Server,blank=True, null=True)

    class Meta:
        db_table = 'vm_host'
    
    def __unicode__(self):
        return self.ip

class Guest(models.Model):
    name               = models.CharField(max_length=50,blank=True,null=True)
    annotation         = models.CharField(max_length=200,blank=True,null=True)
    cpu                = models.IntegerField(blank=True,null=True,default=0)
    diskGB             = models.CharField(max_length=50,blank=True,null=True)
    folder             = models.CharField(max_length=50,blank=True,null=True)
    mem                = models.IntegerField(blank=True,null=True,default=0)
    ostype             = models.CharField(max_length=50,blank=True,null=True)
    path               = models.CharField(max_length=50,blank=True,null=True)
    status             = models.CharField(max_length=50,blank=True,null=True)
    is_template        = models.BooleanField(default=False)
    host               = models.ForeignKey(VmHost,blank=True, null=True)
    datastore          = models.ForeignKey(Datastore,blank=True, null=True)

    class Meta:
        db_table = 'vm_guest'
    
    def __unicode__(self):
        return self.name

class Vnet(models.Model):
    mac                = models.CharField(max_length=50,primary_key=True)
    connected          = models.CharField(max_length=50,blank=True,null=True)
    ip                 = models.GenericIPAddressField(blank=True,null=True,unique=True)
    netlabel           = models.CharField(max_length=100,blank=True,null=True)
    prefix             = models.CharField(max_length=50,blank=True,null=True)   
    guest              = models.ForeignKey(Guest,blank=True, null=True)

    class Meta:
        db_table = 'vm_guest_net'
    
    def __unicode__(self):
        return self.mac

class Cobbler(models.Model):
    ip                 = models.GenericIPAddressField(blank=True,null=True,unique=True)
    port               = models.IntegerField(blank=True,null=True,default=80)
    user               = models.CharField(max_length=50,blank=True,null=True)
    password           = models.CharField(max_length=50,blank=True,null=True)

    class Meta:
        db_table = 'cobbler'
    
    def __unicode__(self):
        return self.ip









