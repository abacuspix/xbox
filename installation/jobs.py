#!/usr/bin/env python 
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals
import time
from .models import Vcenter,Datastore,Datacenter,Cluster,Host,Guest,Vnet,Server,ServerStatus
from .getvmsbycluster import get_vms_by_cluster
from .getdatastorebyname import get_ds_from_vcenter
from .clone_vm import create_vm_by_template
from ops.ipmi_api import ipmitool
from django.shortcuts import get_object_or_404
from django_rq import job

@job
def get_info_from_vcenter(vc_id,user,password,ip,port=443):
	'''
	return vms by cluster
	'''
	vc = Vcenter.objects.get(pk=vc_id)
	vcenter = get_vms_by_cluster(user,password,ip,port)
	if vcenter:
		for datacenter,clusters in vcenter.items():
			dc,created = Datacenter.objects.get_or_create(name=datacenter)
			if dc:
				dc.vcenter = vc
				dc.save()
				for cluster,hosts in clusters.items():
					clu,created = Cluster.objects.get_or_create(name=cluster)
					if clu:
						clu.datacenter = dc
						clu.save()
						for host,vms in hosts.items():
							ht,created = Host.objects.get_or_create(ip=host)
							if ht:
								ht.cluster = clu
								try:
									status = ServerStatus.objects.get(status_type='running')
									server = Server.objects.get(prod_ip=host,serverstatus_id=status.id)
									ht.server = server
								except Exception as e:
									# raise e
									pass
								finally:
									ht.save()
								for name,vm in vms.items():
									guest,created = Guest.objects.update_or_create(name=name,\
										defaults={'annotation':vm['annotation'],\
										'cpu':vm['cpu'],\
										'diskGB':vm['diskGB'],\
										'folder':vm['folder'],\
										'mem':vm['mem'],\
										'ostype':vm['ostype'],\
										'status':vm['state'],\
										'is_template':vm['is_template']})

									if guest:
										l = vm['path'].split()
										dt = l[0].strip('[]')
										ds,created = Datastore.objects.get_or_create(name=dt,vcenter_id=vc.id)
										if ds:
											guest.datastore = ds
											datastore = get_ds_from_vcenter(ds.name,user,password,ip,port)
											if datastore:
												ds.capacity = datastore.get('capacity','')
												ds.free_space = datastore.get('free_space','')
												ds.provisioned = datastore.get('provisioned','')
												ds.free_space = datastore.get('capacity','')
												ds.uncommitted = datastore.get('uncommitted','')
												ds.hosts = datastore.get('hosts','')
												ds.vms = datastore.get('vms','')
												ds.save()
										guest.path = l[1]
										guest.host = ht
										guest.save()
										if vm['net']:
											for mac,net in vm['net'].items():
												vnet,created = Vnet.objects.get_or_create(mac=mac)
												vnet.connected = net.get('connected','')
												vnet.ip = net.get('ip','')
												vnet.netlabel = net.get('netlabel','')
												vnet.prefix = net.get('prefix','')
												vnet.guest = guest
												vnet.save()

@job
def clone_vm(vcenter_id,vcenter_ip,vcenter_user,vcenter_password,vcenter_port,template,vm_name,\
	datacenter_name,datastore_name,cluster_name,power_on,vm_cpus, vm_cpu_sockets, vm_memory):
	'''
	clone vm from template
	'''
	create_vm_by_template(vcenter_ip,vcenter_user,vcenter_password,vcenter_port,template,vm_name,\
		datacenter_name,datastore_name,cluster_name,power_on,vm_cpus, vm_cpu_sockets, vm_memory)
	get_info_from_vcenter(vcenter_id,vcenter_user,vcenter_password,vcenter_ip,vcenter_port)


@job
def chassis_off(server_id):
	server = get_object_or_404(Server,pk=server_id)
	ipmi_ip = server.ipmi_ip
	ipmi_user = server.ipmi_user
	ipmi_pass = server.ipmi_pass
	if not (ipmi_ip and ipmi_user and ipmi_pass):
		server.power = 'ipmi error'
		server.save()
	else:
		ipmi = ipmitool(ipmi_ip,ipmi_pass,username=ipmi_user)
		ipmi.chassis_status()
		if 'off' in ipmi.output:
			pass
		else:
			ipmi.chassis_off()
		server.power = 'off'
		server.pxe_ip = ''
		server.save()

@job
def chassis_install(server_id):
	server = get_object_or_404(Server,pk=server_id)
	ipmi_ip = server.ipmi_ip
	ipmi_user = server.ipmi_user
	ipmi_pass = server.ipmi_pass
	if not (ipmi_ip and ipmi_user and ipmi_pass):
		server.power = 'ipmi error'
		server.save()
	else:
		ipmi = ipmitool(ipmi_ip,ipmi_pass,username=ipmi_user)
		ipmi.chassis_status()
		if 'off' in ipmi.output:
			ipmi.boot_to_pxe()
			ipmi.chassis_on()
		else:
			ipmi.boot_to_pxe()
			ipmi.chassis_reboot()
		server.presystem.progress = 0
		server.presystem.save()

@job
def boot_to_pxe(server_id):
	server = get_object_or_404(Server,pk=server_id)
	ipmi_ip = server.ipmi_ip
	ipmi_user = server.ipmi_user
	ipmi_pass = server.ipmi_pass
	if not (ipmi_ip and ipmi_user and ipmi_pass):
		server.power = 'ipmi error'
		server.save()
	else:
		ipmi = ipmitool(ipmi_ip,ipmi_pass,username=ipmi_user)
		ipmi.chassis_status()
		if 'on' in ipmi.output:
			pass
		else:
			ipmi.boot_to_pxe()
			ipmi.chassis_on()
		server.power = 'start'
		server.pxe_ip = ''
		server.save()