# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.shortcuts import redirect,HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from xbox.decorators import role_required
from xbox.paginator import my_paginator
from django.views.decorators.csrf import csrf_exempt
from .models import *
from xbox.settings import FTP_IP,FTP_PORT
from xbox.settings import SALT_MASTER_HOSTNAME,SALT_IP,SALT_PORT,SALT_USER,SALT_PASSWD,SALT_FILE_ROOTS,SALT_SCRIPTS,SALT_STATES,SALT_FILE_DOWNLOADS
from xbox.settings import MONGO_CLIENT
from opsdb.saltapi import SaltAPI
from xbox.sshapi import remote_cmd
from json2html import *
from django.db.models import Q
import time
from .utils import exacute_cmd,upload_file,push_file_to_minion,get_file_from_minion,run_script,state_deploy
import os
import collections
import json
# Create your views here.

@login_required
@role_required('admin')
def envs(request):
	env_list = Environment.objects.all()
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,envs,page_number = my_paginator(env_list,page,page_number)
	return render(request,'opsdb/env/envs.html',locals())

@login_required
@role_required('admin')
def add_env(request):
	if request.method == "GET":
		return render(request, 'opsdb/env/add_env.html',locals())
	else:
		name = request.POST.get('name','')
		comment = request.POST.get('comment','')
		try:
			Environment.objects.update_or_create(name=name,defaults={'comment':comment})
			messages.success(request, '添加成功')
		except Exception as e:
			messages.error(request, e)
		return redirect('opsdb:envs')

@login_required
@role_required('admin')
def edit_env(request,id):
	env = Environment.objects.get(pk=id)
	if request.method == "GET":
		return render(request, 'opsdb/env/edit_env.html',locals())
	else:
		name = request.POST.get('name','')
		comment = request.POST.get('comment','')
		try:
			Environment.objects.update_or_create(name=name,defaults={'comment':comment})
			messages.success(request, '环境更新成功')
		except Exception as e:
			messages.error(request, e)
		return redirect('opsdb:envs')

@login_required
@role_required('admin')
@csrf_exempt
def delete_env(request):
	ids = request.POST.getlist('ids[]','')
	ret = 'success'
	try:
		Environment.objects.filter(pk__in=ids).delete()
	except Exception as e:
		ret = str(e)
	return HttpResponse(ret)

@login_required
@role_required('admin')
def rules(request):
	rule_list = Rule.objects.all()
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,rules,page_number = my_paginator(rule_list,page,page_number)
	return render(request,'opsdb/rule/rules.html',locals())

@login_required
@role_required('admin')
@csrf_exempt
def edit_rule(request,id):
	hostgroups = HostGroup.objects.all()
	rule = Rule.objects.get(pk=id)
	if request.method == "GET":
		return render(request, 'opsdb/rule/edit_rule.html',locals())
	else:
		try:
			hostgroup_list = request.POST.getlist('hostgroups','')
			comment = request.POST.get('comment','')
			rule.hostgroups = hostgroup_list
			rule.created_by = request.user
			rule.comment = comment
			rule.save()
			messages.success(request, '规则更新成功')
		except Exception as e:
			messages.error(request, e)
		return redirect('opsdb:rules')

@login_required
@role_required('hostadmin')
@csrf_exempt
def add_host(request):
	if request.method == "GET":
		hostgroups = HostGroup.objects.all()
		envs = Environment.objects.all()
		return render(request,'opsdb/host/add_host.html',locals())
	else:
		ip = request.POST.get('ip','')
		port = request.POST.get('port','')
		user = request.POST.get('username','')
		passwd = request.POST.get('password','')
		salt = request.POST.get('salt','')
		zabbix = request.POST.get('zabbix','')
		hostgroups = request.POST.getlist('hostgroups','')
		env = request.POST.get('env','')
		cmd = "curl -s http://%s:%s/install-minion.sh | sh 2>&1"%(FTP_IP,FTP_PORT)
		ret = remote_cmd(cmd,ip,port=int(port),user=user,passwd=passwd)
		if ret['status'] and not ret['err']:
			host,created = Host.objects.get_or_create(ip=ip)
			if host:
				if hostgroups:
					host.hostgroups = hostgroups
				if env:
					host.environment = env
			messages.success(request, '添加成功')
			return redirect('opsdb:hosts')
		else:
			messages.error(request, ret['err'])
			return render(request,'opsdb/host/add_host.html',locals())

@login_required
@role_required('hostadmin')
@csrf_exempt
def add_host_batch(request):
	if request.method == "GET":
		hostinfo = '''#请按照实例格式编辑主机信息:
﻿﻿#IP地址           SSH端口     SSH用户    SSH密码(仅用于安装客户端，不保存)
192.168.1.1     22                root           12345678
192.168.1.2     22                root           87654321'''
		return render(request,'opsdb/host/add_host_batch.html',locals())
	else:
		hostinfo = request.POST.get('hostinfo','')
		lines = hostinfo.split('\n')
		result = {}
		for line in lines:
			host = line.split()
			ip,port,user,passwd = host[0],host[1],host[2],host[3]
			cmd = "curl -s http://%s:%s/install-minion.sh | sh 2>&1"%(FTP_IP,FTP_PORT)
			ret = remote_cmd(cmd,ip,port=int(port),user=user,passwd=passwd,timeout=10)
			if ret['status'] and not ret['err']:
				host,created = Host.objects.get_or_create(ip=ip)
				if host:
					result[ip] = {'status':'Success','comment':'添加成功'}
			else:
				result[ip] = {'status':'Fail','comment':ret['err']}
				continue
		result = json2html.convert(json = result)
		return render(request,'opsdb/host/add_host_batch.html',locals())

@login_required
@role_required('hostadmin')
def hosts(request):
	if request.user.is_superuser:
		host_list = Host.objects.select_related().all()
	else:
		if request.user.groups:
			host_list = []
			for group in request.user.groups.all():
				for hostgroup in group.rule.hostgroups.all():
					host_list.extend(hostgroup.host_set.all())
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,hosts,page_number = my_paginator(host_list,page,page_number)
	return render(request,'opsdb/host/hosts.html',locals())

def host(request,id):
	hosts = MONGO_CLIENT.salt.salt_grains.find({'id':id}).sort([("_id", -1)]).limit(1)
	grains = {'os':{},'software':{},'users':{},'hardware':{},'cron':{}}
	if hosts:
		for host in hosts:
			ret = host.get('return',None)
			# operation system info
			grains = {'os':{},'software':{},'users':{},'hardware':{},'cron':{}}
			grains['os']['fqdn'] = ret.get('fqdn',None)
			grains['os']['os'] = ' '.join([ret.get('os',None),ret.get('osrelease',None)])
			grains['os']['kernel'] = ' '.join([ret.get('kernel',None),ret.get('kernelrelease',None)])
			grains['os']['disk-usage'] = ret.get('disk-usage',None)
			grains['os']['selinux'] = ret.get('selinux',None)
			grains['os']['fqdn_ip4'] = ret.get('fqdn_ip4',None)
			grains['os']['ip4_interfaces'] = ret.get('ip4_interfaces',None)
			grains['os']['ip6_interfaces'] = ret.get('ip6_interfaces',None)
			grains['os']['routes'] = ret.get('routes',None)
			grains['os']['dns'] = ret.get('dns',None)
			grains['os']['ntp'] = ret.get('ntp',None)
			grains['os']['iptable'] = ret.get('iptable',None)
			grains['os']['systemd'] = ret.get('systemd',None)
			grains['os']['lsb_distrib'] = {'id':ret['lsb_distrib_id'],'codename':ret['lsb_distrib_codename']}
			os = json2html.convert(json = grains['os'])

			# software info
			grains['software'] = ret.get('software',None)
			users = json2html.convert(json = grains['software'])

			# system user info
			grains['users'] = ret.get('users',None)
			users = json2html.convert(json = grains['users'])

			# hardware info
			grains['hardware']['virtual'] = ret.get('virtual',None)
			grains['hardware']['serialnumber'] = ret.get('serialnumber',None)
			grains['hardware']['cpu'] = ' * '.join([str(ret.get('num_cpus')),ret.get('cpu_model')])
			grains['hardware']['mem_total(G)'] = ("%.2f"%(ret.get('mem_total',0)/1024.0))
			grains['hardware']['Hugepage & Swap'] = ret.get('Hugepage & Swap',None)
			grains['hardware']['HBA'] = ret.get('HBA',None)
			hardware = json2html.convert(json = grains['hardware'])

			# user cron info
			cron = json2html.convert(json = grains['cron'])

			# summary info
			summary = json2html.convert(json = ret)

	return render(request,'opsdb/host/host.html',locals())

@login_required
@role_required('hostadmin')
@csrf_exempt
def delete_host(request,id):
	host = Host.objects.get(pk=id)
	salt = SaltAPI(SALT_IP,SALT_USER,SALT_PASSWD,port=SALT_PORT)
	try:
		salt.key(client='wheel',fun='key.delete',match=host.minion_id)
		host.delete()
		messages.success(request, '主机删除成功')
	except Exception as e:
		messages.error(request, e)
	return redirect('opsdb:hosts')

@login_required
@role_required('hostadmin')
@csrf_exempt
def delete_host_batch(request):
	ids = request.POST.getlist('ids[]','')
	salt = SaltAPI(SALT_IP,SALT_USER,SALT_PASSWD,port=SALT_PORT)
	ret = 'success'
	for host_id in ids:
		try:
			host = Host.objects.get(pk=host_id)
			salt.key(client='wheel',fun='key.delete',match=host.minion_id)
			host.delete()
		except Exception as e:
			ret = str(e)
			break
	return HttpResponse(ret)

def search_host(request):
	keyword = request.POST.get('keyword','')
	q = Q(ip__icontains=keyword) | Q(hostname__icontains=keyword) | Q(os__icontains=keyword) \
	| Q(hostgroups__name__icontains=keyword) | Q(applications__name__icontains=keyword) \
	| Q(is_virtual__icontains=keyword) | Q(environment__name__icontains=keyword)| Q(comment__icontains=keyword) \
	| Q(minion_id__icontains=keyword) 
	if request.user.is_superuser:
		host_list = Host.objects.select_related().filter(q).distinct()
	else:
		if request.user.groups:
			host_list = []
			for group in request.user.groups.all():
				for hostgroup in group.rule.hostgroups.all():
					host_list.extend(hostgroup.host_set.filter(q).distinct())
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,hosts,page_number = my_paginator(host_list,page,page_number)
	return render(request,'opsdb/host/hosts.html',locals())

def search_exact_host(request):
	if request.method == "GET":
		envs = Environment.objects.all()
		hostgroups = HostGroup.objects.all()
		oses = Host.objects.values('os').distinct()
		virtual = Host.objects.values('is_virtual').distinct()
		return render(request,'opsdb/host/search_exact_host.html',locals())
	else:
		env = request.POST.get('env','')
		hostgroup = request.POST.get('hostgroup','')
		os = request.POST.get('os','')
		virtual = request.POST.get('virtual','')
		q = Q()
		if env:
			q = q & Q(environment__name=env)
		if hostgroup:
			q = q & Q(hostgroups__name=hostgroup)
		if os:
			q = q & Q(os=os)
		if virtual:
			q = q & Q(is_virtual=virtual)
		if request.user.is_superuser:
			host_list = Host.objects.select_related().filter(q).distinct()
		else:
			if request.user.groups:
				host_list = []
				for group in request.user.groups.all():
					for hostgroup in group.rule.hostgroups.all():
						host_list.extend(hostgroup.host_set.filter(q).distinct())
		page_number =  request.GET.get('page_number')
		page = request.GET.get('page')
		paginator,hosts,page_number = my_paginator(host_list,page,page_number)
		return render(request,'opsdb/host/hosts.html',locals())

@login_required
@role_required('hostadmin')
def edit_host(request,id):
	host = Host.objects.get(pk=id)
	if request.method == "GET":
		hostgroups = HostGroup.objects.all()
		envs = Environment.objects.all()
		return render(request,'opsdb/host/edit_host.html',locals())
	else:
		hostgroups = request.POST.getlist('hostgroups','')
		env = request.POST.get('env','')
		try:
			if hostgroups:
				host.hostgroups = hostgroups
			if env != host.environment:
				host.environment = Environment.objects.get(pk=env)
				host.save()
			messages.success(request, '主机更新成功')
		except Exception as e:
			messages.error(request, e)
		return redirect('opsdb:hosts')

@login_required
@role_required('hostadmin')
@csrf_exempt
def edit_host_batch(request):
	if request.method == "GET":
		hostgroups = HostGroup.objects.all()
		envs = Environment.objects.all()
		hosts = Host.objects.all()
		return render(request,'opsdb/host/edit_host_batch.html',locals())
	else:
		hostgroups = request.POST.getlist('hostgroups','')
		env = request.POST.get('env','')
		host_ids = request.POST.getlist('hosts','')
		hosts = Host.objects.filter(pk__in=host_ids)
		try:
			hosts.update(environment_id=env)
			for host in hosts:
				host.hostgroups = hostgroups
			messages.success(request, '更新成功')
		except Exception as e:
			messages.error(request, e)
		return redirect('opsdb:hosts')

@login_required
@role_required('hostadmin')
def hostgroups(request):
	group_lists = HostGroup.objects.all()
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,hostgroups,page_number = my_paginator(group_lists,page,page_number)
	return render(request,'opsdb/host/hostgroups.html',locals())

@login_required
@role_required('hostadmin')
def add_hostgroup(request):
	if request.method == "GET":
		hosts = Host.objects.all()
		return render(request, 'opsdb/host/add_hostgroup.html',locals())
	else:
		name = request.POST.get('name','')
		host_lists = request.POST.getlist('hosts','')
		comment = request.POST.get('comment','')
		try:
			hostgroup,created = HostGroup.objects.get_or_create(name=name)
			if created:
				hostgroup.host_set = host_lists
				if comment:
					hostgroup.comment = comment
					hostgroup.save()
			messages.success(request, '主机组添加成功')
		except Exception as e:
			messages.error(request, e)
		return redirect('opsdb:hostgroups')

@login_required
@role_required('hostadmin')
def edit_hostgroup(request,id):
	hostgroup = HostGroup.objects.get(pk=id)
	if request.method == "GET":
		hosts = Host.objects.all()
		return render(request, 'opsdb/host/edit_hostgroup.html',locals())
	else:
		name = request.POST.get('name','')
		host_lists = request.POST.getlist('hosts','')
		comment = request.POST.get('comment','')
		try:
			if name != hostgroup.name:
				hostgroup.name = name
			if comment != hostgroup.comment:
				hostgroup.comment = comment
			hostgroup.host_set = host_lists
			hostgroup.save()
			messages.success(request, '主机组更新成功')
		except Exception as e:
			messages.error(request, e)
		return redirect('opsdb:hostgroups')

@login_required
@role_required('hostadmin')
@csrf_exempt
def delete_hostgroup(request):
	ids = request.POST.getlist('ids[]','')
	ret = 'success'
	try:
		HostGroup.objects.filter(pk__in=ids).delete()
	except Exception as e:
		ret = str(e)
	return HttpResponse(ret)

@login_required
@role_required('hostadmin')
def cmd(request):
	if request.method == 'POST':
		user = request.user.username
		if request.META.has_key('HTTP_X_FORWARDED_FOR'):
			client =  request.META['HTTP_X_FORWARDED_FOR']  
		else:
			client = request.META['REMOTE_ADDR']
		arg_list = request.POST.get('cmd','') if request.POST.get('cmd','') else 'echo hello'
		hosts = request.POST.get('hosts','')
		target = hosts.split(',')
		result,error = exacute_cmd(user,client,target,arg_list)
	return render(request, 'opsdb/ops/cmd.html',locals())	


@login_required
@role_required('hostadmin')
def select_hosts(request):
	if request.user.is_superuser:
		host_list = Host.objects.select_related().all()
	else:
		if request.user.groups:
			host_list = []
			for group in request.user.groups.all():
				for hostgroup in group.rule.hostgroups.all():
					host_list.extend(hostgroup.host_set.all())
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,hosts,page_number = my_paginator(host_list,page,page_number)
	return render(request,'opsdb/ops/select_hosts.html',locals())

def search_host_for_cmd(request):
	keyword = request.POST.get('keyword','')
	q = Q(ip__icontains=keyword) | Q(hostname__icontains=keyword) | Q(os__icontains=keyword) \
	| Q(hostgroups__name__icontains=keyword) | Q(applications__name__icontains=keyword) \
	| Q(is_virtual__icontains=keyword) | Q(environment__name__icontains=keyword)| Q(comment__icontains=keyword) \
	| Q(minion_id__icontains=keyword) 
	if request.user.is_superuser:
		host_list = Host.objects.select_related().filter(q).distinct()
	else:
		if request.user.groups:
			host_list = []
			for group in request.user.groups.all():
				for hostgroup in group.rule.hostgroups.all():
					host_list.extend(hostgroup.host_set.filter(q).distinct())
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,hosts,page_number = my_paginator(host_list,page,page_number)
	return render(request,'opsdb/ops/select_hosts.html',locals())

@login_required
@role_required('hostadmin')
def joblist(request):
	if request.user.is_superuser:
		sjobs = MONGO_CLIENT.salt.joblist.find().sort([('_id',-1)])
	else:
		sjobs = MONGO_CLIENT.salt.joblist.find({'user':request.user.username}).sort([('_id',-1)])
	job_list = [job for job in sjobs]
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,jobs,page_number = my_paginator(job_list,page,page_number)
	return render(request,'opsdb/ops/joblist.html',locals())

def job_cjid(request,cjid):
	sjob = MONGO_CLIENT.salt.joblist.find_one({'cjid':cjid})
	if sjob.has_key('fun') and sjob['fun'] == 'cmd.script':
		result = {}
		for minion,ret in sjob['result'].items():
			result[minion] = {'stderr':ret['stderr'],'stdout':ret['stdout']}
		return render(request,'opsdb/ops/show_job_result.html',locals())
	elif sjob.has_key('fun') and sjob['fun'] == 'state.sls':
		result = eval(sjob['result'])
		for k,v in result.items():
			process = collections.OrderedDict(sorted(v['process'].iteritems(),key=lambda x:x[0]))
			summary = v['summary']
			result[k] = {'process':process,'summary':summary}
		return render(request,'opsdb/ops/show_state_result.html',locals())
	else:
		return render(request,'opsdb/ops/jobresult.html',locals())

@login_required
@role_required('hostadmin')
def cmds(request):
	cmd_list = Cmd.objects.all()
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,cmds,page_number = my_paginator(cmd_list,page,page_number)
	return render(request,'opsdb/ops/cmds.html',locals())

@login_required
@role_required('hostadmin')
def add_cmd(request):
	if request.method == 'POST':
		name = request.POST.get('name','')
		argument = request.POST.get('argument','')
		comment = request.POST.get('comment')
		try:
			cmd,created = Cmd.objects.get_or_create(name=name,defaults={'argument':argument,'comment':comment,'created_by':request.user.username})
			if created:
				messages.success(request, '命令添加成功')
				return redirect('opsdb:cmds')
			else:
				messages.error(request, '命令名称重复')
		except Exception as e:
			messages.error(request, e)
	return render(request,'opsdb/ops/add_cmd.html',locals())

@login_required
@role_required('hostadmin')
@csrf_exempt
def save_cmd(request):
	if request.method == 'POST':
		argument = request.POST.get('argument','')
	return render(request,'opsdb/ops/add_cmd.html',locals())

@login_required
@role_required('hostadmin')
def edit_cmd(request,id):
	cmd = Cmd.objects.get(pk=id)
	if request.method == 'POST':
		name = request.POST.get('name','')
		argument = request.POST.get('argument','')
		comment = request.POST.get('comment')
		try:
			if name != cmd.name:
				cmd.name = name
			if argument != cmd.argument:
				cmd.argument = argument
			if comment != cmd.comment:
				cmd.comment = comment
			cmd.save()
			messages.success(request, '命令更新成功')
			return redirect('opsdb:cmds')
		except Exception as e:
			messages.error(request, e)
	else:
		name,argument,comment = cmd.name,cmd.argument,cmd.comment
	return render(request,'opsdb/ops/edit_cmd.html',locals())

@login_required
@role_required('hostadmin')
def delete_cmd(request,id):
	ret = 'success'
	try:
		Cmd.objects.filter(pk__in=id).delete()
		messages.success(request, '命令已经删除')
	except Exception as e:
		messages.error(request, e)
	return redirect('opsdb:cmds')

@login_required
@role_required('hostadmin')
@csrf_exempt
def delete_cmds(request):
	ids = request.POST.getlist('ids[]','')
	ret = 'success'
	try:
		Cmd.objects.filter(pk__in=ids).delete()
	except Exception as e:
		ret = str(e)
	return HttpResponse(ret)

@login_required
@role_required('hostadmin')
def get_file(request):
	# files = os.listdir(SALT_FILE_ROOTS)
	files = File.objects.filter(file_type='upload')
	if request.method == 'POST':
		file = request.POST.get('file','')
		remote_path = request.POST.get('remote_path','')
		arg_list = [file,remote_path,'makedirs=True']
		target = request.POST.get('hosts','').split(',')
		user = request.user.username
		if request.META.has_key('HTTP_X_FORWARDED_FOR'):
			client =  request.META['HTTP_X_FORWARDED_FOR']  
		else:
			client = request.META['REMOTE_ADDR']
		result,error = push_file_to_minion(user,client,target,arg_list)
		if error:
			messages.error(request, error)
	return render(request,'opsdb/ops/get_file.html',locals())

@login_required
@role_required('hostadmin')
@csrf_exempt
def put_file(request):
	if request.method == 'POST':
		file = request.FILES.get("file", None)
		if not file:
			messages.error(request, 'No files for upload!')
		else:
			user = request.user.username
			if request.META.has_key('HTTP_X_FORWARDED_FOR'):
				client =  request.META['HTTP_X_FORWARDED_FOR']
			else:
				client = request.META['REMOTE_ADDR']
			try:
				myfile = File.objects.update_or_create(name=file.name,defaults={'created_by':user})
				if myfile:
					error = upload_file(user,client,SALT_FILE_ROOTS,file)
					if error:
						myfile.delete()
						messages.error(request, error)
			except Exception as e:
				messages.error(request, e)
	files = File.objects.filter(file_type='upload')
	return render(request,'opsdb/ops/get_file.html',locals())

@login_required
@role_required('hostadmin')
def delete_file(request,id):
	try:
		file = File.objects.get(pk=id)
		if file and file.file_type == 'upload':
			file_path = os.path.join(SALT_FILE_ROOTS,file.name)
		else:
			file_path = os.path.join(SALT_FILE_DOWNLOADS,file.name)
			os.remove(file_path)
			file.delete()
			messages.success(request, '文件已经删除')
			return redirect('opsdb:push_file')
		os.remove(file_path)
		file.delete()
		messages.success(request, '文件已经删除')
	except Exception as e:
		messages.error(request, e)
	return redirect('opsdb:get_file')

@login_required
@role_required('hostadmin')
def push_file(request):
	if request.method == 'POST':
		remote_path = request.POST.get('remote_path','')
		arg_list = [remote_path]
		target = request.POST.get('hosts','').split(',')
		user = request.user.username
		if request.META.has_key('HTTP_X_FORWARDED_FOR'):
			client =  request.META['HTTP_X_FORWARDED_FOR']  
		else:
			client = request.META['REMOTE_ADDR']
		result,error = get_file_from_minion(user,client,target,arg_list)
		if not error:
			try:
				for tgt in target:
					File.objects.update_or_create(name=tgt+'/files'+remote_path,defaults={'created_by':user,'file_type':'download'})
			except Exception as e:
				messages.error(request, e)
	files = File.objects.filter(file_type='download')
	url = 'http://%s:%s/downloads/'%(FTP_IP,FTP_PORT)
	return render(request,'opsdb/ops/push_file.html',locals())

@login_required
@role_required('hostadmin')
def scripts(request):
	script_list = Script.objects.all()
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,scripts,page_number = my_paginator(script_list,page,page_number)
	return render(request,'opsdb/ops/scripts.html',locals())

@login_required
@role_required('hostadmin')
def upload_script(request):
	if request.method == 'POST':
		file = request.FILES.get("myfile", None)
		if not file:  
			messages.error(request, 'No files for upload!')
		else:
			name = request.POST.get('name') if request.POST.get('name') else file.name
			try:
				user = request.user.username
				script = Script.objects.create(name=name,script_name=file.name,created_by=user)
				if script:
					if request.META.has_key('HTTP_X_FORWARDED_FOR'):
						client =  request.META['HTTP_X_FORWARDED_FOR']  
					else:
						client = request.META['REMOTE_ADDR']
					error = upload_file(user,client,SALT_SCRIPTS,file)
					if not error:
						messages.success(request, '脚本上传成功')
					else:
						messages.error(request, error)
						script.delete()
			except Exception as e:
				messages.error(request, e)
	return render(request,'opsdb/ops/upload_script.html',locals())

@login_required
@role_required('hostadmin')
def edit_script(request,id):
	try:
		script = Script.objects.get(pk=id)
		file_path = os.path.join(SALT_SCRIPTS,script.script_name)
		if request.method == 'POST':
			script_name = request.POST.get('script_name')
			name = request.POST.get('name')
			file = request.POST.get('script')
			f = open(file_path.encode('utf8'),'w')
			f.write(file)
			f.close()
			os.system('dos2unix %s'%(file_path))
			script.comment = request.user.username
			script.script_name = script_name
			script.name = name
			script.save()
			messages.success(request, '保存成功')
		else:
			script_name = script.script_name
			name = script.name
		f = open(file_path,'r')
		file = f.read()
		f.close()
	except Exception as e:
		messages.error(request, e)
	return render(request,'opsdb/ops/edit_script.html',locals())

@login_required
@role_required('hostadmin')
def add_script(request):
	if request.method == "POST":
		try:
			script_name = request.POST.get('script_name')
			name = request.POST.get('name') if request.POST.get('name','') else script_name
			file = request.POST.get('script')
			file_path = os.path.join(SALT_SCRIPTS,script_name)
			script = Script.objects.create(name=name,script_name=script_name,created_by=request.user.username,comment=request.user.username)
			if script:
				try:
					f = open(file_path.encode('utf8'),'wb+')
					f.write(file)
					f.close()
					os.system('dos2unix %s'%(file_path))
					messages.success(request, '保存成功')
					f = open(file_path,'r')
					file = f.read()
					f.close()
				except Exception as e:
					script.delete()
					messages.error(request, e)		
		except Exception as e:
			messages.error(request, e)
	return render(request,'opsdb/ops/add_script.html',locals())

@login_required
@role_required('hostadmin')
def copy_script(request,id):
	try:
		script = Script.objects.get(pk=id)
		file_path = os.path.join(SALT_SCRIPTS,script.script_name)
		if request.method == 'POST':
			script_name = request.POST.get('script_name')
			name = request.POST.get('name')
			file = request.POST.get('script')
			new_script = Script.objects.create(name=name,script_name=script_name,created_by=request.user.username,comment=request.user.username)
			if new_script:
				try:
					file_path = os.path.join(SALT_SCRIPTS,script_name)
					f = open(file_path.encode('utf8'),'wb+')
					f.write(file)
					f.close()
					os.system('dos2unix %s'%(file_path))
					messages.success(request, '复制成功')
				except Exception as e:
					new_script.delete()
					messages.error(request, e)		
		else:
			old_script_name = script.script_name.split('.')
			script_name = '.'.join([old_script_name[0] + '-copy',old_script_name[1]])
			name = script.name + '-copy'
		f = open(file_path,'r')
		file = f.read()
		f.close()
	except Exception as e:
		messages.error(request, e)
	return render(request,'opsdb/ops/copy_script.html',locals())

@login_required
@role_required('hostadmin')
def delete_script(request,id):
	try:
		script = Script.objects.get(pk=id)
		if script:
			file_path = os.path.join(SALT_SCRIPTS,script.script_name)
			os.remove(file_path)
			script.delete()
			messages.success(request, '脚本已经删除')
	except Exception as e:
		messages.error(request, e)
	return redirect('opsdb:scripts')

@login_required
@role_required('hostadmin')
def exacute_script(request,id):
	try:
		script = Script.objects.get(pk=id)
		if request.method == 'POST':
			arg_list = script.script_name
			hosts = request.POST.get('hosts')
			target = hosts.split(',')
			async = request.POST.get('async')
			if request.META.has_key('HTTP_X_FORWARDED_FOR'):
				client =  request.META['HTTP_X_FORWARDED_FOR']  
			else:
				client = request.META['REMOTE_ADDR']
			user = request.user.username
			result,error = run_script(user,client,target,arg_list,async)
			if error:
				messages.error(request, error)
	except Exception as e:
		messages.error(request, e)
	return render(request,'opsdb/ops/exacute_script.html',locals())

@login_required
@role_required('hostadmin')
def search_script(request):
	keyword = request.POST.get('keyword','')
	q = Q(name__icontains=keyword) | Q(script_name__icontains=keyword) | Q(created_by__icontains=keyword) \
	| Q(comment__icontains=keyword)
	script_list = Script.objects.filter(q)
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,scripts,page_number = my_paginator(script_list,page,page_number)
	return render(request,'opsdb/ops/scripts.html',locals())

@login_required
@role_required('hostadmin')
def job_jid(request,jid):
	jobs = MONGO_CLIENT.salt.salt_job_ret.find({'jid':jid})
	result = {}
	if jobs:
		for job in jobs:
			if job['fun'] == 'state.sls':
				ret = eval(job['return'])
				process = collections.OrderedDict(sorted(ret['process'].iteritems(),key=lambda x:x[0]))
				summary = ret['summary']
				result[job['id']] = {'process':process,'summary':summary}
			else:
				result[job['id']] = {'stderr':job['return']['stderr'],'stdout':job['return']['stdout']}
	else:
		error = '抱歉,未查询到结果,请稍后再试.'
	if result:
		for k,v in result.items():
			if v.has_key('process'):
				return render(request,'opsdb/ops/show_state_result.html',locals())
			else:
				break
	return render(request,'opsdb/ops/show_job_result.html',locals())

@login_required
@role_required('hostadmin')
def states(request):
	state_list = SaltState.objects.all()
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,states,page_number = my_paginator(state_list,page,page_number)
	return render(request,'opsdb/ops/states.html',locals())

@login_required
@role_required('hostadmin')
def upload_state(request):
	if request.method == 'POST':
		myfile = request.FILES.get("myfile", None)
		split = myfile.name.split('.')
		name = request.POST.get('name') if request.POST.get('name') else split[0]
		try:
			state = SaltState.objects.create(name=name,state_name=split[0],created_by=request.user.username)
			if state:
				try:
					state_path = os.path.join(SALT_STATES,myfile.name)
					destination = open(state_path,'wb+') 
					for chunk in myfile.chunks():
						destination.write(chunk)  
					destination.close()
					if 'tar' in myfile.name:
						os.system('tar xvf %s -C %s;rm -f %s'%(state_path,SALT_STATES,state_path))
					messages.success(request, '模块上传成功')
				except Exception as e:
					state.delete()
					messages.error(request, str(e))
		except Exception as e:
			messages.error(request, str(e))
	return render(request,'opsdb/ops/upload_state.html')

@login_required
@role_required('hostadmin')
def deploy_state(request,id):
	try:
		state = SaltState.objects.get(pk=id)
		if request.method == 'POST':
			user = request.user.username
			if request.META.has_key('HTTP_X_FORWARDED_FOR'):
				client =  request.META['HTTP_X_FORWARDED_FOR']  
			else:
				client = request.META['REMOTE_ADDR']
			salt = SaltAPI(SALT_IP,SALT_USER,SALT_PASSWD,port=SALT_PORT)
			target = request.POST.get('hosts','').split(',')
			async = request.POST.get('async')
			arg_list = state.state_name
			result,error = state_deploy(user,client,target,arg_list,async)
			if error:
				messages.error(request, error)
			if not result.has_key('jid'):
				for k,v in result.items():
					process = collections.OrderedDict(sorted(v['process'].iteritems(),key=lambda x:x[0]))
					summary = v['summary']
					result[k] = {'process':process,'summary':summary}
	except Exception as e:
		messages.error(request, e)
	return render(request,'opsdb/ops/deploy_state.html',locals())

@login_required
@role_required('hostadmin')
def delete_state(request,id):
	try:
		state = SaltState.objects.get(pk=id)
		if state:
			file_path = os.path.join(SALT_STATES,state.state_name)
			if os.path.isdir(file_path):
				os.system('rm -rf %s'%(file_path))
			else:
				os.remove('.'.join([file_path,'sls']))
			state.delete()
			messages.success(request, '模块已经删除')
	except Exception as e:
		messages.error(request, e)
	return redirect('opsdb:states')