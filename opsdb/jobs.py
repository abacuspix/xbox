#!/usr/bin/python
#coding=utf8

'''
author: wei.yang@jinmuinfo.com
date: 2017.07.28

function:
cronjob for app opsdb

requirements:
1、pip install django-crontab
'''

from opsdb.saltapi import SaltAPI
from opsdb.models import Host
from xbox.settings import SALT_MASTER_HOSTNAME,SALT_IP,SALT_PORT,SALT_USER,SALT_PASSWD

def check_minion_status(arg,arg1,target,arg_list):
	'''
	monitoring host salt-minion status
	'''
	try:
		salt = SaltAPI(SALT_IP,SALT_USER,SALT_PASSWD,port=SALT_PORT)
		ret = salt.minion_alive_check()
		Host.objects.filter(minion_status='E').update(minion_status='O')
		if ret:
			for minion in ret:
				try:
					host = Host.objects.get(minion_id=minion)
					host.minion_status = 'E'
					host.save()
				except Exception as e:
					continue
					# raise e
	except Exception as e:
		print e

def update_grains(arg,arg1,target,arg_list):
	'''
	update all hosts grains in a interval
	'''
	try:
		salt = SaltAPI(SALT_IP,SALT_USER,SALT_PASSWD,port=SALT_PORT)
		salt.run(client='local_async', fun="grains.items", target="*", arg_list=['--batch=10%'],expr_form='glob')
	except Exception as e:
		pass


