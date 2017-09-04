#!/bin/env python
#coding=utf8

'''
author: wei.yang@jinmuinfo.com
date: 2017.08.25

function:
Listening Salt Master Event System and parase the job return ,then store result to mongo and mysql

requirements:
1、The script must be exacuted on salt master because of salt modules
2、The script need pymongo to connect mongodb
3、The script need MySQLdb to connect mysql
4、The script need django-rq

'''

import os
import time

try:
	from redis import Redis
	from rq import Queue
	from script_on_saltmaster import parse_salt_event,log
	import salt.config
	import salt.utils.event
except Exception as e:
	log(e)

# create an RQ queue
try:
	print 'create an RQ queue'
	queue = Queue('high',connection=Redis())
except Exception as e:
	log(e)

# Listen Salt Master Event System
try:
	print 'Listen Salt Master Event System'
	__opts__ = salt.config.client_config('/etc/salt/master')
	event = salt.utils.event.MasterEvent(__opts__['sock_dir'])
	for eachevent in event.iter_events(full=True):
		queue.enqueue(parse_salt_event, eachevent)
except Exception as e:
	log(e)

