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

# Import python libs
import json
import re
import os
import datetime

# Create MongoDB connect
from pymongo import MongoClient
client = MongoClient('192.168.3.169',27017)
db = client.salt

# define collection in mongo
grains = db.salt_grains
job_ret = db.salt_job_ret
job_list = db.salt_joblist

# Create Mysql connect
import MySQLdb
mysql_db = MySQLdb.connect("192.168.3.169","devops","devops","devops" )
cursor = mysql_db.cursor()

# create re pattern objects according to event type
pattern_job_ret = re.compile(r'salt/job/\d+/ret/.+')

def log(e):
	BASE_DIR = os.path.dirname(os.path.abspath(__file__))
	log_path = os.path.join(BASE_DIR, 'logs/salt_event_to_mongo.log')
	with open(log_path,'a+') as f:
		log = '%s : %s\n'%(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),str(e))
		f.write(log)
		f.close()

def parse_salt_event(eachevent):
	try:
		if pattern_job_ret.match(eachevent['tag']):
			if eachevent['data'].has_key('id') and eachevent['data'].has_key('return'):
				if eachevent['data']['fun'] == 'grains.items':
					sql = '''INSERT INTO host (ip,hostname,os,is_virtual,minion_id,minion_status,update_time) VALUES \
					(%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE ip=%s,hostname=%s,os=%s,is_virtual=%s,\
					minion_id=%s,minion_status=%s,update_time=%s'''
					items = eachevent['data']['return']
					try:
						# 执行sql语句
						cursor.execute(sql,(items['ipv4'][1],items['fqdn'],' '.join([items['os'],items['osrelease']]),\
						items['virtual'],items['id'],'O',eachevent['data']['_stamp'],items['ipv4'][1],items['fqdn'],' '.join([items['os'],items['osrelease']]),\
						items['virtual'],items['id'],'O',eachevent['data']['_stamp']))
						# 提交到数据库执行
						mysql_db.commit()
					except Exception as e:
						# Rollback in case there is any error
						mysql_db.rollback()
						# write error log
						log(e)
					# grains.find_one_and_replace({'id':eachevent['data']['id']},eachevent['data'],upsert=True)
					grains.insert_one(eachevent['data'])
				elif eachevent['data']['fun'] == 'state.sls':
					ret = eachevent['data']['return']
					tmp = {'process':{},'summary':{}}
					succeeded = 0
					failed = 0
					total_duration = 0
					for k,v in ret.items():
						tmp1 = k.split('_|-')
						fun = '.'.join([tmp1[0],tmp1[3]])
						v['fun'] = fun
						v['id'] = tmp1[1]
						tmp['process'].update({str(v['__run_num__']):v})
						if v['result'] == True:
							succeeded += 1
						else:
							failed += 1
						total_duration += v['duration']
					tmp['summary'].update({'succeeded':succeeded,'failed':failed,'total_duration':total_duration})
					eachevent['data']['return'] = str(tmp)
					job_ret.insert_one(eachevent['data'])
				else:
					job_ret.insert_one(eachevent['data'])
	except Exception as e:
		log(e)