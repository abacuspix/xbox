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
			if eachevent['data']['fun'] == "saltutil.find_job":
				if eachevent['data'].has_key('return') and eachevent['data']['return'].has_key('metadata'):
					job_list.update_one({'metadata':eachevent['data']['return']['metadata']},\
									{"$set": {"state_id":eachevent['data']['return']['jid']}})
			else:
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
					elif re.match(r'.*salt\s+.+\s+state\.sls\s+(.+)',eachevent['data']['fun_args'][0]):
						m = re.match(r'.*Failed:\s+(\d+).*',eachevent['data']['return'],re.DOTALL)
						if m:
							faild_count = int(m.groups()[0])
							if faild_count:
								job_list.update_one({'jid':eachevent['data']['jid']},\
									{"$set": {"status":'Failed','progress':'Finish'}})
							else:
								job_list.update_one({'jid':eachevent['data']['jid']},\
									{"$set": {"status":'Success','progress':'Finish'}})
						else:
							job_list.update_one({'jid':eachevent['data']['jid']},\
									{"$set": {"status":'Failed','progress':'Finish'}})
					else:
						pass
					job_ret.insert_one(eachevent['data'])
	except Exception as e:
		log(e)

