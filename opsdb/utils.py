# -*- coding: utf-8 -*-
###
# author: wei.yang@jinmuinfo.com
# date : 2017-09-06
###
from xbox.settings import SALT_IP,SALT_PORT,SALT_USER,SALT_PASSWD,SALT_FILE_ROOTS
from xbox.settings import MONGO_CLIENT
from opsdb.saltapi import SaltAPI
import time
import os

def exacute_cmd(user,client,target,arg_list):
	result = {}
	error = ''
	try:
		salt = SaltAPI(SALT_IP,SALT_USER,SALT_PASSWD,port=SALT_PORT)
		result = salt.run(fun='cmd.run',target=target,arg_list=arg_list)
		job = {'user':user,'time':time.strftime("%Y-%m-%d %X", time.localtime()),'client':client,\
		'target':target,'fun':'cmd.run','arg':arg_list,\
		'status':'','progress':'Finish','result':result,'cjid':str(int(round(time.time() * 1000)))}
		MONGO_CLIENT.salt.joblist.insert_one(job)
	except Exception as e:
		error = str(e)
	return result,error

def tansimit_file(user,client,target,arg_list):
	result = {}
	error = ''
	try:
		arg_list[0] = 'salt://files/' + arg_list[0]
		salt = SaltAPI(SALT_IP,SALT_USER,SALT_PASSWD,port=SALT_PORT)
		result = salt.run(fun='cp.get_file',target=target,arg_list=arg_list)
		job = {'user':user,'time':time.strftime("%Y-%m-%d %X", time.localtime()),'client':client,\
		'target':target,'fun':'cp.get_file','arg':arg_list,\
		'status':'','progress':'Finish','result':result,'cjid':str(int(round(time.time() * 1000)))}
		MONGO_CLIENT.salt.joblist.insert_one(job)
	except Exception as e:
		error = str(e)
	return result,error

def upload_file(user,client,destination,file):
	result = False
	error = ''
	try:
		f = open(os.path.join(destination,file.name),'wb+') 
		for chunk in file.chunks():
			f.write(chunk)  
		f.close()
		result = True
		job = {'user':user,'time':time.strftime("%Y-%m-%d %X", time.localtime()),'client':client,\
		'target':'salt master','fun':'upload file to salt master','arg':file.name,\
		'status':'','progress':'Finish','result':'Success','cjid':str(int(round(time.time() * 1000)))}
		MONGO_CLIENT.salt.joblist.insert_one(job)
	except Exception as e:
		error = str(e)
	return result,error


