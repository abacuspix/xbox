# -*- coding: utf-8 -*-
###
# author: wei.yang@jinmuinfo.com
# date : 2017-10-23
from pyzabbix import ZabbixAPI
from xbox.settings import ZABBIX_SERVER,ZABBIX_USER,ZABBIX_PASS
import datetime
import time

zapi = ZabbixAPI(ZABBIX_SERVER)
zapi.login(ZABBIX_USER,ZABBIX_PASS)

def get_hostid_by_ip(ip):
	try:
		data = zapi.hostinterface.get(output=['hostid'],filter={'ip':ip})
		if data:
			data = data[0]['hostid']
	except Exception as e:
		data = str(e)

	return data

def get_itemids_by_hostid(hostid,key):
	try:
		data = zapi.item.get(output=['itemid','key_'],hostids=hostid,search={"key_": key})
		ret = {}
		if data:
			for ele in data:
				ret[ele['key_']] = ele['itemid']
	except Exception as e:
		ret = str(e)

	return ret

# time.mktime(datetime.datetime.now().timetuple())
def get_history_data(itemids=[],time_from=time.time() - 60 * 60 * 1,time_till=time.time()):
	try:
		# Query item's history (integer) data
		history = zapi.history.get(itemids=itemids,
								   time_from=time_from,
								   time_till=time_till,
								   output='extend',
								   sortfield="clock",
								   sortorder="ASC",
								   )

		# If nothing was found, try getting it from history (float) data
		if not len(history):
			history = zapi.history.get(itemids=itemids,
									   time_from=time_from,
									   time_till=time_till,
									   output='extend',
									   sortfield="clock",
									   sortorder="ASC",
									   history=0
									   )
	except Exception as e:
		history = str(e)
	
	return history




