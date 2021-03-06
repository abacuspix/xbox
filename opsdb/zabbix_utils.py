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
	ret = {}
	try:
		data = zapi.item.get(output=['itemid','key_'],hostids=hostid,search={"key_": key})
		if data:
			for ele in data:
				ret[ele['key_']] = ele['itemid']
	except Exception as e:
		ret = str(e)

	return ret


def get_graph_by_ip(ip):
	ret = {}
	try:
		hostid = get_hostid_by_ip(ip)
		graphids = zapi.graph.get(output=["graphid",'name'],hostids=hostid)
		if graphids:
			for ele in graphids:
				ret[ele['name']] = ele['graphid']
	except Exception as e:
		ret = str(e)
	return ret

def get_item_by_graphid(graphid):
	ret = {}
	try:
		itemids = zapi.graphitem.get(output=['itemid'],graphids=graphid)
		if itemids:
			ids = []
			for ele in itemids:
				ids.append(ele['itemid'])
			items = zapi.item.get(output=['key_'],itemids=ids)
			if items:
				for ele in items:
					ret[ele['key_']] = ele['itemid']
	except Exception as e:
		ret = str(e)
	return ret

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
