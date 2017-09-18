#coding:utf-8
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.cache import cache
from django.http import  HttpResponse
import re,json
from opsdb.models import Cmd

def role_required(*role_names):
	"""Requires user passed in."""
	def in_roles(u):
		if u.is_authenticated():
			if bool(u.profile.roles.filter(name__in=role_names)) | u.is_superuser:
				return True
			else:
				raise PermissionDenied
		else:
			raise PermissionDenied
		return False
	return user_passes_test(in_roles)

def black_command_check(func):
	def wrapper_black_command(request,*args,**kws):
		if request.method == 'POST':
			black_command_list = Cmd.objects.filter(command_type='black')  
			if black_command_list:
				command=request.POST.get('cmd')
				_command=re.sub('^ *| *$','',command)
				for _cmd in black_command_list:
					if re.search(_cmd.argument,_command):
						# if request.user.is_superuser or request.user.profile.role.name == 'admin':
						# 	break
						# else:
						raise PermissionDenied
		return func(request,*args,**kws)
	return wrapper_black_command
