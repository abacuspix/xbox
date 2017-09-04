# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from xbox.decorators import role_required
from xbox.paginator import paginator
from easyaudit.models import LoginEvent,CRUDEvent
# Create your views here.

@login_required
@role_required('admin')
def login_log(request):
	log_list = LoginEvent.objects.select_related().all()
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	logs,page_number = paginator(log_list,page,page_number)
	return render(request,'audit/login_log.html',locals())

@login_required
@role_required('admin')
def event_log(request):
	log_list = CRUDEvent.objects.select_related().filter(user__username__isnull=False)
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	logs,page_number = paginator(log_list,page,page_number)
	return render(request,'audit/event_log.html',locals())