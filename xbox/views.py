# encoding:utf-8
from django.shortcuts import render
from django.shortcuts import redirect,HttpResponse
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User,Group
from opsdb.models import Role
from django.contrib import auth
from .decorators import role_required
from .paginator import my_paginator
from django.views.decorators.csrf import csrf_exempt

# Create your views here.
@login_required
def base(request):
	""" base """
	return render(request, 'base.html')

def blank(request):
	""" for test """
	return render(request, 'blank.html')

def dashboard(request):
	""" Dashboard"""
	return render(request, 'dashboard.html')

def login(request):
	""" user login """
	if request.method == 'GET':
		if request.user.is_authenticated():
			return redirect('/')
		else:
			return render(request,'login.html')
	else:
		username = request.POST.get('username','')
		password = request.POST.get('password','')
		user = authenticate(username=username, password=password)
		if user is not None:
			if user.is_active:
				auth_login(request,user)
				return redirect('/')
			else:
				messages.error(request, 'The acount is not actived or not exsit.')
				return render(request,'login.html')
		else:
			messages.error(request, 'The username or password is incorrect .')
			return render(request,'login.html')

@login_required
def logout(request):
	""" user logout """
	auth_logout(request)
	messages.info(request, 'Logout successfully !')
	return render(request,'login.html')

@login_required
def userprofile(request,id):
	""" show user profile """
	user = User.objects.get(id=id)
	if request.method == "POST":
		try:
			username = request.POST.get('username','')
			email = request.POST.get('email','')
			phone = request.POST.get('phone','')
			wechat = request.POST.get('wechat','')
			comment = request.POST.get('comment','')
			if username != user.username:
				user.username=username
			if email != user.email:
				user.email=email
			if phone != user.profile.phone:
				user.profile.phone = phone
			if wechat != user.profile.wechat:
				user.profile.wechat = wechat
			if comment != user.profile.comment:
				user.profile.comment = comment
			user.save()
			messages.success(request, '账户已更新')
		except Exception as e:
			messages.error(request, str(e))
	return render(request, 'userprofile.html',locals())

@login_required
def changepasswd(request):
	""" change password """
	if request.method == 'POST':
		oldpassword = request.POST.get('oldpassword', '')
		user = auth.authenticate(username=request.user.username, password=oldpassword)
		if user:
			newpassword = request.POST.get('newpassword', '')
			newpassword1 = request.POST.get('newpassword1', '')
			if newpassword == newpassword1:
				user.set_password(newpassword)
				user.save()
				messages.success(request, '密码修改成功')
				return redirect('dashboard')
			else:
				messages.error(request, '两次输入密码不同')
		else:
			messages.error(request, '旧密码错误！')
	return render(request, 'changepasswd.html',locals())

@login_required
@role_required('admin')
def users(request):
	user_list = User.objects.all()
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,users,page_number = my_paginator(user_list,page,page_number)
	return render(request,'users.html',locals())

@login_required
@role_required('admin')
@csrf_exempt
def add_user(request):
	roles = Role.objects.all()
	groups = Group.objects.all()
	if request.method == "GET":
		return render(request, 'add_user.html',locals())
	else:
		try:
			username = request.POST.get('username','')
			# password = request.POST.get('password','')
			roles = request.POST.getlist('roles','')
			groups = request.POST.getlist('groups','')
			is_active = bool(int(request.POST.get('is_active','')))
			email = request.POST.get('email','')
			phone = request.POST.get('phone','')
			wechat = request.POST.get('wechat','')
			comment = request.POST.get('comment','')
			user = User.objects.create(username=username,email=email,is_active=is_active)
			if user:
				user.set_password("1qaz@WSX")
				user.profile.roles = roles
				role_admin = Role.objects.get(name='admin')
				if role_admin.id in roles:
					user.is_superuser = True
				user.profile.created_by = request.user
				if phone:
					user.profile.phone = phone
				if wechat:
					user.profile.wechat = wechat
				if comment:
					user.profile.comment = comment
				if groups:
					user.groups = groups 
				user.save()
			messages.success(request, '用户添加成功')
		except Exception as e:
			messages.error(request, e)
		return redirect('users')

@login_required
@role_required('admin')
def edit_user(request,id):
	user = User.objects.get(id=id)
	roles = Role.objects.all()
	groups = Group.objects.all()
	if request.method == "GET":
		return render(request, 'edit_user.html',locals())
	else:
		try:
			username = request.POST.get('username','')
			new_roles = request.POST.getlist('roles','')
			new_groups = request.POST.getlist('groups','')
			email = request.POST.get('email','')
			phone = request.POST.get('phone','')
			wechat = request.POST.get('wechat','')
			comment = request.POST.get('comment','')
			user.profile.roles = new_roles
			user.groups = new_groups
			if username != user.username:
				user.username=username
			if email != user.email:
				user.email=email
			if phone != user.profile.phone:
				user.profile.phone = phone
			if wechat != user.profile.wechat:
				user.profile.wechat = wechat
			if comment != user.profile.comment:
				user.profile.comment = comment
			user.save()
			messages.success(request, '用户更新成功')
		except Exception as e:
			messages.error(request, e)
		return redirect('users')

@login_required
@role_required('admin')
@csrf_exempt
def delete_user(request):
	ids = request.POST.getlist('ids[]','')
	ret = 'success'
	try:
		User.objects.filter(pk__in=ids).delete()
	except Exception as e:
		ret = str(e)	
	return HttpResponse(ret)

@login_required
@role_required('admin')
@csrf_exempt
def disable_user(request):
	ids = request.POST.getlist('ids[]','')
	ret = 'success'
	try:
		User.objects.filter(pk__in=ids).update(is_active=False)
	except Exception as e:
		ret = str(e)
	return HttpResponse(ret)

@login_required
@role_required('admin')
@csrf_exempt
def enable_user(request):
	ids = request.POST.getlist('ids[]','')
	ret = 'success'
	try:
		User.objects.filter(pk__in=ids).update(is_active=True)
	except Exception as e:
		ret = str(e)
	return HttpResponse(ret)

@login_required
@role_required('admin')
@csrf_exempt
def resetpwd(request):
	ids = request.POST.getlist('ids[]','')
	ret = 'success'
	for user_id in ids:
		try:
			user = User.objects.get(pk=user_id)
			user.set_password('1qaz@WSX')
			user.save()
		except Exception as e:
			ret = str(e)
			break
	return HttpResponse(ret)

@login_required
@role_required('admin')
def groups(request):
	group_list = Group.objects.all()
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	paginator,groups,page_number = my_paginator(group_list,page,page_number)
	return render(request, 'groups.html',locals())

@login_required
@role_required('admin')
def group_has_users(request,id):
	user_list = Group.objects.get(pk=id).user_set.all()
	page_number =  request.GET.get('page_number')
	page = request.GET.get('page')
	users,page_number = paginator(user_list,page,page_number)
	return render(request,'users.html',locals())

@login_required
@role_required('admin')
@csrf_exempt
def add_group(request):
	users = User.objects.all()
	if request.method == "GET":
		return render(request, 'add_group.html',locals())
	else:
		name = request.POST.get('name','')
		members = request.POST.getlist('members','')
		try:
			group = Group.objects.create(name=name)
			if group and members:
				group.user_set = members
			messages.success(request, '用户组添加成功')
		except Exception as e:
			messages.error(request, e)
		return redirect('groups')

@login_required
@role_required('admin')
@csrf_exempt
def edit_group(request,id):
	group = Group.objects.get(id=id)
	users = User.objects.all()
	if request.method == "GET":
		return render(request,'edit_group.html',locals())
	else:
		name = request.POST.get('name','')
		members = request.POST.getlist('members','')
		try:
			if group.name != name:
				group.update(name=name)
			group.user_set = members
			messages.success(request, '更新成功')
		except Exception as e:
			messages.error(request, e)
		return redirect('groups')

@login_required
@role_required('admin')
@csrf_exempt
def delete_group(request):
	ids = request.POST.getlist('ids[]','')
	ret = 'success'
	try:
		Group.objects.filter(pk__in=ids).delete()
	except Exception as e:
		ret = str(e)
	return HttpResponse(ret)