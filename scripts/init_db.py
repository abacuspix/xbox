# -*- coding: utf-8 -*-
from django.contrib.auth.models import User,Group
from opsdb.models import Role
import datetime

# create roles
roles = {'viewer':'访客','install':'装机','hostadmin':'主机管理','appadmin':'应用管理','admin':'管理员'}
try:
    for name,comment in roles.items():
        Role.objects.get_or_create(name=name,defaults={'comment':comment})
        print '***********',name,comment,'***********'
except Exception as e:
    print e

# create admin user
try:
    user,created = User.objects.get_or_create(username='admin',defaults ={ 'is_superuser': True })
    if created:
        user.set_password('admin@123')
        role = Role.objects.get(name='admin')
        user.profile.roles.add(role)
        user.profile.created_by = user
        user.save()
        group,created = Group.objects.get_or_create(name='admin')
        if created:
            user.groups.add(group)
    print '*************',user.username,'*************'
except Exception as e:
    raise e