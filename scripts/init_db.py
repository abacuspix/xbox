# -*- coding: utf-8 -*-
from django.contrib.auth.models import User,Group
from opsdb.models import Role
from installation.models import ServerStatus,Tag,Cobbler

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

# 创建数据来源<从LiveCD获取的信息会自动填入L，线上主机通过Agent抓取的为A>
tag = {'L':'livecd','A':'agent'}
try:
    for tag_type,description in tag.items():
        Tag.objects.get_or_create(tag_type=tag_type,defaults={'description':description})
        print '***********',tag_type,description,'***********'
except Exception as e:
    print e

    
# 创建物理服务器状态<初始化、安装系统、运行中、下线>
server_status = {'init':'初始化','install':'安装系统','running':'运行中','off_line':'下线'}
try:
    for status_type,status_name in server_status.items():
        ServerStatus.objects.get_or_create(status_type=status_type,defaults={'name':status_name})
        print '***********',status_type,status_name,'***********'
except Exception as e:
    print e

# 初始化cobbler
try:
    cobbler,created = Cobbler.objects.get_or_create(user='cobbler',defaults ={ 'ip': '0.0.0.0','password':'cobbler' })
    print '*************',cobbler.user,cobbler.ip,cobbler.password,'*************'
except Exception as e:
    print e

from xbox.settings import scheduler
from opsdb.jobs import check_minion_status,update_grains
try:
    job1 = scheduler.cron('*/10 * * * *',func=check_minion_status,args=['','',['all'],'checking minions status'],repeat=None,queue_name='default')
    print job1
    job2 = scheduler.cron('0 0 */3 * *',func=update_grains,args=['','',['all'],'updating grains'],repeat=None,queue_name='default')
    print job2
except Exception as e:
    print e




