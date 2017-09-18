# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.

from django.contrib.auth.models import User,Group
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

class Role(models.Model):
	name           = models.CharField(max_length=30, blank=True)
	comment        = models.TextField(max_length=100,blank=True)

	class Meta:
		db_table = 'user_role'

	def __str__(self):
		return self.name

class Profile(models.Model):
	user          = models.OneToOneField(User,related_name='profile', on_delete=models.CASCADE)
	roles         = models.ManyToManyField(Role)
	phone         = models.CharField(max_length=30, blank=True)
	wechat        = models.CharField(max_length=30, blank=True)
	created_by    = models.ForeignKey(User,related_name='created_by',blank=True, null=True,on_delete=models.PROTECT)
	is_delele     = models.BooleanField(default=False)
	comment       = models.TextField(max_length=100,blank=True)

	class Meta:
		db_table = 'user_profile'

	def __str__(self):
		return self.user.username

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
	if created:
		Profile.objects.create(user=instance)
	instance.profile.save()

class Environment(models.Model):
	name           = models.CharField(max_length=100,blank=True,null=True)
	comment        = models.TextField(max_length=200,blank=True)
	class Meta:
		db_table = 'environment'

	def __unicode__(self):
		return self.name


class Application(models.Model):
	name           = models.CharField(max_length=50,blank=True,null=True)
	comment        = models.TextField(max_length=200,blank=True)

	class Meta:
		db_table = 'application'

	def __unicode__(self):
		return self.name

class HostGroup(models.Model):
	name           = models.CharField(max_length=50,blank=True,null=True)
	comment        = models.TextField(max_length=200,blank=True)

	class Meta:
		db_table = 'hostgroup'

	def __unicode__(self):
		return self.name

class Host(models.Model):
	minion_status_choices =(("O","OK"),("E","Error"),("N","Uninstall"))
	ip            = models.GenericIPAddressField(unique=True)
	hostname      = models.CharField(max_length=100,blank=True,null=True)
	os            = models.CharField(max_length=30,blank=True,null=True)
	is_virtual    = models.CharField(max_length=30,blank=True,null=True)
	minion_id     = models.CharField(max_length=100,unique=True,blank=True,null=True)
	minion_status = models.CharField(max_length=1,choices=minion_status_choices,default="N")
	comment       = models.CharField(max_length=200,blank=True,null=True)
	hostgroups    = models.ManyToManyField(HostGroup)
	applications  = models.ManyToManyField(Application)
	environment   = models.ForeignKey(Environment,blank=True, null=True,on_delete=models.PROTECT)
	create_time   = models.DateTimeField(auto_now_add=True)
	update_time   = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'host'
		
	def __unicode__(self):
		return self.name

class Rule(models.Model):
	group         = models.OneToOneField(Group,related_name='rule', on_delete=models.CASCADE)
	hostgroups    = models.ManyToManyField(HostGroup)
	applications  = models.ManyToManyField(Application)
	created_by    = models.ForeignKey(User,blank=True, null=True,on_delete=models.PROTECT)
	comment       = models.TextField(max_length=100,blank=True)

	class Meta:
		db_table = 'permission_rule'

	def __str__(self):
		return self.group.name

@receiver(post_save, sender=Group)
def create_or_update_group_rule(sender, instance, created, **kwargs):
	if created:
		Rule.objects.create(group=instance)
	instance.rule.save()

class Idc(models.Model):
	name               = models.CharField(max_length=100,blank=True,null=True)
	address            = models.CharField(max_length=100,blank=True,null=True)
	comment            = models.TextField(max_length=200,blank=True,default='')

	class Meta:
		db_table = 'idc'

	def __unicode__(self):
		return self.name

class Cabinet(models.Model): 
	sn                 = models.CharField(max_length=100,blank=True,null=True)
	location           = models.CharField(max_length=100,blank=True,null=True)
	size               = models.IntegerField(blank=True,null=True)
	idc                = models.ForeignKey(Idc,blank=True, null=True,on_delete=models.PROTECT)
	comment            = models.TextField(max_length=200,blank=True,default='')
	class Meta:
		db_table = 'cabinet'

	def __unicode__(self):
		return self.sn

class Contacter(models.Model):
	name               = models.CharField(max_length=30,blank=True,null=True)
	phone              = models.CharField(max_length=30,blank=True,null=True)
	email              = models.EmailField(blank=True,null=True)
	dept               = models.CharField(max_length=30,blank=True,null=True)
	company            = models.CharField(max_length=30,blank=True,null=True)

	class Meta:
		db_table = 'contacter'

	def __unicode__(self):
		return self.name

class Cmd(models.Model):
	name               = models.CharField(unique=True,max_length=100)
	argument           = models.CharField(max_length=200,blank=True,null=True)
	created_by         = models.CharField(max_length=80,blank=True,null=True)
	command_type       = models.CharField(max_length=80,default='common')
	create_time        = models.DateTimeField(auto_now_add=True)
	update_time        = models.DateTimeField(auto_now=True)
	comment            = models.CharField(max_length=200,blank=True,null=True)

	class Meta:
		db_table = 'command'

	def __unicode__(self):
		return self.name

class Script(models.Model):
	name               = models.CharField(unique=True,max_length=100)
	script_name        = models.CharField(unique=True,max_length=100)
	created_by         = models.CharField(max_length=80,blank=True,null=True)
	comment            = models.CharField(max_length=200,blank=True,null=True)
	create_time        = models.DateTimeField(auto_now_add=True)
	update_time        = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'script'

	def __unicode__(self):
		return self.name		

class SaltState(models.Model):
	name               = models.CharField(unique=True,max_length=100)
	state_name         = models.CharField(unique=True,max_length=100)
	created_by         = models.CharField(max_length=80,blank=True,null=True)
	comment            = models.CharField(max_length=200,blank=True,null=True)
	create_time        = models.DateTimeField(auto_now_add=True)
	update_time        = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'state'

	def __unicode__(self):
		return self.name

class File(models.Model):
	name               = models.CharField(max_length=100)
	created_by         = models.CharField(max_length=80,blank=True,null=True)
	file_type          = models.CharField(max_length=20,default='upload')
	create_time        = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'file'

	def __unicode__(self):
		return self.name
