# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2017-09-05 05:38
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0008_alter_user_username_max_length'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('opsdb', '0002_auto_20170901_1545'),
    ]

    operations = [
        migrations.CreateModel(
            name='Rule',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('comment', models.TextField(blank=True, max_length=100)),
            ],
            options={
                'db_table': 'permission_rule',
            },
        ),
        migrations.RemoveField(
            model_name='application',
            name='groups',
        ),
        migrations.RemoveField(
            model_name='hostgroup',
            name='groups',
        ),
        migrations.RemoveField(
            model_name='host',
            name='environment',
        ),
        migrations.AddField(
            model_name='host',
            name='environment',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='opsdb.Environment'),
        ),
        migrations.AlterField(
            model_name='host',
            name='minion_status',
            field=models.CharField(choices=[('O', 'OK'), ('E', 'Error'), ('N', 'Uninstall')], default='N', max_length=1),
        ),
        migrations.AddField(
            model_name='rule',
            name='applications',
            field=models.ManyToManyField(to='opsdb.Application'),
        ),
        migrations.AddField(
            model_name='rule',
            name='created_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='rule',
            name='group',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='rule', to='auth.Group'),
        ),
        migrations.AddField(
            model_name='rule',
            name='hostgroups',
            field=models.ManyToManyField(to='opsdb.HostGroup'),
        ),
    ]
