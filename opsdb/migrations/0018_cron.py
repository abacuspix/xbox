# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2017-10-16 05:19
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('opsdb', '0017_auto_20170921_1137'),
    ]

    operations = [
        migrations.CreateModel(
            name='Cron',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cron_id', models.CharField(max_length=100)),
                ('cron_type', models.CharField(choices=[('C', 'command'), ('S', 'script')], default='C', max_length=1)),
                ('cron_string', models.CharField(max_length=200)),
                ('target', models.TextField()),
                ('arg_list', models.CharField(max_length=200)),
                ('create_time', models.DateTimeField(auto_now_add=True)),
                ('create_by', models.CharField(default='', max_length=200)),
                ('description', models.TextField()),
            ],
            options={
                'db_table': 'cron',
            },
        ),
    ]
