# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2017-09-15 08:52
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('opsdb', '0011_auto_20170915_1650'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='name',
            field=models.CharField(max_length=100),
        ),
    ]
