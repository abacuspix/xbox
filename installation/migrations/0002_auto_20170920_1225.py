# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2017-09-20 04:25
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('installation', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='datacenter',
            name='vcenter',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='installation.Vcenter'),
        ),
    ]
