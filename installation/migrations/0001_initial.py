# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('opsdb', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Cluster',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, db_column='ha_id')),
                ('name', models.CharField(max_length=50, null=True, db_column='ha_name', blank=True)),
            ],
            options={
                'db_table': 'vm_cluster',
            },
        ),
        migrations.CreateModel(
            name='Cobbler',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, db_column='cobbler_id')),
                ('ip', models.GenericIPAddressField(unique=True, null=True, blank=True)),
                ('port', models.IntegerField(default=80, null=True, blank=True)),
                ('user', models.CharField(max_length=50, null=True, blank=True)),
                ('password', models.CharField(max_length=50, null=True, blank=True)),
            ],
            options={
                'db_table': 'cobbler',
            },
        ),
        migrations.CreateModel(
            name='Datacenter',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, db_column='dc_id')),
                ('name', models.CharField(max_length=50, null=True, db_column='dc_name', blank=True)),
            ],
            options={
                'db_table': 'vm_datacenter',
            },
        ),
        migrations.CreateModel(
            name='Datastore',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, db_column='datastore_id')),
                ('name', models.CharField(max_length=50, null=True, db_column='datastore_name', blank=True)),
                ('capacity', models.CharField(max_length=50, null=True, blank=True)),
                ('free_space', models.CharField(max_length=50, null=True, blank=True)),
                ('provisioned', models.CharField(max_length=50, null=True, blank=True)),
                ('uncommitted', models.CharField(max_length=50, null=True, blank=True)),
                ('hosts', models.IntegerField(default=0, null=True, blank=True)),
                ('vms', models.IntegerField(default=0, null=True, blank=True)),
            ],
            options={
                'db_table': 'vm_datastore',
            },
        ),
        migrations.CreateModel(
            name='Disk',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, db_column='disk_id')),
                ('path', models.CharField(max_length=30, null=True, db_column='disk_name', blank=True)),
                ('dtype', models.CharField(max_length=30, null=True, db_column='disk_model', blank=True)),
                ('raid_name', models.CharField(max_length=100, null=True, blank=True)),
                ('raid_type', models.CharField(max_length=100, null=True, blank=True)),
                ('size', models.CharField(max_length=30, null=True, db_column='disk_size', blank=True)),
            ],
            options={
                'db_table': 'disk',
            },
        ),
        migrations.CreateModel(
            name='Guest',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, db_column='guest_id')),
                ('name', models.CharField(max_length=50, null=True, db_column='guest_name', blank=True)),
                ('annotation', models.CharField(max_length=200, null=True, blank=True)),
                ('cpu', models.IntegerField(default=0, null=True, blank=True)),
                ('diskGB', models.CharField(max_length=50, null=True, blank=True)),
                ('folder', models.CharField(max_length=50, null=True, blank=True)),
                ('mem', models.IntegerField(default=0, null=True, blank=True)),
                ('ostype', models.CharField(max_length=50, null=True, blank=True)),
                ('path', models.CharField(max_length=50, null=True, blank=True)),
                ('status', models.CharField(max_length=50, null=True, blank=True)),
                ('is_template', models.BooleanField(default=False)),
                ('datastore', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, blank=True, to='installation.Datastore', null=True)),
            ],
            options={
                'db_table': 'vm_guest',
            },
        ),
        migrations.CreateModel(
            name='Host',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, db_column='host_id')),
                ('ip', models.GenericIPAddressField(unique=True, null=True, blank=True)),
                ('cluster', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, blank=True, to='installation.Cluster', null=True)),
            ],
            options={
                'db_table': 'vm_host',
            },
        ),
        migrations.CreateModel(
            name='Nic',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, db_column='nic_id')),
                ('name', models.CharField(max_length=20, null=True, db_column='nic_name', blank=True)),
                ('mac', models.CharField(max_length=50, null=True, db_column='mac', blank=True)),
                ('model', models.CharField(max_length=100, null=True, db_column='nic_model', blank=True)),
            ],
            options={
                'db_table': 'nic',
            },
        ),
        migrations.CreateModel(
            name='PreSystem',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('ip', models.GenericIPAddressField(unique=True, null=True, blank=True)),
                ('name', models.CharField(max_length=50, null=True, blank=True)),
                ('hostname', models.CharField(max_length=50, null=True, blank=True)),
                ('mac', models.CharField(max_length=50, null=True, blank=True)),
                ('profile', models.CharField(max_length=50, null=True, blank=True)),
                ('progress', models.IntegerField(default=-1, null=True, blank=True)),
                ('create_time', models.DateTimeField(auto_now_add=True)),
                ('update_time', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['-create_time'],
                'db_table': 'pre_system',
            },
        ),
        migrations.CreateModel(
            name='Server',
            fields=[
                ('id', models.CharField(max_length=100, serialize=False, primary_key=True, db_column='server_id')),
                ('sn', models.CharField(max_length=100, null=True, blank=True)),
                ('cpu_model', models.CharField(max_length=100, null=True, blank=True)),
                ('cpu_sockets', models.IntegerField(null=True, blank=True)),
                ('cpu_cores', models.IntegerField(null=True, blank=True)),
                ('cpu_threads', models.IntegerField(null=True, blank=True)),
                ('mem_size', models.IntegerField(null=True, blank=True)),
                ('mem_total_slots', models.IntegerField(null=True, blank=True)),
                ('mem_free_slots', models.IntegerField(null=True, blank=True)),
                ('raid_adapter', models.CharField(max_length=200, null=True, blank=True)),
                ('raid_adapter_slot', models.CharField(max_length=20, null=True, blank=True)),
                ('ipmi_ip', models.GenericIPAddressField(null=True, blank=True)),
                ('ipmi_user', models.CharField(max_length=30, null=True, blank=True)),
                ('ipmi_pass', models.CharField(max_length=30, null=True, blank=True)),
                ('unit', models.IntegerField(null=True, blank=True)),
                ('pxe_mac', models.CharField(max_length=30, null=True, blank=True)),
                ('pxe_ip', models.GenericIPAddressField(null=True, blank=True)),
                ('vendor', models.CharField(max_length=30, null=True, blank=True)),
                ('model', models.CharField(max_length=30, null=True, blank=True)),
                ('prod_ip', models.GenericIPAddressField(null=True, blank=True)),
                ('power', models.CharField(default='on', max_length=10, null=True, blank=True)),
                ('create_time', models.DateTimeField(auto_now_add=True)),
                ('update_time', models.DateTimeField(auto_now=True)),
                ('cabinet', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, blank=True, to='opsdb.Cabinet', null=True)),
                ('contacter', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, blank=True, to='opsdb.Contacter', null=True)),
            ],
            options={
                'ordering': ['-create_time'],
                'db_table': 'server',
            },
        ),
        migrations.CreateModel(
            name='ServerStatus',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, db_column='server_status_id')),
                ('status_type', models.CharField(max_length=50, null=True, db_column='server_status_type', blank=True)),
                ('name', models.CharField(max_length=100, null=True, db_column='server_status_name', blank=True)),
            ],
            options={
                'db_table': 'server_status',
            },
        ),
        migrations.CreateModel(
            name='Tag',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, db_column='tag_id')),
                ('tag_type', models.CharField(max_length=10, null=True, blank=True)),
                ('description', models.CharField(max_length=30, null=True, blank=True)),
            ],
            options={
                'db_table': 'tag',
            },
        ),
        migrations.CreateModel(
            name='Vcenter',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, db_column='vc_id')),
                ('name', models.CharField(max_length=50, null=True, db_column='vc_name', blank=True)),
                ('ip', models.GenericIPAddressField(unique=True, null=True, blank=True)),
                ('port', models.CharField(default='443', max_length=10)),
                ('user', models.CharField(max_length=50, null=True, blank=True)),
                ('password', models.CharField(max_length=50, null=True, blank=True)),
            ],
            options={
                'db_table': 'vcenter',
            },
        ),
        migrations.CreateModel(
            name='Vnet',
            fields=[
                ('mac', models.CharField(max_length=50, serialize=False, primary_key=True, db_column='mac')),
                ('connected', models.CharField(max_length=50, null=True, blank=True)),
                ('ip', models.GenericIPAddressField(unique=True, null=True, blank=True)),
                ('netlabel', models.CharField(max_length=100, null=True, blank=True)),
                ('prefix', models.CharField(max_length=50, null=True, blank=True)),
                ('guest', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, blank=True, to='installation.Guest', null=True)),
            ],
            options={
                'db_table': 'vm_guest_net',
            },
        ),
        migrations.AddField(
            model_name='server',
            name='serverstatus',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, blank=True, to='installation.ServerStatus', null=True),
        ),
        migrations.AddField(
            model_name='server',
            name='tag',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, blank=True, to='installation.Tag', null=True),
        ),
        migrations.AddField(
            model_name='presystem',
            name='server',
            field=models.OneToOneField(to='installation.Server'),
        ),
        migrations.AddField(
            model_name='nic',
            name='server',
            field=models.ForeignKey(to='installation.Server'),
        ),
        migrations.AddField(
            model_name='host',
            name='server',
            field=models.OneToOneField(null=True, on_delete=django.db.models.deletion.PROTECT, blank=True, to='installation.Server'),
        ),
        migrations.AddField(
            model_name='guest',
            name='host',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, blank=True, to='installation.Host', null=True),
        ),
        migrations.AddField(
            model_name='disk',
            name='server',
            field=models.ForeignKey(to='installation.Server'),
        ),
        migrations.AddField(
            model_name='datastore',
            name='vcenter',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, blank=True, to='installation.Vcenter', null=True),
        ),
        migrations.AddField(
            model_name='datacenter',
            name='vcenter',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, blank=True, to='installation.Vcenter', null=True),
        ),
        migrations.AddField(
            model_name='cluster',
            name='datacenter',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, blank=True, to='installation.Datacenter', null=True),
        ),
    ]
