"""xbox URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^environment/$',views.envs,name='envs'),
    url(r'^environment/add_env/$',views.add_env,name='add_env'),
    url(r'^environment/edit_env/(\d+)/$',views.edit_env,name='edit_env'),
    url(r'^environment/delete/$',views.delete_env,name='delete_env'),
    url(r'^permission_rule/$',views.rules,name='rules'),
    url(r'^permission_rule/edit/(\d+)/$',views.edit_rule,name='edit_rule'),
    url(r'^hosts/$',views.hosts,name='hosts'),
    url(r'^host/(.+)/$',views.host,name='host'),
    url(r'^hosts/search/$',views.search_host,name='search_host'),
    url(r'^hosts/search_exact/$',views.search_exact_host,name='search_exact_host'),
    url(r'^hosts/add/$',views.add_host,name='add_host'),
    url(r'^hosts/add_batch/$',views.add_host_batch,name='add_host_batch'),
    url(r'^hosts/delete/(\d+)/$',views.delete_host,name='delete_host'),
    url(r'^hosts/delete_batch/$',views.delete_host_batch,name='delete_host_batch'),
    url(r'^hosts/edit/(\d+)/$',views.edit_host,name='edit_host'),
    url(r'^hosts/edit_batch/$',views.edit_host_batch,name='edit_host_batch'),
    url(r'^hostgroups/$',views.hostgroups,name='hostgroups'),
    url(r'^hostgroups/add/$',views.add_hostgroup,name='add_hostgroup'),
    url(r'^hostgroups/edit/(\d+)/$',views.edit_hostgroup,name='edit_hostgroup'),
    url(r'^hostgroups/delete/$',views.delete_hostgroup,name='delete_hostgroup'),
    url(r'^ops/cmd/$',views.cmd,name='cmd'),
    url(r'^ops/select_hosts/$',views.select_hosts,name='select_hosts'),
    url(r'^ops/search/$',views.search_host_for_cmd,name='search_host_for_cmd'),
    url(r'^ops/joblist/$',views.joblist,name='joblist'),
    url(r'^ops/job_cjid/(\d+)/$',views.job_cjid,name='job_cjid'),
    url(r'^ops/job_jid/(\d+)/$',views.job_jid,name='job_jid'),
    url(r'^ops/search_job/$',views.search_job,name='search_job'),
    url(r'^ops/cmds/$',views.cmds,name='cmds'),
    url(r'^ops/cmds/black/$',views.black_cmds,name='black_cmds'),
    url(r'^ops/cmds/add/$',views.add_cmd,name='add_cmd'),
    url(r'^ops/cmds/add_black/$',views.add_black_cmd,name='add_black_cmd'),
    url(r'^ops/cmds/edit/(\d+)/$',views.edit_cmd,name='edit_cmd'),
    url(r'^ops/cmds/delete/(\d+)/$',views.delete_cmd,name='delete_cmd'),
    url(r'^ops/cmds/delete/$',views.delete_cmds,name='delete_cmds'),
    url(r'^ops/save_cmd/$',views.save_cmd,name='save_cmd'),
    url(r'^ops/files/get/$',views.get_file,name='get_file'),
    url(r'^ops/files/put/$',views.put_file,name='put_file'),
    url(r'^ops/files/delete/(\d+)/$',views.delete_file,name='delete_file'),
    url(r'^ops/files/push/$',views.push_file,name='push_file'),
    url(r'^ops/scripts/$',views.scripts,name='scripts'),
    url(r'^ops/scripts/upload/$',views.upload_script,name='upload_script'),
    url(r'^ops/scripts/edit/(\d+)/$',views.edit_script,name='edit_script'),
    url(r'^ops/scripts/add/$',views.add_script,name='add_script'),
    url(r'^ops/scripts/copy/(\d+)/$',views.copy_script,name='copy_script'),
    url(r'^ops/scripts/delete/(\d+)/$',views.delete_script,name='delete_script'),
    url(r'^ops/scripts/exacute/(\d+)/$',views.exacute_script,name='exacute_script'),
    url(r'^ops/scripts/search/$',views.search_script,name='search_script'),
    url(r'^ops/states/$',views.states,name='states'),
    url(r'^ops/states/upload/$',views.upload_state,name='upload_state'),
    url(r'^ops/states/deploy/(\d+)/$',views.deploy_state,name='deploy_state'),
    url(r'^ops/states/delete/(\d+)/$',views.delete_state,name='delete_state'),
    url(r'^ops/cron/$',views.cron,name='cron'),
    url(r'^ops/cron/add/$',views.add_cron,name='add_cron'),
    url(r'^ops/cron/delete/(.+)/$',views.delete_cron,name='delete_cron'),
    url(r'^metrics/insert/$',views.metric_to_mongo,name='metric_to_mongo'),
    url(r'^metrics/show_host/(.+)/(.+)/$',views.show_host,name='show_host'),
    url(r'^metrics/show_performance/(.+)/(.+)/$',views.show_performance,name='show_performance'),
    url(r'^metrics/show_user/(.+)/(.+)/$',views.show_user,name='show_user'),
    url(r'^metrics/show_socket/(.+)/(.+)/$',views.show_socket,name='show_socket'),
    url(r'^metrics/show_process/(.+)/(.+)/$',views.show_process,name='show_process'),
    url(r'^zabbix/(.+)/(.+)/$',views.zabbix,name='zabbix'),
]



