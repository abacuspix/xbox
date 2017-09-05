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
    url(r'^hosts/add/$',views.add_host,name='add_host'),
    url(r'^hosts/add_batch/$',views.add_host_batch,name='add_host_batch'),
    url(r'^hosts/delete/(\d+)/$',views.delete_host,name='delete_host'),
    url(r'^hosts/delete_batch/$',views.delete_host_batch,name='delete_host_batch'),
    url(r'^hosts/search_exact/$',views.search_exact,name='search_exact'),
    url(r'^hosts/edit/(\d+)/$',views.edit_host,name='edit_host'),
    url(r'^hosts/edit_batch/$',views.edit_host_batch,name='edit_host_batch'),
    url(r'^hostgroups/$',views.hostgroups,name='hostgroups'),
    url(r'^hostgroups/add/$',views.add_hostgroup,name='add_hostgroup'),
    url(r'^hostgroups/edit/(\d+)/$',views.edit_hostgroup,name='edit_hostgroup'),
    url(r'^hostgroups/delete/$',views.delete_hostgroup,name='delete_hostgroup'),
    url(r'^ops/cmd/$',views.cmd,name='cmd'),
    url(r'^ops/select_hosts/$',views.select_hosts,name='select_hosts'),
]
