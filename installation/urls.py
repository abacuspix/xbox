"""ops URL Configuration

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
from django.conf.urls import url,include
from django.contrib import admin
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    url(r'^post_server_info/',views.post_server_info,name='post_server_info'),
    url(r'^servers/init/',views.init,name='init'),
    url(r'^servers/install/',views.install,name='install'),
    url(r'^server/detail/(\w+)/$',views.server_detail,name='server_detail'),
    url(r'^server/delete/$',views.server_delete,name='server_delete'),
    url(r'^server/edit/(\w+)/$',views.server_edit,name='server_edit'),
    url(r'^server/raid/(\w+)/(\w+)/(\w*)',views.server_raid,name='server_raid'),
    url(r'^select_cab/',views.select_cab,name='select_cab'),
    url(r'^server/status/',views.server_change_status,name='server_change_status'),
    url(r'^server/power/$',views.server_power,name='server_power'),
    url(r'^ipmi/update/(\w+)/$',views.update_ipmi,name='update_ipmi'),
    url(r'^install_pre_post/$',views.install_pre_post,name='install_pre_post'),
    url(r'^server/install/(\w+)/$',views.get_system,name='get_system'),
    url(r'^server/add_system/(\w+)/$',views.add_system,name='add_system'),
    url(r'^server/edit_system/(\w+)/(\w+)/$',views.edit_system,name='edit_system'),
    url(r'^server/system/view/(\w+)/$',views.view_system,name='view_system'),
    url(r'^server/system/delete/(\w+)/(\w+)/$',views.delete_system,name='delete_system'),
    url(r'^vm/vcenter/$',views.vcenter,name='vcenter'),
    url(r'^vm/add_vcenter/$',views.add_vcenter,name='add_vcenter'),
    url(r'^vm/edit_vcenter/(\d+)/$',views.edit_vcenter,name='edit_vcenter'),
    url(r'^vm/delete_vcenter/(\d+)/$',views.delete_vcenter,name='delete_vcenter'),
    url(r'^vm/add_vm/$',views.add_vm,name='add_vm'),
    url(r'^vm/get_obj',views.get_obj,name='get_obj'),
    url(r'^installserver/$',views.cobbler,name='cobbler'),
    url(r'^installserver/add/$',views.add_cobbler,name='add_cobbler'),
    url(r'^installserver/edit/(\d+)/$',views.edit_cobbler,name='edit_cobbler'),
]


