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
from django.conf.urls import url,include
# from django.contrib import admin
from . import views

urlpatterns = [
    # url(r'^admin/', admin.site.urls),
    url(r'^$',views.base,name="base"),
    url(r'^blank/$',views.blank,name="blank"),
    url(r'^dashboard/$',views.dashboard,name="dashboard"),    
	url(r'^accounts/login',views.login,name="login"),
	url(r'^logout/',views.logout,name="logout"),
    url(r'^users/$',views.users,name="users"),
    url(r'^userprofile/(\d+)/$',views.userprofile,name="userprofile"),
    url(r'^changepasswd/$',views.changepasswd,name="changepasswd"),
    url(r'^add_user/$',views.add_user,name='add_user'),
    url(r'^edit_user/(\d+)/$',views.edit_user,name='edit_user'),
    url(r'^disable_user/$',views.disable_user,name='disable_user'),
    url(r'^enable_user/$',views.enable_user,name='enable_user'),
    url(r'^delete_user/$',views.delete_user,name='delete_user'),
    url(r'^reset_password/$',views.resetpwd,name='resetpwd'),
    url(r'^groups/$',views.groups,name='groups'),
    url(r'^group_has_users/(\d+)/$',views.group_has_users,name='group_has_users'),
    url(r'^add_group/$',views.add_group,name='add_group'),
    url(r'^edit_group/(\d+)/$',views.edit_group,name='edit_group'),
    url(r'^delete_group/$',views.delete_group,name='delete_group'),
    url(r'^audit/',include('audit.urls',namespace='audit')),
    url(r'^opsdb/',include('opsdb.urls',namespace='opsdb')),
    url(r'^django-rq/', include('django_rq.urls')),
    url(r'^installation/', include('installation.urls',namespace='installation')),
]
