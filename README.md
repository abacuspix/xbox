# xbox
[xbox](http://180.175.180.251:9000) (admin/admin@123) 是一个自动化运维平台，目前模块包括自动化装机(cobbler)、自动化配置(saltstack)、权限管理、操作审计。

### 技术栈
开发语言: python(2.7)

后端框架：Django(1.11)

前端框架：Bootstrap

数据库：MySQL(5.7),MongoDB(3.4)

自动化装机：Cobbler(2.8)

自动化配置： Saltstack(2016.5)

### Requirements

cobbler, saltstack, mongodb, mysql, django-rq（详细文档查看document内相关文档）

### QuickStart

####### 安装python开发库
```
pip install -r requirements.txt
```


####### 配置settings.py文件(根据实际情况修改配置)
主要修改以下条目
```
# Configure your queues for djanog-rq
RQ_QUEUES = {
    'default': {
        'HOST': 'localhost',
        'PORT': 6379,
        'DB': 0,
        # 'PASSWORD': 'some-password',
        'DEFAULT_TIMEOUT': 360,
    },
    'high': {
        'HOST': 'localhost',
        'PORT': 6379,
        'DB': 0,
        # 'PASSWORD': 'some-password',
        'DEFAULT_TIMEOUT': 360,
    },
    'low': {
        'HOST': 'localhost',
        'PORT': 6379,
        'DB': 0,
        # 'PASSWORD': 'some-password',
        'DEFAULT_TIMEOUT': 360,
    }
}

FTP_IP = '192.168.3.169'
FTP_PORT = '80'
SALT_MASTER_HOSTNAME = 'prod'
SALT_IP = '192.168.3.169'
SALT_PORT = '8080'
SALT_USER = 'salt_api'
SALT_PASSWD = 'salt_api'
SALT_FILE_ROOTS = '/srv/salt/files'
SALT_SCRIPTS = '/srv/salt/scripts'
SALT_STATES = '/srv/salt/states'
MONGO_IP = '192.168.3.169'
MONGO_PORT = '27017'
from pymongo import MongoClient
MONGO_CLIENT = MongoClient(MONGO_IP,int(MONGO_PORT))
```

####### 设置数据库

1、如果只是测试，可直接使用内置开发数据库(sqlite3)

```
DATABASES = {  
    'default': { 
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'), 
    }  
} 
```


2、使用MySQL

####### install MySQLdb
```
yum install -y MySQL-python
```

####### create db
```
mysql
create database opsdb default charset=utf8;
```

####### create user
```
grant all on opsdb.* to ops@'%' identified by "ops@123";
```

####### 根据实际修改opsp配置文件settings.py的数据库配置：

```
DATABASES = {  
    'default': { 
        'ENGINE': 'django.db.backends.mysql',  
        'NAME': 'opsdb',  
        'USER': 'ops',  
        'PASSWORD': 'ops@123',  
        'HOST': 'localhost',  
        'PORT': '3306',  
    }  
} 
```

####### 数据库迁移
```
cd xbox
python manage.py migrate
```

####### 初始化数据
```
cd xbox
python manage.py shell < scripts/init_db.py
```

####### 启动服务
进入项目文件夹启动服务
```
python manage.py runserver 0.0.0.0:8000
``` 

####### 登录
```
http://ip:8000  
初始账户及密码：admin/admin@123
```
