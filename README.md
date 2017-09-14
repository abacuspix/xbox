# 自动化运维平台 
## 1、从github下载开发代码

```
git clone https://github.com/uevol/xbox.git
```

## 2、配置python开发库

### 方法1、直接从网络安装
#### 配置pip豆瓣源(可选,可以有效提升安装速度)
```
mkdir  ~/.pip/
cd ~/.pip/
vi pip.conf

[global]
index-url = http://pypi.douban.com/simple
trusted-host = pypi.douban.com
```

#### 实际测试在pip install之前以下软件需提前安装：
```
yum -y install MySQL-python
yum -y install python-devel libxml2-devel libxslt-devel gcc
yum -y install openssl openssl-devel
```

#### 安装python开发库
```
cd vbox/ops/
pip install -r requirements.txt
```


## 3、配置settings.py文件(根据实际情况修改配置)
主要修改以下条目
```
# Configure your queues
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

## 4、设置数据库

### 如果只是测试，可直接使用内置开发数据库(sqlite3)

#### 修改opsp配置文件settings.py的数据库配置：
```
DATABASES = {  
    'default': { 
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'), 
    }  
} 
```

### for postgresql

#### 切换用户
```
su postgres
psql -U postgres 
```

#### 修改密码(可选)：
```
\password postgres  
```

#### 创建数据库用户dbuser，并设置密码:
```
CREATE USER ops WITH PASSWORD 'ops@123';  
```

#### 创建用户数据库，这里为opsdb，并指定所有者为ops:
```
CREATE DATABASE ops OWNER ops;  
```

#### 将opsdb数据库的所有权限都赋予ops，否则ops只能登录控制台，没有任何数据库操作权限:
```
GRANT ALL PRIVILEGES ON DATABASE opsdb to ops;  
```

#### 登录数据库
```
psql -U ops -d opsdb -h 127.0.0.1 -p 5432;  
```

#### 根据实际修改opsp配置文件settings.py的数据库配置：

```
DATABASES = {  
    'default': { 
        'ENGINE': 'django.db.backends.psql',  
        'NAME': 'opsdb',  
        'USER': 'ops',  
        'PASSWORD': 'ops@123',  
        'HOST': '192.168.31.200',  
        'PORT': '5432',  
    }  
} 
```

### for mysql

#### install MySQLdb
```
yum install -y MySQL-python
```

#### create db
```
mysql
create database opsdb default charset=utf8;
```

#### create user
```
grant all on opsdb.* to ops@'%' identified by "ops@123";
```

#### 根据实际修改opsp配置文件settings.py的数据库配置：

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

## 5、数据库迁移
```cd ops
python manage.py migrate
```

## 6、初始化数据
```
cd opsp/ops/
python manage.py shell < scripts/init_db.py
```

## 7、启动服务
进入项目文件夹启动服务
```
python manage.py runserver 0.0.0.0:8000
``` 

## 8、登录
```
http://ip:8000  
初始账户及密码：admin/admin@123
```
