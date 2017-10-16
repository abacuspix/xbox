"""
Django settings for xbox project.

Generated by 'django-admin startproject' using Django 1.11.4.

For more information on this file, see
https://docs.djangoproject.com/en/1.11/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.11/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.11/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '%qijyrvy)-+fmv&twl&vikpw1+z6$9dbut-!!(qcyeb42&zd+*'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'django_rq',
    'audit',
    'easyaudit',
    'opsdb',
    'installation',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    'easyaudit.middleware.easyaudit.EasyAuditMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

DJANGO_EASY_AUDIT_UNREGISTERED_CLASSES_EXTRA = ['installation.server','installation.disk','installation.nic','opsdb.file','opsdb.script']

ROOT_URLCONF = 'xbox.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'xbox.wsgi.application'


DATABASES = {  
    'default': { 
#       'ENGINE': 'django.db.backends.sqlite3',
#       'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
        'ENGINE': 'django.db.backends.mysql',  
        'NAME': 'devops',  
        'USER': 'devops',  
        'PASSWORD': 'devops',  
        'HOST': 'mysql',
        'PORT': '3306',  
    }  
} 


# Password validation
# https://docs.djangoproject.com/en/1.11/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/1.11/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Shanghai'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_URL = '/static/'
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static'),
)
#STATIC_ROOT = os.path.join(BASE_DIR, 'collectedstatic')

FTP_IP = '192.168.3.167'
FTP_PORT = '80'
SALT_MASTER_HOSTNAME = 'prod'
SALT_IP = 'salt'
SALT_PORT = '8080'
SALT_USER = 'salt_api'
SALT_PASSWD = 'salt_api'
SALT_FILE_ROOTS = '/srv/salt/files'
SALT_SCRIPTS = '/srv/salt/scripts'
SALT_STATES = '/srv/salt/states'
SALT_FILE_DOWNLOADS = '/var/cache/salt/master/minions'
MONGO_IP = 'mongo'
MONGO_PORT = '27017'
from pymongo import MongoClient
MONGO_CLIENT = MongoClient(MONGO_IP,int(MONGO_PORT))

from redis import Redis
from rq_scheduler import Scheduler
scheduler = Scheduler(connection=Redis())

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        "rq_console": {
            "format": "%(asctime)s %(message)s",
            "datefmt": "%H:%M:%S",
        },
    },
    'handlers': {
        "rq_console": {
            "level": "DEBUG",
            "class": "logging.handlers.TimedRotatingFileHandler",
            'filename': os.path.join(BASE_DIR, 'logs/rqworker.log'),
            "formatter": "rq_console",
        },
    },
    'loggers': {
        "rq.worker": {
            "handlers": ["rq_console"],
            "level": "DEBUG"
        },
    }
}
