#!/bin/bash

cd /root/xbox/
# nohup python manage.py runserver 0.0.0.0:80 > /dev/null &
# sleep 1
nohup python manage.py rqworker high default low > /dev/null &
sleep 1
nohup python salt_event_to_mongo.py  > /dev/null &
