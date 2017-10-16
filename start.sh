#!/bin/bash
cd /usr/local/xbox
python manage.py migrate
nohup rqscheduler > /dev/null &
python manage.py shell < scripts/init_db.py
nohup python manage.py rqworker high default low > /dev/null &
