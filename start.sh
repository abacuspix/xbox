#!/bin/bash
cd /usr/local/xbox
python manage.py migrate
python manage.py shell < scripts/init_db.py
nohup python manage.py rqworker high default low > /dev/null &
