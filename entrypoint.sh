#!/bin/sh

# Collect static files
python manage.py collectstatic --noinput

# Apply database migrations
python manage.py migrate

# Start Gunicorn server
exec gunicorn --bind 0.0.0.0:8000 core.wsgi:application
