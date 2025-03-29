#!/bin/sh

echo "====================================="
echo "🔹 Django Backend Service Starting 🔹"
echo "====================================="

echo "\n📦 Collecting static files..."
python manage.py collectstatic --noinput

echo "\n🔄 Running migrations generation..."
python manage.py makemigrations

echo "\n🔄 Applying database migrations..."
python manage.py migrate

echo "\n🚀 Starting Gunicorn server..."
echo "====================================="
exec gunicorn --bind 0.0.0.0:8000 core.wsgi:application
