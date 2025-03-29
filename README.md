# Store Project Services

This directory contains the services that make up the Store project:

## Backend

The backend directory contains the Django REST API application that powers the store's functionality.

- Located in `/services/backend`
- Runs on port 8001
- Provides API endpoints and admin interface

## Frontend

The frontend directory contains the web interface for the store.

- Located in `/services/frontend`
- Runs on port 8000
- Displays the store's user interface

## Running the Services

Use docker-compose to run all services together:

```bash
docker-compose up -d
```

### Access Points

- Frontend: http://localhost:8000
- Backend API: http://localhost:8001
- Nginx: http://localhost:8080 (routes /api and /admin to backend)
- PostgreSQL: localhost:5432
