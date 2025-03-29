# Django Authentication API

This project is a Django-based authentication API that provides user management and authentication functionalities.

## Features

- User registration with email verification
- User login with JWT authentication
- Password reset functionality
- User logout
- Last activity tracking
- Rate limiting for API endpoints

## Setup

1. Clone the repository
2. Create a virtual environment and activate it
3. Install dependencies: `pip install -r requirements.txt`
4. Copy `env-example.txt` to `.env` and fill in your environment variables
5. Run migrations: `python manage.py migrate`
6. Start the server: `python manage.py runserver`

## Environment Variables

- `SECRET_KEY`: Django secret key
- `DATABASE_URL`: PostgreSQL database URL
- `EMAIL_HOST`: SMTP server host
- `EMAIL_HOST_USER`: Email username
- `EMAIL_HOST_PASSWORD`: Email password
- `DEFAULT_FROM_EMAIL`: Default sender email address

## API Endpoints

- `/api/signup/`: User registration
- `/api/login/`: User login
- `/api/verify-email/`: Email verification
- `/api/logout/`: User logout
- `/api/password-reset/`: Password reset functionality
- `/api/profile/`: User profile
- `/api/profile/update/`: Update user profile

## Security Features

- JWT token-based authentication
- Email verification for new user registrations
- OTP-based password reset
- Token blacklisting for logout
- Rate limiting to prevent abuse

## Technologies Used

- Django
- Django Rest Framework
- Simple JWT
- PostgreSQL
- SMTP for email sending

For more detailed information, please refer to the source code and comments within the project files.
