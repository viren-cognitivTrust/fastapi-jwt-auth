# FastAPI JWT Authentication Backend

A secure FastAPI backend with user registration and login using JWT authentication, built with security best practices.

## Features

- 🔐 **Secure Password Handling**: Bcrypt hashing with cost factor 12
- 🎫 **JWT Authentication**: Access and refresh tokens with configurable expiration
- 🛡️ **Security Middleware**: Rate limiting, request size limits, CORS protection
- 📊 **Relational Database**: SQLAlchemy with SQLite (configurable for other databases)
- ✅ **Password Validation**: Strong password requirements (12+ chars, complexity rules)
- 🔍 **Audit Logging**: Structured logging for security events
- ⚙️ **Safe Configuration**: Environment-based configuration with validation

## Security Features

- JWT secrets must be at least 32 characters and different from each other
- Rate limiting per client IP (configurable, default: 10 requests per 60 seconds)
- Request body size limits (default: 10KB, hard cap: 1MB)
- Content-Type validation for state-changing operations
- CORS with explicit origin whitelisting
- Token type validation to prevent token confusion attacks
- Clock skew tolerance (10 seconds) for token validation
- Constant-time secret comparison to prevent timing attacks

## Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd fastapi-jwt-auth
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment:**
   - On Windows:
     ```bash
     venv\Scripts\activate
     ```
   - On Linux/Mac:
     ```bash
     source venv/bin/activate
     ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Set up environment variables:**
   ```bash
   cp .env.example .env
   ```

6. **Edit `.env` file and set your JWT secrets:**
   ```bash
   # Generate secure random strings
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
   
   Update `.env` with the generated secrets:
   ```
   JWT_SECRET_KEY=your-generated-secret-key-here
   JWT_REFRESH_SECRET_KEY=your-generated-refresh-secret-key-here
   ```

## Running the Application

```bash
python -m app.main
```

Or using uvicorn directly:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The API will be available at `http://127.0.0.1:8000`

## API Endpoints

### Health Check
- **GET** `/health` - Health check endpoint (no authentication required)

### Authentication
- **POST** `/auth/register` - Register a new user
  - Request body:
    ```json
    {
      "email": "user@example.com",
      "password": "SecurePass123!"
    }
    ```
  - Password requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character

- **POST** `/auth/login` - Login with email and password
  - Request body:
    ```json
    {
      "email": "user@example.com",
      "password": "SecurePass123!"
    }
    ```

- **POST** `/auth/refresh` - Refresh access token using refresh token
  - Request body:
    ```json
    {
      "refresh_token": "your-refresh-token"
    }
    ```

- **GET** `/auth/me` - Get current user information (requires authentication)
  - Headers: `Authorization: Bearer <access_token>`

## Example Usage

### Register a new user:
```bash
curl -X POST "http://127.0.0.1:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

### Login:
```bash
curl -X POST "http://127.0.0.1:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

### Get current user info:
```bash
curl -X GET "http://127.0.0.1:8000/auth/me" \
  -H "Authorization: Bearer <your-access-token>"
```

### Refresh token:
```bash
curl -X POST "http://127.0.0.1:8000/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<your-refresh-token>"
  }'
```

## Configuration

All configuration is done through environment variables (see `.env.example`):

- `JWT_SECRET_KEY`: Secret key for access tokens (required, min 32 chars)
- `JWT_REFRESH_SECRET_KEY`: Secret key for refresh tokens (required, min 32 chars, must be different)
- `ACCESS_TOKEN_EXPIRE_MINUTES`: Access token expiration (1-60 minutes, default: 15)
- `REFRESH_TOKEN_EXPIRE_DAYS`: Refresh token expiration (1-30 days, default: 7)
- `DATABASE_URL`: Database connection string (default: SQLite)
- `MAX_REQUEST_BODY_SIZE`: Maximum request body size in bytes (default: 10240)
- `RATE_LIMIT_REQUESTS`: Max requests per window (default: 10)
- `RATE_LIMIT_WINDOW`: Rate limit window in seconds (default: 60)
- `ALLOWED_ORIGINS`: Comma-separated list of allowed CORS origins (optional)

## Database

The application uses SQLAlchemy ORM. By default, it uses SQLite for development. To use PostgreSQL or MySQL, update the `DATABASE_URL` in your `.env` file:

```
DATABASE_URL=postgresql://user:password@localhost/dbname
```

The database schema is automatically created on first run.

## Security Notes

- All passwords are hashed using bcrypt with cost factor 12
- JWT tokens use HS256 algorithm with strict validation
- Rate limiting prevents brute force attacks
- Request size limits prevent DoS attacks
- CORS is enforced with explicit origin whitelisting
- Audit logs are generated for all authentication events
- Configuration is validated at startup to ensure security requirements

## Project Structure

```
fastapi-jwt-auth/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI application
│   ├── config.py        # Configuration management
│   ├── database.py      # Database setup and models
│   ├── schemas.py       # Pydantic models
│   ├── auth.py          # Authentication logic
│   ├── middleware.py    # Security middleware
│   └── routes.py        # API routes
├── .env.example         # Example environment variables
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## License

This project is provided as-is for educational and development purposes.

