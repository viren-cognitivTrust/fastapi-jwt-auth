import os
import hmac
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()


class SecurityConfig:
    def __init__(self):
        self.jwt_secret = os.environ.get("JWT_SECRET_KEY", "")
        self.jwt_refresh_secret = os.environ.get("JWT_REFRESH_SECRET_KEY", "")
        self.access_token_expire_minutes = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
        self.refresh_token_expire_days = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
        self.allowed_origins = os.environ.get("ALLOWED_ORIGINS", "").split(",") if os.environ.get("ALLOWED_ORIGINS") else []
        self.max_request_body_size = int(os.environ.get("MAX_REQUEST_BODY_SIZE", "10240"))
        self.rate_limit_requests = int(os.environ.get("RATE_LIMIT_REQUESTS", "10"))
        self.rate_limit_window = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
        self.database_url = os.environ.get("DATABASE_URL", "sqlite:///./secure_app.db")
        
        self._validate()
    
    def _validate(self):
        if not self.jwt_secret or len(self.jwt_secret) < 32:
            raise RuntimeError("JWT_SECRET_KEY must be set and at least 32 characters")
        if not self.jwt_refresh_secret or len(self.jwt_refresh_secret) < 32:
            raise RuntimeError("JWT_REFRESH_SECRET_KEY must be set and at least 32 characters")
        if not self._constant_time_compare(self.jwt_secret, self.jwt_refresh_secret):
            if self.jwt_secret == self.jwt_refresh_secret:
                raise RuntimeError("JWT_SECRET_KEY and JWT_REFRESH_SECRET_KEY must be different")
        if self.access_token_expire_minutes < 1 or self.access_token_expire_minutes > 60:
            raise RuntimeError("ACCESS_TOKEN_EXPIRE_MINUTES must be between 1 and 60")
        if self.refresh_token_expire_days < 1 or self.refresh_token_expire_days > 30:
            raise RuntimeError("REFRESH_TOKEN_EXPIRE_DAYS must be between 1 and 30")
        if self.max_request_body_size > 1048576:
            raise RuntimeError("MAX_REQUEST_BODY_SIZE must not exceed 1MB")
        if self.rate_limit_requests < 1 or self.rate_limit_requests > 100:
            raise RuntimeError("RATE_LIMIT_REQUESTS must be between 1 and 100")
        if self.rate_limit_window < 1 or self.rate_limit_window > 3600:
            raise RuntimeError("RATE_LIMIT_WINDOW must be between 1 and 3600 seconds")
    
    @staticmethod
    def _constant_time_compare(a: str, b: str) -> bool:
        return hmac.compare_digest(a.encode(), b.encode())


config = SecurityConfig()

