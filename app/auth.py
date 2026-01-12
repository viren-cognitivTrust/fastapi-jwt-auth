import bcrypt
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.config import config
from app.database import get_db, User


class PasswordHasher:
    @staticmethod
    def hash_password(password: str) -> str:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


class TokenManager:
    ALGORITHM = "HS256"
    ALLOWED_ALGORITHMS = ["HS256"]
    CLOCK_SKEW_SECONDS = 10
    
    @staticmethod
    def create_access_token(user_id: int, email: str) -> str:
        now = datetime.utcnow()
        payload = {
            "sub": str(user_id),
            "email": email,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=config.access_token_expire_minutes),
            "nbf": now
        }
        return jwt.encode(payload, config.jwt_secret, algorithm=TokenManager.ALGORITHM)
    
    @staticmethod
    def create_refresh_token(user_id: int, email: str) -> str:
        now = datetime.utcnow()
        payload = {
            "sub": str(user_id),
            "email": email,
            "type": "refresh",
            "iat": now,
            "exp": now + timedelta(days=config.refresh_token_expire_days),
            "nbf": now
        }
        return jwt.encode(payload, config.jwt_refresh_secret, algorithm=TokenManager.ALGORITHM)
    
    @staticmethod
    def verify_access_token(token: str) -> Dict[str, Any]:
        try:
            payload = jwt.decode(
                token,
                config.jwt_secret,
                algorithms=TokenManager.ALLOWED_ALGORITHMS,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "require_exp": True,
                    "require_iat": True,
                    "require_nbf": True
                },
                leeway=TokenManager.CLOCK_SKEW_SECONDS
            )
            if payload.get("type") != "access":
                raise ValueError("Invalid token type")
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    
    @staticmethod
    def verify_refresh_token(token: str) -> Dict[str, Any]:
        try:
            payload = jwt.decode(
                token,
                config.jwt_refresh_secret,
                algorithms=TokenManager.ALLOWED_ALGORITHMS,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "require_exp": True,
                    "require_iat": True,
                    "require_nbf": True
                },
                leeway=TokenManager.CLOCK_SKEW_SECONDS
            )
            if payload.get("type") != "refresh":
                raise ValueError("Invalid token type")
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")


security_scheme = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> User:
    payload = TokenManager.verify_access_token(credentials.credentials)
    user_id = int(payload["sub"])
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

