from typing import Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.database import get_db, User
from app.schemas import UserRegistration, UserLogin, TokenResponse, RefreshTokenRequest
from app.auth import PasswordHasher, TokenManager, get_current_user
from app.config import config

router = APIRouter()


def audit_log(event_type: str, user_id: Optional[int], details: Dict[str, Any]):
    sanitized_details = {k: v for k, v in details.items() if k not in ["password", "token", "secret"]}
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "user_id": user_id,
        "details": sanitized_details
    }
    print(f"AUDIT: {log_entry}")


@router.get("/health")
async def health_check():
    return {"status": "healthy"}


@router.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegistration, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Registration failed")
        
        hashed_password = PasswordHasher.hash_password(user_data.password)
        
        new_user = User(
            email=user_data.email,
            hashed_password=hashed_password
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        access_token = TokenManager.create_access_token(new_user.id, new_user.email)
        refresh_token = TokenManager.create_refresh_token(new_user.id, new_user.email)
        
        audit_log("USER_REGISTERED", new_user.id, {"email": new_user.email})
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        audit_log("USER_REGISTRATION_FAILED", None, {"error": "internal_error"})
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Registration failed")


@router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.email == credentials.email).first()
        if not user or not PasswordHasher.verify_password(credentials.password, user.hashed_password):
            audit_log("LOGIN_FAILED", None, {"email": credentials.email})
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        
        access_token = TokenManager.create_access_token(user.id, user.email)
        refresh_token = TokenManager.create_refresh_token(user.id, user.email)
        
        audit_log("USER_LOGIN", user.id, {"email": user.email})
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Login failed")


@router.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(token_request: RefreshTokenRequest, db: Session = Depends(get_db)):
    try:
        payload = TokenManager.verify_refresh_token(token_request.refresh_token)
        user_id = int(payload["sub"])
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        
        access_token = TokenManager.create_access_token(user.id, user.email)
        refresh_token = TokenManager.create_refresh_token(user.id, user.email)
        
        audit_log("TOKEN_REFRESHED", user.id, {"email": user.email})
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token refresh failed")


@router.get("/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "created_at": current_user.created_at.isoformat()
    }


@router.options("/{full_path:path}")
async def preflight_handler(request: Request):
    if config.allowed_origins:
        origin = request.headers.get("origin")
        if not origin or origin not in config.allowed_origins:
            raise HTTPException(status_code=403, detail="Origin not allowed")
    return {"status": "ok"}

