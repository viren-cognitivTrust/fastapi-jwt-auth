import time
from collections import defaultdict
from threading import Lock
from typing import Dict
from fastapi import Request, HTTPException, Response

from app.config import config


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.clients: Dict[str, list] = defaultdict(list)
        self.lock = Lock()
        self.last_cleanup = time.time()
    
    def is_allowed(self, client_id: str) -> bool:
        current_time = time.time()
        
        with self.lock:
            self._cleanup_if_needed(current_time)
            
            if client_id not in self.clients:
                self.clients[client_id] = [current_time]
                return True
            
            timestamps = [ts for ts in self.clients[client_id] if current_time - ts < self.window_seconds]
            
            if len(timestamps) >= self.max_requests:
                self.clients[client_id] = timestamps
                return False
            
            timestamps.append(current_time)
            self.clients[client_id] = timestamps
            return True
    
    def _cleanup_if_needed(self, current_time: float):
        if current_time - self.last_cleanup > 300:
            cutoff = current_time - self.window_seconds
            clients_to_remove = []
            for client_id, timestamps in self.clients.items():
                active = [ts for ts in timestamps if ts > cutoff]
                if not active:
                    clients_to_remove.append(client_id)
                else:
                    self.clients[client_id] = active
            for client_id in clients_to_remove:
                del self.clients[client_id]
            self.last_cleanup = current_time


rate_limiter = RateLimiter(config.rate_limit_requests, config.rate_limit_window)


async def security_middleware(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    
    client_id = request.client.host if request.client else "unknown"
    if not rate_limiter.is_allowed(client_id):
        return Response(
            content='{"detail":"Rate limit exceeded"}',
            status_code=429,
            media_type="application/json"
        )
    
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > config.max_request_body_size:
        raise HTTPException(status_code=413, detail="Request body too large")
    
    if request.method in ["POST", "PUT", "PATCH"]:
        content_type = request.headers.get("content-type", "")
        if not content_type.startswith("application/json"):
            raise HTTPException(status_code=415, detail="Content-Type must be application/json")
    
    if config.allowed_origins:
        origin = request.headers.get("origin")
        if origin and origin not in config.allowed_origins:
            raise HTTPException(status_code=403, detail="Origin not allowed")
    
    response = await call_next(request)
    
    if config.allowed_origins and request.headers.get("origin"):
        origin = request.headers.get("origin")
        if origin in config.allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    
    return response



