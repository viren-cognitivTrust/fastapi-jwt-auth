from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.database import Base, engine
from app.routes import router
from app.middleware import security_middleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="FastAPI JWT Authentication",
    description="Secure FastAPI backend with JWT authentication",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

app.middleware("http")(security_middleware)
app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

