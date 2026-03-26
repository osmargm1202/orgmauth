from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
from app.auth.router import router as auth_router
from app.api.public import router as public_router
from app.api.protected import router as protected_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="OrgAuth",
    description="Centralized authentication service using Google OAuth",
    version="0.1.0",
    lifespan=lifespan,
)

origins = [
    "http://localhost",
    "http://localhost:8500",
    "http://localhost:3000",
    "https://auth.or-gm.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(public_router)
app.include_router(protected_router)


@app.get("/")
def root():
    return {"service": "OrgAuth", "status": "running"}


@app.get("/health")
def health():
    return {"status": "healthy"}
