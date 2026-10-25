from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .database import Base, engine, get_db
from .models import APIKey, User
from .schemas import (
    APIKeyCreate, APIKeyCreated, APIKeyOut, ProtectedData,
    TokenOut, UserCreate, UserOut,
)
from .security import (
    constant_time_hash_match, create_access_token, decode_access_token,
    generate_api_key, hash_api_key, hash_password, verify_password,
)

limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="SecureKey API",
    description=(
        "A demo API key management service. Register, sign in, create and revoke API keys, "
        "and access a protected endpoint. Use only for local learning and demonstrations."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    user_id = decode_access_token(token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def get_api_key_owner(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> User:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    candidate_hash = hash_api_key(x_api_key)
    key_record = db.scalar(select(APIKey).where(APIKey.key_hash == candidate_hash))
    if key_record is None or not key_record.active:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    return key_record.owner


@app.get("/", tags=["General"])
def home():
    return {"message": "Welcome to SecureKey API", "docs": "/docs"}


@app.get("/health", tags=["General"])
def health_check():
    return {"status": "healthy"}


@app.post("/auth/register", response_model=UserOut, status_code=201, tags=["Authentication"])
@limiter.limit("5/minute")
def register(request: Request, payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.scalar(select(User).where(User.email == payload.email.lower()))
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = User(email=payload.email.lower(), password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=TokenOut, tags=["Authentication"])
@limiter.limit("10/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.scalar(
        select(User).where(User.email == form_data.username.lower())
    )

    if user is None or not verify_password(
        form_data.password, user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
        )

    return {
        "access_token": create_access_token(user.id),
        "token_type": "bearer",
    }


@app.get("/users/me", response_model=UserOut, tags=["Authentication"])
def read_me(user: User = Depends(get_current_user)):
    return user


@app.post("/keys", response_model=APIKeyCreated, status_code=201, tags=["API Keys"])
def create_key(
    payload: APIKeyCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    raw_key = generate_api_key()
    record = APIKey(
        name=payload.name,
        key_prefix=raw_key[:16],
        key_hash=hash_api_key(raw_key),
        owner_id=user.id,
        active=True,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    # The full key is returned once only. It is not stored in the database.
    return {
        "id": record.id,
        "name": record.name,
        "key_prefix": record.key_prefix,
        "active": record.active,
        "created_at": record.created_at,
        "api_key": raw_key,
    }


@app.get("/keys", response_model=list[APIKeyOut], tags=["API Keys"])
def list_keys(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return list(db.scalars(select(APIKey).where(APIKey.owner_id == user.id).order_by(APIKey.id)))


@app.delete("/keys/{key_id}", status_code=204, tags=["API Keys"])
def revoke_key(
    key_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    record = db.scalar(select(APIKey).where(APIKey.id == key_id, APIKey.owner_id == user.id))
    if record is None:
        raise HTTPException(status_code=404, detail="API key not found")
    record.active = False
    db.commit()
    return None


@app.get("/protected/data", response_model=ProtectedData, tags=["Protected"])
@limiter.limit("30/minute")
def protected_data(request: Request, user: User = Depends(get_api_key_owner)):
    return {"message": "You accessed protected data with a valid API key", "user_id": user.id}
