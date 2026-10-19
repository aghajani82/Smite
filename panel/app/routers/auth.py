"""Authentication endpoints"""
from datetime import datetime, timedelta
import hmac
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, or_
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt

from app.database import get_db
from app.models import Admin
from app.config import settings
from app import mfa

router = APIRouter()
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = settings.secret_key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None


class MfaPasswordRequest(BaseModel):
    password: str


class MfaConfirmRequest(BaseModel):
    password: str
    code: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class TokenData(BaseModel):
    username: Optional[str] = None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> Admin:
    """Get the current authenticated user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    result = await db.execute(select(Admin).where(Admin.username == token_data.username))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    if payload.get("v", 0) != (user.auth_version or 0):
        raise credentials_exception
    if user.totp_secret and payload.get("mfa") is not True:
        raise credentials_exception
    return user


@router.post("/login", response_model=LoginResponse)
async def login(login_data: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    """Login endpoint"""
    result = await db.execute(select(Admin).where(Admin.username == login_data.username))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if user.totp_secret:
        if _mfa_locked(user):
            raise HTTPException(status_code=429, detail="Too many invalid codes. Please try again later.")
        if not login_data.mfa_code:
            raise HTTPException(status_code=428, detail="Two-factor code required")
        if not await _consume_factor(db, user, login_data.mfa_code):
            await _record_mfa_failure(db, user)
            raise HTTPException(status_code=401, detail="Invalid or already used two-factor code")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "mfa": bool(user.totp_secret), "v": user.auth_version or 0},
        expires_delta=access_token_expires
    )
    
    response.headers["Cache-Control"] = "no-store"
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        username=user.username
    )


@router.get("/me")
async def get_current_user_info(current_user: Admin = Depends(get_current_user)):
    """Get current user information"""
    return {
        "username": current_user.username,
        "id": current_user.id,
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None
    }


@router.post("/logout")
async def logout():
    """Logout endpoint (client-side token removal)"""
    return {"message": "Logged out successfully"}



def _mfa_locked(user: Admin) -> bool:
    return bool(user.mfa_locked_until and user.mfa_locked_until > datetime.utcnow())


async def _record_mfa_failure(db: AsyncSession, user: Admin):
    failures = (user.mfa_failures or 0) + 1
    user.mfa_failures = failures
    if failures >= 5:
        user.mfa_locked_until = datetime.utcnow() + timedelta(minutes=5)
    await db.commit()


async def _consume_factor(db: AsyncSession, user: Admin, code: str) -> bool:
    """Atomically consume a TOTP time-step or a single recovery code."""
    try:
        secret = mfa.open_secret(user.totp_secret)
    except (ValueError, TypeError):
        return False
    step = mfa.matching_step(secret, code, user.totp_last_counter)
    if step is not None:
        result = await db.execute(
            update(Admin)
            .where(Admin.id == user.id)
            .where(or_(Admin.totp_last_counter.is_(None), Admin.totp_last_counter < step))
            .values(totp_last_counter=step, mfa_failures=0, mfa_locked_until=None)
        )
        if result.rowcount == 1:
            await db.commit()
            return True
        return False

    digest = mfa.recovery_digest(code)
    codes = list(user.recovery_codes or [])
    if not any(hmac.compare_digest(saved, digest) for saved in codes):
        return False
    remaining = [saved for saved in codes if not hmac.compare_digest(saved, digest)]
    result = await db.execute(
        update(Admin).where(Admin.id == user.id, Admin.recovery_codes == codes)
        .values(recovery_codes=remaining, mfa_failures=0, mfa_locked_until=None)
    )
    if result.rowcount == 1:
        await db.commit()
        return True
    return False


@router.get("/2fa/status")
async def mfa_status(current_user: Admin = Depends(get_current_user)):
    return {"enabled": bool(current_user.totp_secret), "pending": bool(current_user.totp_pending_secret)}


@router.post("/2fa/setup")
async def mfa_setup(
    data: MfaPasswordRequest,
    response: Response,
    current_user: Admin = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not verify_password(data.password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect password")
    if current_user.totp_secret:
        raise HTTPException(status_code=409, detail="Two-factor authentication is already enabled")
    if not mfa.mfa_configured():
        raise HTTPException(status_code=503, detail="Configure a strong SECRET_KEY before enabling two-factor authentication")
    secret = mfa.new_secret()
    current_user.totp_pending_secret = mfa.seal_secret(secret)
    await db.commit()
    response.headers["Cache-Control"] = "no-store"
    uri = mfa.provisioning_uri(current_user.username, secret)
    return {
        "secret": secret,
        "otpauth_uri": uri,
        "qr_data_uri": mfa.local_qr_data_uri(uri),
    }


@router.post("/2fa/enable")
async def mfa_enable(
    data: MfaConfirmRequest,
    response: Response,
    current_user: Admin = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not verify_password(data.password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect password")
    if current_user.totp_secret:
        raise HTTPException(status_code=409, detail="Two-factor authentication is already enabled")
    if not current_user.totp_pending_secret:
        raise HTTPException(status_code=400, detail="Start two-factor setup first")
    try:
        pending = mfa.open_secret(current_user.totp_pending_secret)
    except ValueError:
        raise HTTPException(status_code=503, detail="Authenticator enrollment cannot be decrypted")
    step = mfa.matching_step(pending, data.code)
    if step is None:
        raise HTTPException(status_code=400, detail="Invalid authenticator code")
    codes = mfa.create_recovery_codes()
    current_user.totp_secret = current_user.totp_pending_secret
    current_user.totp_pending_secret = None
    current_user.totp_last_counter = step
    current_user.recovery_codes = [mfa.recovery_digest(code) for code in codes]
    current_user.mfa_failures = 0
    current_user.mfa_locked_until = None
    current_user.auth_version = (current_user.auth_version or 0) + 1
    await db.commit()
    token = create_access_token({"sub": current_user.username, "mfa": True, "v": current_user.auth_version})
    response.headers["Cache-Control"] = "no-store"
    return {"enabled": True, "recovery_codes": codes, "access_token": token, "username": current_user.username}


@router.post("/2fa/disable")
async def mfa_disable(
    data: MfaConfirmRequest,
    response: Response,
    current_user: Admin = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not verify_password(data.password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect password")
    if not current_user.totp_secret:
        raise HTTPException(status_code=409, detail="Two-factor authentication is not enabled")
    if _mfa_locked(current_user):
        raise HTTPException(status_code=429, detail="Too many invalid codes. Please try again later.")
    if not await _consume_factor(db, current_user, data.code):
        await _record_mfa_failure(db, current_user)
        raise HTTPException(status_code=401, detail="Invalid or already used two-factor code")
    # Re-read after atomic factor consumption to avoid stale ORM fields.
    await db.refresh(current_user)
    current_user.totp_secret = None
    current_user.totp_pending_secret = None
    current_user.recovery_codes = None
    current_user.totp_last_counter = None
    current_user.auth_version = (current_user.auth_version or 0) + 1
    current_user.mfa_failures = 0
    current_user.mfa_locked_until = None
    await db.commit()
    response.headers["Cache-Control"] = "no-store"
    return {"enabled": False}
