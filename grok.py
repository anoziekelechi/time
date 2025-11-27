
@router.post("/admin/disable")
async def disable_user(
    data: UserActionSchema,
    current_user: User = Depends(require_admin),
    _: None = Depends(verify_csrf_token),  # ← CSRF PROTECTION
    db: AsyncSession = Depends(get_session)
):
    await crud.disable_user_account(data=data, session=db, performed_by=current_user.id)
    return {"msg": "User disabled"}

# core/security.py
import jwt
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

# CONFIG
PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY\n-----END PRIVATE KEY-----"
PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nYOUR_PUBLIC_KEY\n-----END PUBLIC KEY-----"
ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 20
REFRESH_TOKEN_EXPIRE_DAYS = 30

def create_access_token(user_id: int, jti: str | None = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    payload = {
        "sub": user_id,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": jti or secrets.token_urlsafe(32),
        "token_type": "access"
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)

async def create_refresh_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    jti = secrets.token_urlsafe(32)
    
    payload = {
        "sub": user_id,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": jti,
        "token_type": "refresh"
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)
    
    # Store in Redis set
    async with get_redis() as r:
        await r.sadd(f"user_refresh:{user_id}", token)
        await r.expire(f"user_refresh:{user_id}", REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60)
    
    return token

async def revoke_refresh_token(refresh_token: str):
    try:
        payload = jwt.decode(refresh_token, PUBLIC_KEY, algorithms=[ALGORITHM])
        user_id = payload["sub"]
        jti = payload["jti"]
        
        async with get_redis() as r:
            await r.srem(f"user_refresh:{user_id}", refresh_token)
            await r.set(f"blacklist:refresh:{jti}", "1", ex=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60)
    except:
        pass  # already invalid

# core/security.py (add this function)

async def validate_refresh_token(refresh_token: str) -> int:
    """
    Validates a refresh token and returns user_id if valid.
    Used in /refresh endpoint.
    """
    async with get_redis() as r:
        # 1. Check if token is blacklisted (by jti)
        try:
            # First decode without verification first to get jti
            unverified = jwt.decode(refresh_token, options={"verify_signature": False})
            jti = unverified.get("jti")
            token_type = unverified.get("token_type")

            if not jti or token_type != "refresh":
                raise HTTPException(status_code=401, detail="Invalid refresh token")

            if await r.get(f"blacklist:refresh:{jti}"):
                raise HTTPException(status_code=401, detail="Token revoked")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid token format")

        # 2. Now verify signature + expiration
        try:
            payload = jwt.decode(
                refresh_token,
                PUBLIC_KEY,
                algorithms=[ALGORITHM],
                options={"require": ["exp", "sub", "jti", "iat"]}
            )
            claims = RefreshTokenPayload(**payload)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Refresh token expired")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        user_id = claims.sub

        # 3. Final check: is this exact token still in user's active set?
        is_member = await r.sismember(f"user_refresh:{user_id}", refresh_token)
        if not is_member:
            # Token was revoked or never existed
            raise HTTPException(status_code=401, detail="Token no longer valid")

        return user_id
# routers/auth.py

@router.post("/refresh")
async def refresh_token(
    request: Request,
    db: AsyncSession = Depends(get_session)
):
    old_refresh_token = request.cookies.get("refresh_token")
    if not old_refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    # Validate old token → get user_id
    user_id = await validate_refresh_token(old_refresh_token)

    # Generate NEW tokens
    new_access_token = create_access_token(user_id)
    new_refresh_token = await create_refresh_token(user_id)  # auto-stored in Redis
    new_csrf_token = secrets.token_urlsafe(32)

    # Revoke old refresh token
    await revoke_refresh_token(old_refresh_token)

    response = JSONResponse({
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "csrf_token": new_csrf_token,
        "token_type": "bearer"
    })

    # Update cookies
    response.set_cookie("access_token", new_access_token, httponly=True, secure=True, samesite="lax", max_age=20*60)
    response.set_cookie("refresh_token", new_refresh_token, httponly=True, secure=True, samesite="lax", max_age=30*24*60*60)
    response.set_cookie("csrf_token", new_csrf_token, httponly=False, secure=True, samesite="lax", max_age=30*24*60*60)

    return response



from pydantic import BaseModel, EmailStr, Field

class LoginStep1(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)

class LoginStep2(BaseModel):
    email: EmailStr
    otp: str = Field(..., pattern=r"^\d{6}$")
    login_token: str = Field(..., min_length=32)   # temporary anti-replay token
# routers/auth.py
from fastapi import APIRouter, Depends, BackgroundTasks, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from ..crud.auth import initiate_login, complete_login, logout_user
from ..core.deps import get_current_user_optional, require_csrf_protection, get_session

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.post("/login")
async def login_step1(
    data: LoginStep1,
    background_tasks: BackgroundTasks,
    db = Depends(get_session),
    current_user = Depends(get_current_user_optional)
):
    if current_user:
        raise HTTPException(status_code=403, detail="Already logged in")

    result = await initiate_login(
        email=data.email,
        password=data.password,
        db=db,
        background_tasks=background_tasks
    )
    return result


@router.post("/login/verify")
async def login_step2(
    data: LoginStep2,
    db = Depends(get_session)
):
    tokens = await complete_login(
        email=data.email,
        otp=data.otp,
        login_token=data.login_token,
        db=db
    )

    response = JSONResponse({
        "message": "Login successful",
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "csrf_token": tokens["csrf_token"]
    })

    response.set_cookie("access_token", tokens["access_token"], httponly=True, secure=True, samesite="lax", max_age=20*60)
    response.set_cookie("refresh_token", tokens["refresh_token"], httponly=True, secure=True, samesite="lax", max_age=30*24*60*60)
    response.set_cookie("csrf_token", tokens["csrf_token"], httponly=False, secure=True, samesite="lax", max_age=30*24*60*60)

    return response


@router.post("/logout")
async def logout(
    request: Request,
    _: None = Depends(require_csrf_protection),
    current_user = Depends(get_current_user)
):
    refresh_token = request.cookies.get("refresh_token")
    await logout_user(refresh_token)

    response = JSONResponse({"message": "Logged out"})
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("csrf_token")
    return response
# crud/auth.py
from fastapi import HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession
from ..core.security import (
    verify_hash_password,
    create_access_token,
    create_refresh_token,
    revoke_refresh_token,
    generate_and_send_otp
)
from ..models import User
import secrets

async def initiate_login(
    email: str,
    password: str,
    db: AsyncSession,
    background_tasks
):
    user = await db.exec(select(User).where(User.email == email)).first()
    if not user or user.disabled:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_hash_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate login token (anti-replay)
    login_token = secrets.token_urlsafe(32)
    async with get_redis() as r:
        await r.setex(f"login_attempt:{login_token}", 600, str(user.id))

    # Send OTP
    await generate_and_send_otp(
        user=user,
        subject="Your Login OTP",
        background_tasks=background_tasks,
        otp_type="login"
    )

    return {
        "message": "OTP sent",
        "login_token": login_token
    }


async def complete_login(
    email: str,
    otp: str,
    login_token: str,
    db: AsyncSession
):
    # Verify login_token
    async with get_redis() as r:
        user_id_str = await r.get(f"login_attempt:{login_token}")
        if not user_id_str:
            raise HTTPException(status_code=400, detail="Invalid login session")
        await r.delete(f"login_attempt:{login_token}")

    user_id = int(user_id_str)
    user = await db.get(User, user_id)
    if not user or user.email != email:
        raise HTTPException(status_code=401, detail="Invalid user")

    # Verify OTP
    async with get_redis() as r:
        key = f"otp:{otp}:{user.id}"
        if not await r.get(key):
            raise HTTPException(status_code=401, detail="Invalid or expired OTP")
        await r.delete(key)
        await r.srem(f"user_otps:{user.id}", otp)

    # Generate tokens
    access_token = create_access_token(user.id)
    refresh_token = await create_refresh_token(user.id)
    csrf_token = secrets.token_urlsafe(32)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "csrf_token": csrf_token,
        "user": user
    }


async def logout_user(refresh_token: str | None):
    if refresh_token:
        await revoke_refresh_token(refresh_token)
