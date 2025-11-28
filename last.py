
async def validate_refresh_token(refresh_token: str) -> int:
    async with get_redis() as r:
        # 1. Extract jti quickly (no signature check yet)
        try:
            unverified = jwt.decode(refresh_token, options={"verify_signature": False})
            jti = unverified.get("jti")
            if not jti or unverified.get("token_type") != "refresh":
                raise HTTPException(status_code=401, detail="Invalid refresh token")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Malformed token")

        # 2. Blacklist check
        if await r.get(f"blacklist:refresh:{jti}"):
            raise HTTPException(status_code=401, detail="Token revoked")

        # 3. Full cryptographic + expiry validation
        try:
            payload = jwt.decode(
                refresh_token,
                PUBLIC_KEY,
                algorithms=[ALGORITHM],
                options={"require": ["exp", "sub", "jti"]}
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

        user_id = payload["sub"]

        # 4. Final rotation check — exact token must still exist
        if not await r.sismember(f"user_refresh:{user_id}", refresh_token):
            raise HTTPException(status_code=401, detail="Token no longer valid")

        return user_id

async def create_refresh_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    jti = secrets.token_urlsafe(32)

    payload = {
        "sub": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)).timestamp()),
        "jti": jti,
        "token_type": "refresh"
    }

    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)

    # Store exact token in Redis set for revocation + rotation
    async with get_redis() as r:
        await r.sadd(f"user_refresh:{user_id}", token)
        await r.expire(f"user_refresh:{user_id}", REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60)

    return token

# routers/auth.py
from fastapi import APIRouter, Depends, BackgroundTasks, Request, HTTPException
from fastapi.responses import JSONResponse
from sqlmodel.ext.asyncio.session import AsyncSession
from ..crud.auth import initiate_login, complete_login, logout_user
from ..core.deps import get_current_user_optional, require_csrf_protection, get_session
from ..schemas.auth import LoginStep1, LoginStep2, TokenResponse

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.post("/login")
async def login(
    data: LoginStep1,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
    current_user = Depends(get_current_user_optional)
):
    if current_user:
        raise HTTPException(status_code=403, detail="Already logged in")
    
    return await initiate_login(data, db, background_tasks)


@router.post("/login/verify", response_model=TokenResponse)
async def login_verify(
    data: LoginStep2,
    db: AsyncSession = Depends(get_session)
):
    tokens = await complete_login(data, db)

    response = JSONResponse(content=tokens.model_dump())

    response.set_cookie("access_token",  tokens.access_token,  httponly=True,  secure=True, samesite="lax", max_age=1200, path="/")
    response.set_cookie("refresh_token", tokens.refresh_token, httponly=True,  secure=True, samesite="lax", max_age=2592000, path="/auth/refresh")
    response.set_cookie("csrf_token",    tokens.csrf_token,    httponly=False, secure=True, samesite="lax", max_age=2592000, path="/")

    return response


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request):
    old_refresh = request.cookies.get("refresh_token")
    if not old_refresh:
        raise HTTPException(status_code=401, detail="No refresh token")

    from ..core.security import validate_refresh_token, create_token_response
    user_id = await validate_refresh_token(old_refresh)
    await revoke_refresh_token(old_refresh)
    new_tokens = await create_token_response(user_id)

    response = JSONResponse(content=new_tokens.model_dump())

    response.set_cookie("access_token",  new_tokens.access_token,  httponly=True,  secure=True, samesite="lax", max_age=1200, path="/")
    response.set_cookie("refresh_token", new_tokens.refresh_token, httponly=True,  secure=True, samesite="lax", max_age=2592000, path="/auth/refresh")
    response.set_cookie("csrf_token",    new_tokens.csrf_token,    httponly=False, secure=True, samesite="lax", max_age=2592000, path="/")

    return response


@router.post("/logout")
async def logout(
    request: Request,
    _: None = Depends(require_csrf_protection),
    current_user = Depends(get_current_user)
):
    refresh_token = request.cookies.get("refresh_token")
    await logout_user(refresh_token)

    response = JSONResponse({"message": "Logged out successfully"})
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/auth/refresh")
    response.delete_cookie("csrf_token", path="/")
    return response

# crud/auth.py
from fastapi import HTTPException, BackgroundTasks
from sqlmodel.ext.asyncio.session import AsyncSession
from ..models import User
from ..core.security import (
    verify_hash_password,
    create_access_token,
    create_refresh_token,
    revoke_refresh_token,
    generate_and_send_otp
)
from ..schemas.auth import TokenResponse, LoginStep1, LoginStep2
import secrets

async def initiate_login(
    data: LoginStep1,
    db: AsyncSession,
    background_tasks: BackgroundTasks
):
    user = await db.exec(select(User).where(User.email == data.email)).first()
    if not user or user.disabled:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_hash_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    login_token = secrets.token_urlsafe(32)
    async with get_redis() as r:
        await r.setex(f"login_attempt:{login_token}", 600, str(user.id))

    await generate_and_send_otp(
        user=user,
        subject="Your Login OTP",
        background_tasks=background_tasks,
        otp_type="login"
    )

    return {"message": "OTP sent to your email", "login_token": login_token}


async def complete_login(data: LoginStep2, db: AsyncSession) -> TokenResponse:
    # Verify login_token
    async with get_redis() as r:
        user_id_str = await r.get(f"login_attempt:{data.login_token}")
        if not user_id_str:
            raise HTTPException(status_code=400, detail="Invalid or expired login session")
        await r.delete(f"login_attempt:{data.login_token}")

    user_id = int(user_id_str)
    user = await db.get(User, user_id)
    if not user or user.email != data.email or user.disabled:
        raise HTTPException(status_code=401, detail="Invalid user")

    # Verify OTP
    async with get_redis() as r:
        key = f"otp:{data.otp}:{user.id}"
        if not await r.get(key):
            raise HTTPException(status_code=401, detail="Invalid or expired OTP")
        await r.delete(key)
        await r.srem(f"user_otps:{user.id}", data.otp)

    # Generate tokens
    access_token = create_access_token(user.id)
    refresh_token = await create_refresh_token(user.id)
    csrf_token = secrets.token_urlsafe(32)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        csrf_token=csrf_token,
        token_type="bearer"
    )


async def logout_user(refresh_token: str | None):
    if refresh_token:
        await revoke_refresh_token(refresh_token)
