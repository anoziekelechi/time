@router.post("/register")
async def register(
    user_data: UserCreate,
    background_tasks: BackgroundTasks = Depends(),
    db: DB,
    redis: RedisDep,
    mailer: MailerDep,
):
    result = await add_user(
        user_data=user_data,
        db=db,
        background_tasks=background_tasks,
        redis=redis,
        mailer=mailer,
    )
    return result  # contains message + reg_token + email


# ── VERIFY REGISTRATION OTP
@router.post("/register/verify")
async def verify_reg_otp(
    data: VerifyRegistrationOtp,
    db: DB,
    redis: RedisDep,
):
    user = await verify_registration_otp(data, db, redis)
    return {"message": "Account verified successfully", "user": user}

# routes/auth.py — FINAL, THIN, SACRED, ETERNAL
from fastapi import APIRouter, Depends, Request, HTTPException, status
from deps import DB, RedisDep
from schemas.auth import LoginStep1, LoginStep2
from crud.auth import initiate_password_login, complete_password_login, logout
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/auth", tags=["auth"])

# ── STEP 1: Password → Send OTP
@router.post("/login")
async def login_step1(
    data: LoginStep1,
    background_tasks: BackgroundTasks = Depends(),
    db: DB,
    redis: RedisDep,
    mailer: MailerDep,
):
    return await initiate_password_login(
        email=data.email,
        password=data.password,
        background_tasks=background_tasks,
        db=db,
        redis=redis,
        mailer=mailer,
    )

# ── STEP 2: OTP → Issue tokens + set cookies
@router.post("/login/verify")
async def login_step2(
    data: LoginStep2,
    db: DB,
    redis: RedisDep,
):
    tokens = await complete_password_login(data, db, redis)

    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie("access_token",  tokens.access_token,  httponly=True, secure=True, samesite="lax", max_age=900, path="/")
    response.set_cookie("refresh_token", tokens.refresh_token, httponly=True, secure=True, samesite="lax", max_age=30*24*60*60, path="/auth/refresh")
    response.set_cookie("csrf_token",    tokens.csrf_token,    httponly=False, secure=True, samesite="lax", max_age=30*24*60*60)
    
    return response

# ── REFRESH TOKEN
@router.post("/refresh")
async def refresh_token(
    request: Request,
    redis: RedisDep,
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    # validate_refresh_token returns user_id + jti
    user_id, jti = await validate_refresh_token(refresh_token, redis)

    # Revoke old one
    await logout(user_id=user_id, jti=jti, refresh_token=refresh_token, redis=redis)

    # Issue new ones
    tokens = await create_token_response(user_id, redis)

    response = JSONResponse(content={"message": "Refreshed"})
    response.set_cookie("access_token",  tokens.access_token,  httponly=True, secure=True, samesite="lax", max_age=900, path="/")
    response.set_cookie("refresh_token", tokens.refresh_token, httponly=True, secure=True, samesite="lax", max_age=30*24*60*60, path="/auth/refresh")
    response.set_cookie("csrf_token",    tokens.csrf_token,    httponly=False, secure=True, samesite="lax", max_age=30*24*60*60)

    return response

# ── LOGOUT
@router.post("/logout")
async def logout_endpoint(
    request: Request,
    redis: RedisDep,
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="No active session")

    try:
        payload = jwt.decode(refresh_token, PUBLIC_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
        jti = payload["jti"]
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

    await logout(user_id=user_id, jti=jti, refresh_token=refresh_token, redis=redis)

    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/auth/refresh")
    response.delete_cookie("csrf_token")

    return response
