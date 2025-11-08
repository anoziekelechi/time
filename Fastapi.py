
from datetime import datetime,timedelta,timezone
from sqlalchemy.ext.asyncio import AsyncSession
from api.users.schemas import UserCreate,LoginUser,ReadUser
from api.users.models import User
from sqlmodel import select
from fastapi import HTTPException,status, BackgroundTasks
import logging
from fastapi import FastAPI
from fastapi_mail import MessageSchema,MessageType
from api.core.mail import mail, fm
#from api.users.auth import verify_hash_password,ACCESS_TOKEN_EXPIRE_MINUTES
from typing import Optional
from api.users.auth import create_access_token
import jwt
from jwt.exceptions import InvalidTokenError
#from api.users.auth import SECRET_KEY, ALGORITHM, PUBLIC_KEY
from api.users.schemas import TokenData
from api.core.redis import Redis_connection
import redis.asyncio as redis
import json
from api.core.redis import get_redis
from api.users.tasks import send_otp_email_task
import secrets
from tenacity import retry,stop_after_attempt,wait_fixed
from api.users.auth import get_user,hash_user_password,verify_csrf_token,verify_hash_password,generate_csrf_token,ALGORITHM, \
PUBLIC_KEY
from api.users.schemas import VerifyPassword, UpdatePassword, UpdateUser,ForgotPassword,ResetPassword,Users,VerifyOtp

OTP_EXPIRES_MINUTES = 20

##
logging.basicConfig(level=logging.INFO)
logger= logging.getLogger(__name__)

# generate send otp via celery
    
async def generate_and_send_otp(
    redis_client: redis.Redis, 
    user:User,
    subject:str,
    background_tasks:BackgroundTasks,
    otp_type:str,
    ) -> str:
    otp= ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    expiry_delta = timedelta(minutes=OTP_EXPIRES_MINUTES)
    expires_at=int((datetime.now(timezone.utc) + expiry_delta).timestamp())
    
    otp_data={
        "user_id":user.id,
        "expires_at":expires_at,
        "otp_type":otp_type
    }
    # Store otp in redis
    await redis_client.set(
            f"otp:{otp}:{user.id}",
            json.dumps(otp_data),
            ex=expiry_delta
        )
        # track all otp for this user
        
    await redis_client.sadd(f"user_otps:{user.id}", otp)
       
       #Que email via celery
    background_tasks.add_task(
        send_otp_email_task.delay,
        recipient=user.email,
        otp=otp,
        subject=subject,
    )
    
   
    logger.info(f"OTP {otp} generated and queued for {user.email} (type: {otp_type})")
    return otp
        
async def login_user(
    db:AsyncSession, 
    email:str, 
    password:str, 
    redis_client: Redis_connection,
    csrf_token:str,
    background_tasks:BackgroundTasks,
    current_user: Optional[ReadUser] = None
    ) -> dict:
    
    if current_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Action not allowed for already logged in user",
            headers={"Location":"/protected"},
        )
    
    statement = select(User).where(User.email == email)
    result= await db.execute(statement)
    db_user=result.scalars().first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            headers={"WWW-Authenticate":"Bearer"}
            )
    if db_user.disable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="Your account is disable")
    if not verify_hash_password(password,db_user.hashed_password):
        raise HTTPException(
              status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            headers={"WWW-Authenticate":"Bearer"}       
        )
    # if not await verify_csrf_token(redis_client,db_user.id,csrf_token):
    #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="invalid csrf token")
    
    user=Users.model_validate(db_user)
    #otp=await generate_and_send_otp may use db_user instead of user
    # generate and send otp in background
    subject="Your Login OTP Code"
    background_tasks.add_task(
        generate_and_send_otp,user,redis_client
    )
    csrf_token=await generate_csrf_token(redis_client,user.id)
    return {"message":"OTP sent to email","email":email,"csrf_token":csrf_token}


async def verify_login_otp(redis_client:redis.Redis, db:AsyncSession, email:str,otp:str,csrf_token:str) ->Users:
    user=await get_user(db,email)
    if not user:
          raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            )
    if user.disable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="Your account is disable")
    
    if not await verify_csrf_token(redis_client,user.id,csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="invalid csrf token")
    
    key= f"otp:{otp}:{user.id}"
    otp_data=await redis_client.get(key)
    if not otp_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")
    otp_info=json.loads(otp_data)
    expires_at=otp_info.get("expires_at")
    if expires_at < int(datetime.now(timezone.utc).timestamp()):
        await redis_client.delete(key)
        await redis_client.srem(f"user_otps:{user.id}",otp)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="OTP expired")
    await redis_client.delete(key)
    await redis_client.srem(f"user_otps{user.id}", otp)
    return user
    

# registration
# async def send_otp(email:str,messages:str):
#     message=MessageSchema(
#         subject="Verify Your Email",
#         recipients=[email],
#         body=messages,
#         subtype=MessageType.plain,
#     )
#     try:
#         await mail.send_message(message)
#         logger.info(f"OTP sent successfully to {email}")
#     except Exception as e:
#         logger.error(f"OTP not sent to {email}")


async def add_user(
    user: UserCreate, 
    db:AsyncSession,
    background_tasks:BackgroundTasks,
    #redis_client: redis.Redis,
    current_user: Optional[User] = None, 
   
    ) -> dict: #return dict since we are returning "message:"
    
    # check if user is logged in
    if current_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, #use 307
            detail="Authenticated User Cannot create New Account",
            headers={"location":"/protected"} #"X-Redirect":"/"
        )
    # check for unique email
    db_users=await get_user(db, user.email)
    if db_users:
        raise HTTPException(status_code=400, detail="email already exist")
   
    
    # create new user now
    #since pyndatic has validate data no need to use model_validate again
    hashed_password = hash_user_password(user.password)
    new_user=User(
        surname = user.surname,
        othernames = user.othernames,
        email = user.email,
        hashed_password = hashed_password,
        disable = False,
        payment_id = None,
        one_click = False,
        verified = False,
        date_added = datetime.now(timezone.utc),
        date_modify = datetime.now(timezone.utc)
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # USE SINGLE REDIS POOL
    async with get_redis() as redis_client:
         # send otp
        await generate_and_send_otp(
            redis_client=redis_client,
            user=new_user,
            background_tasks=background_tasks,
            otp_yype="registration",
            subject="verify your Account"
        )
        # generate csrf token
        csrf_token=await generate_csrf_token(redis_client,user.id)
    return {"message": "OTP sent to email","csrf_token":csrf_token, "email": new_user.email}



async def verify_registration_otp(
    #redis_client:redis.Redis, 
    data:VerifyOtp,
    otp:str, 
    db: AsyncSession,
    user:User ,
    )-> Users: #Readuser
    
    # re fetch user from sesion
    #result = await db.execute(select(User).where(User.id == user_id))
    #user = result.scalars().first()
    #user= await get_user(db, email)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="Account has been verified")
    
    # verify user from redis
    async with get_redis() as redis_client:
       
        key= f"otp:{data.otp_code}:{user.id}"
        otp_data= await redis_client.get(key)
        if not otp_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid or expired OTP")
        try:
            otp_info=json.loads(otp_data)
        except json.JSONDecodeError:
            await redis_client.delete(key)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Corrupted otp")
        # check otp valid time
        expires_at= otp_info.get("expires_at")
        if expires_at < int(datetime.now(timezone.utc).timestamp()):
            await redis_client.delete(key)
            await redis_client.srem(f"user_otp:{user.id}", otp)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="OTP expired")
        # check type
        otp_type=otp_info.get("otp_type")
        if otp_type != "registration":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="OTP expired")
        
        #  Update user
        user.verified = True
        user.date_verified = datetime.now(timezone.utc)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        # clean redis
        await redis_client.delete(key)
        await redis_client.srem(f"user_otp:{user.id}", otp)
    return Users.model_validate(user)
    
      
    
async def delete_user(
    db: AsyncSession, 
    redis_client: redis.redis,
    #id:int,
    email:str,
    user_password:VerifyPassword,
    current_user: Optional[Users]=None
    )-> None:
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You must logged in to peform this operation",
            headers={"location":"/token"} #recheck
        )
    if current_user.email != email:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="Access denied")
    statement=select(User).where(User.email == email)
    result=await db.execute(statement)
    db_user=result.scalars().first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="User not found")
    if not verify_hash_password(user_password.password, db_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")
    #clean Redis
    tokens=await redis_client.smembers(f"user_tokens:{db_user.id}")
    for token in tokens:
        await redis_client.delete(f"refresh_token:{token}:{db_user.id}")
    await redis_client.delete(f"user_tokens:{db_user.id}")
    otps=await redis_client.smembers(f"user_otps:{db_user.id}")
    for otp in otps:
        await redis_client.delete(f"otp:{otp}:{db_user.id}")
    await redis_client.delete(f"user_otps:{db_user.id}")
    csrf_tokens=await redis_client.smember(f"user_csrf:{db_user.id}")
    for csrf_token in csrf_tokens:
        await redis_client.delete(f"csrf:{csrf_token}:{db_user.id}")
    await redis_client.delete(f"user_csrf:{db_user.id}")
    await db.delete(db_user)
    await db.commit()
    

async def changed_password(db:AsyncSession, user: UpdatePassword,current_user: User= None) -> None:
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Logging Required",
            headers={"Location": "/token"} #loggin route
        )
    statement = select(User).where(User.email == current_user.email)
    result = await db.execute(statement)
    db_user=result.scalars().first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="User not found")
    
    if db_user.disable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="Access denied")
    if not verify_hash_password(user.current_password,db_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid current password")
    
    db_user.hashed_password=hash_user_password(user.new_password)
    db.add(db_user)
    await db.commit()
    
    
async def logout_user(db: AsyncSession,redis_client:redis.Redis,current_user:ReadUser) -> None:
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Logging Required",
            headers={"Location": "/token"}
        )
        
    tokens=await redis_client.smembers(f"user_tokens:{current_user.id}")
    for token in tokens:
        await redis_client.delete(f"refresh_token:{token}:{current_user.id}")
    await redis_client.delete(f"user_tokens:{current_user.id}")
    otps=await redis_client.smembers(f"user_otps:{current_user.id}")
    for otp in otps:
        await redis_client.delete(f"otp:{otp}:{current_user.id}")
    await redis_client.delete(f"user_otps:{current_user.id}")
    csrf_tokens = await redis_client.smembers(f"user_csrf:{current_user.id}")
    for csrf_token in csrf_tokens:
        await redis_client.delete(f"csrf:{csrf_token}:{current_user.id}")
    await redis_client.delete(f"user_csrf:{current_user.id}")
    
    
async def get_current_user(
    db: AsyncSession, 
    token: Optional[str] = None
    ) -> Optional[ReadUser]:
    
    credentials_exception=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unable to verify your credentials",
        headers={"WWW-Authenticate":"Bearer"} 
    )
    
    if token is None:
        return None
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms= [ALGORITHM])
        token_data = TokenData(**payload)
        user= await get_user(db, email = token_data.email)
        if user is None or user.verified is False or user.disable:
            raise credentials_exception
        return user
    except (InvalidTokenError, ValueError):
        raise credentials_exception 
    
    
# async def forgotpassword(
#     db:AsyncSession,
#     redis_client:redis.Redis,
#     user:ForgotPassword,
#     background_tasks:BackgroundTasks,
#     current_user:Optional[ReadUser] = None
# ) -> dict:  
    
#     if current_user:
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Action not allowed",
#             headers={"Location":"/protected"}
#         )
        
#     app_user = await get_user(db, user.email)
#     if not app_user:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="User not found")
#     if app_user.disable:
#         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="Your Account is disable")
#     #send otp
#     subject="Password Reset OTP"
#     background_tasks.add_task(generate_and_send_otp,redis_client,user,subject)
#     return {"message":"An OTP to reset your password has been sent to your inbox","email":user.email}
    
