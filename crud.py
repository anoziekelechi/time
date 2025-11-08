
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from api.users.models import User
from api.users.schemas import Refresh, ReadUser, Users
from typing import Optional
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import HTTPException,status,Request,Depends
from jwt.exceptions import InvalidTokenError
from api.core.redis import Redis_connection,get_redis
import uuid
import json
import secrets
import redis.asyncio as redis
from api.users.logics import get_current_user


pwd_context=CryptContext(schemes=["bycrypt"], deprecated="auto")  
oauth2_scheme = OAuth2PasswordBearer(tokenurl = "token") 

SECRET_KEY = "mysecret"
ALGORITHM ="HS256"
PRIVATE_KEY="mykey"
PUBLIC_KEY="mykey"
ACCESS_TOKEN_EXPIRE_MINUTES = 20
REFRESH_TOKEN_EXPIRES_DAYS =7
CSRF_TOKEN_EXPIRE_MINUTES =30




#models

def hash_user_password(password:str)-> str:
        return pwd_context.hash(password)    
   
def verify_hash_password(plain_password:str,hashed_password:str) -> bool:
        return pwd_context.verify(plain_password,hashed_password)
    
async def get_user(db: AsyncSession, email:str) -> Optional[Users]:
    statement=select(User).where(User.email == email)
    result=await db.execute(statement)
    user = result.scalars().first()
    if user:
        return Users.model_validate(user)
    return None
    
def create_access_token(data: dict,expire_delta: Optional[timedelta] = None)-> str:
    to_encode = data.copy()
    if expire_delta:
        expire=datetime.now(timezone.utc)+ expire_delta
    else:
        expire=datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp":expire, "token_type": "access"})
    encodeed_jwt=jwt.encode(to_encode,PRIVATE_KEY,algorith=ALGORITHM)
    return encodeed_jwt



async def create_refresh_token(redis_client: Redis_connection,user_id: int) -> str:
    token = str(uuid.uuid4())
    expiry_delta=timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS)
    expires_at = int((datetime.now(timezone.utc) +  expiry_delta).timestamp())
    token_data ={
        "user_id":user_id,
        "expires_at":expires_at,
    }
    # store in redis
    await redis_client.set(
        f"refresh_token:{token}:{user_id}",
        json.dumps(token_data),
        ex=expiry_delta
    )
    #add to users token set
    await redis_client.sadd(f"user_token:{user_id}", token)
    return token

async def validate_refresh_token(db: AsyncSession, redis_client: redis.Redis, token: str) -> Refresh:
    async for key in redis_client.scan_iter(f"refresh_token:{token}:*"):
        token_data=await redis_client.get(key)
        if token_data:
            token_info=json.loads(token_data)
            expires_at=token_info.get("expires_at")
            user_id=token_info.get("user_id")
            if expires_at < int(datetime.now(timezone.utc).timestamp()):
                await redis_client.delete(key)
                await redis_client.srem(f"user_token:{user_id}", token)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, 
                    details="Refresh token expired"
                )
            statement=select(User).where(User.id == user_id)
            result=await db.execute(statement)
            user=result.scalars().first()
            if not user or user.verify is False:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="user not found")
            return Refresh(
                id=user.id,
                email=user.email, 
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="invalid refresh token")


async def generate_csrf_token(user_id:int) -> str:
    csrf_token=secrets.token_urlsafe(32)
    expiry_delta= int(timedelta(minutes=CSRF_TOKEN_EXPIRE_MINUTES).total_seconds())
    expires_at=int((datetime.now(timezone.utc)+ expiry_delta).timestamp)
    csrf_data={
        "user_id":user_id,
        "expires_at":expires_at
    }
    async with get_redis() as redis_client:
        key=f"csrf:{csrf_token}:{user_id}"
        await redis_client.set(
            key, json.dumps(csrf_data),ex=expiry_delta
        )
      
        await redis_client.sadd(f"user_csrf:{user_id}", csrf_token)
    return csrf_token

async def verify_csrf_token(user_id:int,csrf_token:str) -> bool:
    async with get_redis() as redis_client:
        key=f"csrf:{csrf_token}:{user_id}"
        csrf_data= await redis_client.get(key)
        if not csrf_data:
            return False
        try:
            csrf_info=json.loads(csrf_data)
        except json.JSONDecodeError:
            await redis_client.delete(key)
            return False
        if csrf_info.get("user_id") != user_id:
            return False
    expires_at= csrf_info.get("expires_at")
    if not expires_at or expires_at < int(datetime.now(timezone.utc).timestamp()):
        await redis_client.delete(key)
        await redis_client.srem(f"user_csrf:{user_id}", csrf_token)
        return False
    return True



async def get_and_verift_csrf(request:Request,current_user:User=Depends(get_current_user),)->str:#for loggin users
    token=request.headers.get("X-CSRF-Token")
    if not token:
        try:
            body=await request.json()
            token=body.get("csrf_token")
        except:
            pass
    if not token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="csrf token missing")
    if not await verify_csrf_token(current_user.id,token):
         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="csrf token missing")
    return token
