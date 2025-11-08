
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

from pydantic import BaseModel,field_validator,EmailStr,Field, ConfigDict
from typing import Optional
from datetime import datetime,timezone
import re


class Tokenn(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    
class UserBase(BaseModel):
    email: EmailStr
    
    # @field_validator("email",mode='before')
    # @classmethod
    # def validate_email(cls, value:str) -> str:
    #     return value.lower()
    
class Refresh(UserBase):
    id: int
    
    

class UserCreate(UserBase):
    surname:str = Field(
        max_length=20,
        validation_error_messages={
            'string_too_long':'Surname cannot be more than 20',
        }
        )
    othernames:str
    password:str
    
    @field_validator("email",mode='before')
    @classmethod
    def validate_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.lower()
    
    @field_validator("password")
    @classmethod
    def validate(cls, value:str) -> str:
        if not re.match(r"^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])[a-zA-Z0-9#@$]{8-12}",value):
            raise ValueError("password must be at least 8 or 20 characters long,atleast upper case letters,lower case letters,0-9 digits,special characters #@$,no space ")
        return value
    
    @field_validator("surname")
    @classmethod
    def validate_surname(cls,value:str) -> str:
        
        
        if not re.match(r'^[a-zA-Z]+$',value):
            raise ValueError('Surname must contain only alphabetics characters and no space')
        return value.upper()
    
    @field_validator(othernames)
    @classmethod
    def validate_othernames(cls,value:str) -> str:
        if not re.match(r'^[a-zA-Z\s]+$',value):
            raise ValueError('Names must contain only alphabetics characters')
        names = " ".join(value.split())
        return names.upper()
    
    #model_config=ConfigDict(from_attributes=True)   
    
class ReadUser(UserBase): #or use basemodel
    id: int
    surname:str
    othernames:str
    verified: bool
    date_verified: Optional[datetime] = None
    date_added: datetime #datetime.now(timezone.utc)
    date_modify:datetime
        
        # only needed in read
    class Config:
        from_attributes=True
        

class Users(ReadUser): #UsersInDb
    #model_config=ConfigDict(from_attributes=True) # this will mapped these fields to corresponding fields in User table
    hashed_password: str
    disable: bool 
    payment_id: Optional[str] = None
    one_click:bool
        
class VerifyOtp(UserBase): # for reg
    otp_code:str = Field(...,min_length=6,max_length=6,pattern=r"^\d{6}$",description="6 digits otp")
    csrf_token:str
    
    
class LoginUser(UserBase):
    password: str
    
    
class TokenData(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    

class VerifyPassword(BaseModel):
    password:str
    
class UpdateUser(BaseModel): #BaseModel
    email:EmailStr | None = None
    surname:str | None = None
    othernames: str | None = None
    
     
    @field_validator("email",mode='before')
    @classmethod
    def validate_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.lower()
    
    @field_validator("surname")
    @classmethod
    def validate_surname(cls,value:str) -> str:
        
        
        if not re.match(r'^[a-zA-Z]+$',value):
            raise ValueError('Surname must contain only alphabetics characters and no space')
        return value.upper()
    
    @field_validator(othernames)
    @classmethod
    def validate_othernames(cls,value:str) -> str:
        if not re.match(r'^[a-zA-Z\s]+$',value):
            raise ValueError('Names must contain only alphabetics characters')
        names = " ".join(value.split())
        return names.upper()
    
    
class UpdatePassword(BaseModel):
    current_password:str
    new_password:str
    
    
class ForgotPassword(BaseModel):
    email:EmailStr
    
class ResetPassword(BaseModel):
    email:EmailStr
    otp:str
    new_password:str
            
            
    
        

# auth

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
