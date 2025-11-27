

pwd_context=CryptContext(schemes=["bycrypt"], deprecated="auto")  
#oauth2_scheme = OAuth2PasswordBearer(tokenurl = "token") 

SECRET_KEY = "mysecret"
ALGORITHM ="HS256"
PRIVATE_KEY="mykey"
PUBLIC_KEY="mykey"
ACCESS_TOKEN_EXPIRE_MINUTES = 20
REFRESH_TOKEN_EXPIRES_DAYS =7
CSRF_TOKEN_EXPIRE_MINUTES =30

def hash_user_password(password:str)-> str:
        return pwd_context.hash(password)  
  # login route  
oauth2_scheme=OAuth2PasswordBearer(tokenUrl="/login",scheme_name="JWT")  
   
def verify_hash_password(plain_password:str,hashed_password:str) -> bool:
        return pwd_context.verify(plain_password,hashed_password)
  # get user by id  
async def get_user_by_id(db: AsyncSession, user_id: int) -> Optional[User]:
    result= await db.execute(select(User).where(User.id==user_id))
    return result.scalars().first()
# get token fromcookies
async def get_token_from_cookie(request: Request) -> str:
    token=request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="access token missing",
            headers={"WWW-Authenticate": "Bearer"},)
    return token

async def get_user_by_email(db: AsyncSession, email:str) -> Optional[Users]:
    statement=select(User).where(User.email == email)
    result=await db.execute(statement)
    user = result.scalars().first()
    return user
    
    
async def get_user(db: AsyncSession, email:str) -> Optional[Users]:
    statement=select(User).where(User.email == email)
    result=await db.execute(statement)
    user = result.scalars().first()
    if user:
        return Users.model_validate(user)
    return None
  
  #____ REVOKE TOKEN ___________
  
async def revoke_refresh_token(user_id:int,refresh_token: str):
      async with get_redis() as r:
          # Remove from set
          await r.srem(f"user_refresh:{user_id}",refresh_token)
          #Blacklist
          await r.set(f"blacklist:refresh:{refresh_token}", "1",ex=60*60)
  #_________ ACCESS TOKEN___________  
def create_access_token(user_id: int,expires_delta: Optional[timedelta] = None)-> str:
    if expires_delta is not None:
        expire=datetime.now(timezone.utc)+ expires_delta
    else:
        expire=datetime.now(timezone.utc) + timedelta(minutes=15)
    payload={
        "sub":str(user_id),
        "exp":int(expire.timestamp()),
        "token_type":"access"
    }
    
    encodeed_jwt=jwt.encode(payload,PRIVATE_KEY,algorith=ALGORITHM)#sethings().PRIVATE_KEY
    return encodeed_jwt


#__________ REFRESH TOKEN ____________
async def create_refresh_token(user_id: int) ->str:#redis_client: Redis_connection,user_id: int) -> str:
    payload = {
        "sub":user_id,
        "jti":str(uuid.uuid4()),
        "exp":int((datetime.now(timezone.utc)+ timedelta(days=30)).timestamp()),
        "token_type": "refresh" 
    }
    return jwt.encode(payload,PRIVATE_KEY,algorithm=ALGORITHM)
 
 #__________ SAVE REFRESH TOKEN ______________   
async def store_refresh_token(user_id:int,refresh_token:str):
    async with get_redis()as r:
        await r.sadd(f"user_refresh:{user_id}" ,refresh_token)
        await r.expire(f"user_refresh:{user_id}", 30*24*60*60) #30 days
    
#___________ VALIDATE REFERSH TOKEN ______________
async def validate_refresh_token(refresh_token: str) -> int: #Refresh
    async with get_redis() as r:
    # Blacklist check
        if await r.get(f"blacklist:refresh:{refresh_token}"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Token revoked")
    # Decode jwt
        try:
            payload = jwt.decode(refresh_token,PUBLIC_KEY,algorithms=ALGORITHM)
            # Check for Expired
            claims = RefreshPayload(**payload)
            user_id = claims.sub
        except jwt.PyJWTError as e:
             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Token revoked")
         # Check token is still active
        is_active = await r.sismember(f"user_refresh:{user_id}", refresh_token)
        if not is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Token revoked")
        return user_id
            


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
