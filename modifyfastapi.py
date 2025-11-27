

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



        # logics
        OTP_EXPIRES_MINUTES = 20

##
logging.basicConfig(level=logging.INFO)
logger= logging.getLogger(__name__)

# generate send otp via celery
    
async def generate_and_send_otp(
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
    async with get_redis() as r:
        #otp key
        await r.set(
            f"otp:{otp}:{user.id}",
            json.dumps(otp_data),
            ex=expiry_delta
        )
        # track all otp for this user
        
        await r.sadd(f"user_otps:{user.id}", otp)
       
       #Que email via celery
    background_tasks.add_task(
        send_otp_email_task.delay,
        recipient=user.email,
        otp=otp,
        subject=subject,
    )
    
   
    logger.info(f"OTP {otp} generated and queued for {user.email} (type: {otp_type})")
    return otp

    
 

async def add_user(
    user: UserCreate, 
    db:AsyncSession,
    background_tasks:BackgroundTasks,
    current_user: Optional[User] = None, 
   
    ) -> dict: #return dict since we are returning "message:"
    
    # check if user is logged in
    if current_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Authenticated User Cannot create New Account",
            #headers={"location":"/protected"} #show error msg in frontend and redirect
        )
    # check for unique email
    db_users=await get_user(db, user.email)
    if db_users:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="email already exist")
   
    
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

    
    await generate_and_send_otp(
        user=new_user,
        background_tasks=background_tasks,
        otp_yype="registration",
        subject="verify your Account"
        )
    return {"message": "OTP sent to email", "email": new_user.email}



async def verify_registration_otp( 
    data:VerifyOtpRequest,
    otp:str, 
    db: AsyncSession,
    #user:User ,
    )-> ReadUser: #Readuser
    
    user = await get_user_by_email
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="Account has been verified")#raise error and navigate in frontend
    
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
    return ReadUser.model_validate(user)
    
      
    
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
            #headers={"location":"/token"} #raise error use navigate
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
    
 #____ get current logged in user _______
    
async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    #token: str = Depends(get_token_from_cookie),
    ) -> ReadUser:
    
    token=request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="access token missing",
            headers={"WWW-Authenticate": "Bearer"},)
    
    # credentials_exception=HTTPException(
    #     status_code=status.HTTP_401_UNAUTHORIZED,
    #     detail="Unable to verify your credentials",
    #     headers={"WWW-Authenticate":"Bearer"} 
    # )
   # Decode jwt
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms= [ALGORITHM],options={"require":["exp","sub"]})#get_settings().PUBLIC_KEY
        claims = TokenPayload(**payload)
        user_id= claims.sub
    except PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user= await get_user_by_id(db, user_id)
    if user is None or user.verified is False or user.disable:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return ReadUser.model_validate(user)

# _____ Login  Function ______
async def login_user(
    data: LoginRequest,
    db:AsyncSession = Depends(get_db),  
    background_tasks:BackgroundTasks = Depends(BackgroundTasks),
    current_user: ReadUser | None = Depends(get_current_user),
    ) -> dict:
     
    if current_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Action not allowed for already logged in user",
            headers={"Location":"/profile"},
        )
    
    user = await get_user_by_email(db,data.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            #headers={"WWW-Authenticate":"Bearer"}
            )
    if user.disable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="Your account is disable")
    if not verify_hash_password(data.password, user.hashed_password):
        raise HTTPException(
              status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            #headers={"WWW-Authenticate":"Bearer"}       
        )
    await generate_and_send_otp(
        user = user,
        subject = "Your Login OTP",
        background_tasks=background_tasks,
        otp_type="Login"
    )
    async with get_redis() as r:
        csrf_token = await generate_csrf_token(r,user.id)
    return {"message":"OTP sent","email":user.email,"csrf_token":csrf_token}


#____ Verify Login OTP ______
    
async def verify_login_otp(data: VerifyOtpRequest, db:AsyncSession = Depends(get_db)) ->TokenData:
    user=await get_user_by_email(db,data.email)
    if not user:
          raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            )
    # if user.disable:
    #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="Your account is disable")
    
    # verify csrf 
    async with get_redis() as r:
        if not await verify_csrf_token(r,user.id,data.csrf_token):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="invalid csrf token")
    
        key= f"otp:{data.otp}:{user.id}"
        otp_data = await r.get(key)
        if not otp_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")
        otp_info=json.loads(otp_data)
        if otp_info.get("expires_at",0) < int(datetime.now(timezone.utc).timestamp()):
            await r.delete(key)
            await r.srem(f"user_otps:{user.id}", data.otp)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")
        # valid delete
        await r.delete(key)
        await r.srem(f"user_otps:{user.id}", data.otp)
        
        # issue tokens
        access= create_access_token(user.id)
        refresh= create_refresh_token()
        await store_refresh_token(r,user.id,refresh)
        return TokenData(access_token=access,refresh_token=refresh)
        
#_____LOG OUT USER _____
async def logout_user(
    current_user: ReadUser,
)-> None:
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Only logged in users allowed to perform this",
            headers={"WWW-Authenticate":"Bearer"},
            )


    
    
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
    
    return token
