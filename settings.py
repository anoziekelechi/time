#validate_refresh_token 

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


#alembic.ini
[alembic]
script_location = alembic
#alembic env.py

from logging.config import fileConfig
from api.core.database import engine
from alembic import context
from sqlmodel import SQLModel
# import all your databases here
from api.users.models import User

# configure alembic
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
    
# use the async engine synchronously

connectable = engine.sync_engine

with connectable.connect() as connection:
    context.configure(
        connection = connection,
        target_metadata = SQLModel.metadata,
        compare_type = True,
        compare_server_default= True,
        
    )
    with context.begin_transaction():
        context.run_migrations()
##

from sqlalchemy.ext.asyncio import create_async_engine,AsyncSession,async_sessionmaker
from api.core.settings import get_settings
from sqlmodel import SQLModel
from contextlib import asynccontextmanager
from typing import AsyncGenerator

DATABASE_URL = get_settings().DATABASE_URL

engine=create_async_engine(DATABASE_URL,echo=True, future=True)

AsyncSessionLocal=async_sessionmaker(engine,class_=AsyncSession,expire_on_commit=False)

async def init_db():
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.run_sync(SQLModel.metadata.create_all)
    
    
@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession,None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
            
            
async def get_db() ->  AsyncGenerator[AsyncSession,None]:
    async with get_session() as session:
        yield session
#main.py
from fastapi import FastAPI,Request,Depends
from api.core.redis import get_redis_pool
from api.core.database import engine,init_db
from contextlib import asynccontextmanager
from api.products.views import router as products_router
from fastapi_limiter import FastAPILimiter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
from api.core.settings import get_settings, AppMode,Settings



# ___ LOGGIN CONGIG _____
logging.basicConfig(
    level=logging.DEBUG if get_settings().is_development() else logging.INFO,
    format ="%(asctime)s | %(name)s | %(levelname)s | %(filename)s:%(lineno)d -> %(message)s",
    handlers=[logging.StreamHandler()],
    force=True,
    
)
logger = logging.getLogger("api")
logger.info(f"starting API in {get_settings().app_mode.upper()} mode")
@asynccontextmanager
async def lifespan(app:FastAPI):
    #start
    await init_db()
    app.state.redis_pool = await get_redis_pool()
    await FastAPILimiter.init(app.state.redis_pool)
    yield
    #shutdown
    await engine.dispose()
    await app.state.redis_pool.aclose()
    
mode = get_settings().app_mode
    
app=FastAPI(title="Ecommerce app",docs_url="/api/docs",redoc_url="/api/redoc",openapi_url="/api/openapi.json")  

origins = [
    "http://localhost:5174/",
    #"http://myfrontenddomain.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#routes
app.include_router(products_router)
# other routers goes here


# ___ Register generic error  in production
if get_settings().app_mode == AppMode.PRODUCTION:
    #def get_global_exception():
    async def production_exception(_request: Request, exc: Exception):
        logger.exception("internal server error")
        return JSONResponse(status_code=500,content={"detail":"something went wrong please try again later"})
    app.add_exception_handler(Exception,production_exception())
    logger.info("global exception handler enabled(production mode)")
else:
    logger.info("global exception handler disabled(debug mode on)")
#redis.py
import redis.asyncio as redis
from typing import AsyncGenerator,Annotated
from contextlib import asynccontextmanager

REDIS_URL="redis://localhost:6379" #try move this to settings settings().Redis_url

Redis_connection=redis.Redis

# create a usable redis connection pool
async def get_redis_pool() -> redis.Redis:
    return await redis.from_url(REDIS_URL, decode_responses = True)
 
 
 # redis dependency       
@asynccontextmanager
async def get_redis() ->AsyncGenerator[redis.Redis,None]:
    client = await redis.from_url(REDIS_URL,decode_response=True)
    try:
        await client.ping()
        yield client
    except redis.ConnectionError as e:
        raise Exception(f"failed to connect to redis:{e}")
    finally:
        pass #no need to close as pool is managed by lifespan
#taslk.py
from tenacity import retry, stop_after_attempt,wait_exponential, retry_if_exception_type
import logging
import asyncio
from fastapi_mail import FastMail, MessageSchema, MessageType
from api.core.mail import mail_config
from api.core.celery import app_name

logger=logging.getLogger(__name__)

@retry(
    stop=stop_after_attempt(4),
    wait= wait_exponential(multiplier=2, min=2, max=30),
    retry=retry_if_exception_type((ConnectionError, TimeoutError, Exception)),
    before_sleep=lambda rs:logger.warning(
        f"OTP email failed(attempt {rs.attempt_number}).Retrying in {rs.next_action.sleep:.1f}s..."),
    reraise=True,
)
async def _send_otp_email(recipient:str, otp:str, subject:str) -> None:
    message=MessageSchema(
        subject=subject,
        recipients=[recipient],
        body=f"Your OTP is {otp} it expires in 20 minutes",
        subtype=MessageType.plain,
    )
    fm=FastMail(mail_config)
    await fm.send_message(message)
    logger.info(f"OTP email sent to {recipient}")
    
    
@app_name.task(bind=True,max_retries=0)
def send_otp_email_task(self, recipient:str, otp:str, subject:str):
    try:
        loop=asyncio.get_event_loop()
        loop.run_until_complete(_send_otp_email(recipient,otp,subject))
    except Exception as exc:
        logger.error(f"Failed to send OTP to {recipient} after all retries: {exc}")
        raise
        
#celery
from api.core.settings import get_settings
from celery import Celery

app_name = Celery(
    "underground_task",
    broker=get_settings().broker,
    #backend=
    )
app_name.autodiscover_tasks()

#mail
  from fastapi_mail import FastMail, ConnectionConfig
from api.core.settings import get_settings
from typing import AsyncGenerator

mail_config = ConnectionConfig(
    MAIL_USERNAME=get_settings().MAIL_USERNAME,
    MAIL_PASSWORD=get_settings().MAIL_PASSWORD,
    MAIL_FROM=get_settings().MAIL_FROM,
    MAIL_PORT=get_settings().MAIL_PORT,
    MAIL_SERVER=get_settings().MAIL_SERVER,
    MAIL_SSL=get_settings().MAIL_SSL,
    MAIL_TLS=get_settings().MAIL_TLS,
)


mail=FastMail(mail_config)
# mail dependency
async def get_fastmail() -> AsyncGenerator[FastMail,None]:
    fm=FastMail(mail_config)
    yield fm
       
        
        
      
