import magic
from fastapi import HTTPException, UploadFile

ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}

async def validate_file_securely(file: UploadFile):
    # Read first 2KB for magic byte detection
    header = await file.read(2048)
    await file.seek(0) # Always rewind!
    
    detected_mime = magic.from_buffer(header, mime=True)
    
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=415, 
            detail=f"File {file.filename} is an invalid type: {detected_mime}"
        )
    return detected_mime

####
# Reuse the helper function from earlier
def get_s3_url(key: str | None):
    if not key: return None
    return s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': BUCKET_NAME, 'Key': key},
        ExpiresIn=3600
    )

#get home
@app.get("/home", response_model=HomeResponse)
def get_home_settings(session: Session = Depends(get_session)):
    # Always fetch the one marked "MAIN"
    statement = select(Home).where(Home.config_type == "MAIN")
    home = session.exec(statement).first()
    
    if not home:
        raise HTTPException(status_code=404, detail="Settings not initialized")

    return HomeResponse(
        sitename=home.sitename,
        logo_url=get_s3_url(home.logo_key), # Helper function for presigned URL
        image_url=get_s3_url(home.image_key)
    )


###


else:
            # OPTIONAL: Delete old files from S3 before updating keys
            if home.logo_key:
                s3_client.delete_object(Bucket=BUCKET_NAME, Key=home.logo_key)
            if home.image_key:
                s3_client.delete_object(Bucket=BUCKET_NAME, Key=home.image_key)

            # UPDATE: Replace fields
            home.sitename = sitename
            home.logo_key = logo_key
            home.image_key = image_key
#new
import uuid
from typing import Annotated
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from sqlmodel import Session, select

router = APIRouter()

@router.post("/home/setup", status_code=201)
async def setup_home(
    sitename: Annotated[str, Form()],
    logo: Annotated[UploadFile, File()],
    image: Annotated[UploadFile, File()],
    session: Session = Depends(get_session)
):
    # 1. Secure Validation
    await validate_file_securely(logo)
    await validate_file_securely(image)

    # 2. Check if the "MAIN" singleton record already exists
    statement = select(Home).where(Home.config_type == "MAIN")
    home = session.exec(statement).first()
    
    # 3. Prepare unique S3 Keys
    logo_key = f"home/logo-{uuid.uuid4()}"
    image_key = f"home/hero-{uuid.uuid4()}"

    try:
        # 4. Stream uploads to S3 (Efficient for 2025)
        s3_client.upload_fileobj(logo.file, BUCKET_NAME, logo_key)
        s3_client.upload_fileobj(image.file, BUCKET_NAME, image_key)

        if not home:
            # CREATE: New record with the unique config_type
            home = Home(
                sitename=sitename, 
                config_type="MAIN", # Enforces the singleton via DB constraint
                logo_key=logo_key, 
                image_key=image_key
            )
            session.add(home)
        else:
            # UPDATE: Replace fields on the existing "MAIN" record
            home.sitename = sitename
            home.logo_key = logo_key
            home.image_key = image_key
        
        session.commit()
        session.refresh(home)
        return {"message": "Home settings updated", "config_type": home.config_type}

    except Exception as e:
        session.rollback()
        # Optionally delete uploaded S3 files here if the DB commit fails
        raise HTTPException(status_code=500, detail="Failed to save settings")

#
import asyncio

# This runs both validations at the same time
await asyncio.gather(
    validate_file_securely(image),
    validate_file_securely(logo)
)

#
@app.post("/products/{product_id}/media")
async def upload_product_media(
    product_id: int, 
    image: UploadFile = File(...), 
    logo: UploadFile = File(...), 
    session: Session = Depends(get_session)
):
    # Validate both files individually
    await validate_file_securely(image)
    await validate_file_securely(logo)

    # Process S3 uploads for both...
    # unique_image_key = ...
    # unique_logo_key = ...
    
    return {"message": "Image and Logo uploaded successfully"}

#
import magic
from fastapi import HTTPException, UploadFile

ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/svg"}

async def validate_file_securely(file: UploadFile):
    # Read first 2KB for magic byte detection
    header = await file.read(2048)
    await file.seek(0) # Always rewind!
    
    detected_mime = magic.from_buffer(header, mime=True)
    
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=415, 
            detail=f"File {file.filename} is an invalid type: {detected_mime}"
        )
    return detected_mime

#boto
import boto3
from botocore.exceptions import ClientError

s3_client = boto3.client('s3')
BUCKET_NAME = "your-app-bucket"

def upload_to_s3(file_data, key, content_type):
    s3_client.put_object(Bucket=BUCKET_NAME, Key=key, Body=file_data, ContentType=content_type)

def get_presigned_url(key):
    if not key: return None
    return s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': BUCKET_NAME, 'Key': key},
        ExpiresIn=3600
    )

#addd
import uuid
from typing import Annotated
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from sqlmodel import Session

router = APIRouter()

@router.post("/products", status_code=201)
async def create_product(
    # Use Form for text data and File for the image
    name: Annotated[str, Form()],
    price: Annotated[float, Form()],
    image: Annotated[UploadFile, File()],
    session: Session = Depends(get_session)
):
    # 1. Basic Validation (Optional but recommended for 2025)
    if not image.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")

    # 2. Generate a unique S3 Key (Path)
    # Pattern: products/uuid-filename.jpg
    file_extension = image.filename.split(".")[-1]
    unique_key = f"products/{uuid.uuid4()}.{file_extension}"

    try:
        # 3. Upload file to S3
        file_content = await image.read()
        s3_client.put_object(
            Bucket=BUCKET_NAME,
            Key=unique_key,
            Body=file_content,
            ContentType=image.content_type
        )

        # 4. Save metadata to Database
        new_product = Product(
            name=name,
            price=price,
            image_key=unique_key  # Store the reference, not the file
        )
        session.add(new_product)
        session.commit()
        session.refresh(new_product)

        return {"message": "Product created", "product_id": new_product.id}

    except Exception as e:
        # Log error and inform user
        print(f"S3 Upload Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload image")


#get
@app.get("/products", response_model=List[ProductResponse])
def get_products(session: Session = Depends(get_session)):
    # 1. Fetch all products from database
    products = session.exec(select(Product)).all()
    
    # 2. Build the list of responses with S3 links
    product_list = []
    for p in products:
        url = None
        if p.image_key:
            # Generate a 1-hour secure link for each product
            url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': BUCKET_NAME, 'Key': p.image_key},
                ExpiresIn=3600
            )
        
        # Create response object and append
        product_list.append(
            ProductResponse(
                id=p.id,
                name=p.name,
                price=p.price,
                image_url=url
            )
        )
        
    return product_list
