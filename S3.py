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
