import boto3
import os
import uuid
from dotenv import load_dotenv

load_dotenv()

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = "us-east-1"
S3_BUCKET = "ai.workshop.files"

s3_client = boto3.client(
    "s3",
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

def upload_and_get_presigned_url(file_bytes: bytes, filename: str, content_type: str = "image/png"):
    key = f"invoices/{uuid.uuid4()}_{filename}"

    s3_client.put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=file_bytes,
        ContentType=content_type
    )

    presigned_url = s3_client.generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": key},
        ExpiresIn=3600
    )

    return key, presigned_url


def get_presigned_url_from_key(key: str, expires_in: int = 3600) -> str:
    """
    Returns a pre-signed URL for a given S3 object key.
    """
    presigned_url = s3_client.generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": key},
        ExpiresIn=expires_in
    )
    return presigned_url
