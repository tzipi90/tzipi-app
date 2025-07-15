import os
import requests
import base64
from dotenv import load_dotenv
import openai

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

from db import *
from models import Invoice
from aws_file_utils import *
from models import Invoice
from sqlalchemy.orm import Session

def get_user_invoices(user_id: int, db: Session):
    invoices = db.query(Invoice).filter(Invoice.user_id == user_id).all()
    for invoice in invoices:
        if invoice.file_key:
            invoice.presigned_url = get_presigned_url_from_key(invoice.file_key)
    return invoices
    
def save_invoice_to_db(data: dict):
    db = SessionLocal()
    try:
        invoice = Invoice(**data)
        db.add(invoice)
        db.commit()
        db.refresh(invoice)
        return invoice
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def encode_image_from_url(image_url: str) -> str:
    response = requests.get(image_url)
    response.raise_for_status()
    return base64.b64encode(response.content).decode("utf-8")

def ask_openai_about_invoice(base64_image: str) -> dict:
    prompt = """
You are an expert at reading financial documents. Extract the following fields from the image of an invoice:

- Total amount (in numbers)
- Date of invoice (in ISO format: YYYY-MM-DD)
- Name or description of the service or item
- Suggested accounting category (e.g. marketing, office supplies, transportation, software, etc.)
- Name of the provider or company who issued the invoice
- Invoice number (written anywhere on the document)

Return the result as a JSON object with these keys: amount, date, service, category, provider, invoice_number.
Only return the JSON, no explanations or notes.
"""
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "user", "content": [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{base64_image}"}}
            ]}
        ],
        max_tokens=500
    )


    # Extract JSON from the reply (be generous in case model adds explanation)
    import json, re
    text_response = response.choices[0].message.content
    match = re.search(r"\{.*\}", text_response, re.DOTALL)
    if match:
        return json.loads(match.group(0))
    else:
        return {"error": "Could not extract structured data", "raw": text_response}

def analyze_invoice_url(image_url: str):
    base64_img = encode_image_from_url(image_url)
    result = ask_openai_about_invoice(base64_img)
    return result

# Example
if __name__ == "__main__":
    image_url = "https://s3.amazonaws.com/thumbnails.venngage.com/template/f817aebd-2d8e-42cf-8c9f-80a234f077ea.png"  # Replace with your image URL
    result = analyze_invoice_url(image_url)
    print(result)
