<H1> INVOICE READER WORKSHOP </H1>

<h3>SETUP</h3>
 run in shell window
```
pip install dotenv requests fastapi uvicorn sqlalchemy alembic python-jose[cryptography] passlib[bcrypt] python-multipart openai psycopg2-binary boto3  jinja2
```

![Architecture Diagram](images/architecture.png)

<h3>add OPENAI_API_KEY as secret </h3>
go to "secrets" screen in replit and add 

```
OPENAI_API_KEY=openai key

AWS_ACCESS_KEY_ID=aws access id
AWS_SECRET_ACCESS_KEY=aws secret
```

<h3>create the invoice reader utility</h3>

invoice_reader.py
```
import os
import requests
import base64
from dotenv import load_dotenv
import openai

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

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


```

<h4>test</h4>
run in shell window

```
python invoice_reader.py
```

<h3>call invoice reading from swagger</h3>

main.py
```
from invoice_reader import analyze_invoice_url
from fastapi import FastAPI, HTTPException, Query
```
```
@app.get("/read-invoice-by-url")
def read_invoice_by_url(url: str = Query(..., description="Direct image URL")):
    try:
        return analyze_invoice_url(url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```
run the app and navigate to /docs <br>
run the read-invoice-by-url api with this url:
https://s3.amazonaws.com/thumbnails.venngage.com/template/f817aebd-2d8e-42cf-8c9f-80a234f077ea.png

<h3>DB CREATION</h3>
db.py

```
import psycopg2
from psycopg2.extras import RealDictCursor
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Connection for creating the DB
DB_HOST = "node128.codingbc.com"
DB_PORT = "9001"
DB_USER = "postgres"
DB_PASSWORD = "Lesson2017890"
DB_NAME = "[yourname]_invoice_db"

# SQLAlchemy connection string
SQLALCHEMY_DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = None
SessionLocal = None

def try_create_session():
    global engine, SessionLocal
    try:
        engine = create_engine(SQLALCHEMY_DATABASE_URL)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        print("Database connection successful.")
    except Exception as e:
        print(f"Error connecting to database with SQLAlchemy: {e}")

db_connection = None

def get_db_connection():
    return get_db_connection_(DB_NAME)

def get_db_connection_(db_name):
    global db_connection
    try:
        db_connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            dbname=db_name
        )
        db_connection.autocommit = True
        return db_connection
    except psycopg2.Error as e:
        print(f"Error connecting to database '{db_name}': {e}")
        db_connection = None
        return None

def init_db():
    conn = get_db_connection_('postgres')  # connect to default 'postgres' DB
    if conn:
        try:
            with conn.cursor() as cursor:
                cursor.execute(f"CREATE DATABASE {DB_NAME};")
                print(f"Database '{DB_NAME}' initialized successfully.")
                return True
        except psycopg2.Error as e:
            if "already exists" in str(e):
                print(f"Database '{DB_NAME}' already exists.")
                return True
            print(f"Error initializing database: {e}")
            return False
        finally:
            conn.close()
    return False
    
try_create_session() 
if __name__ == "__main__": 
    init_db()             

```
change the DB_NAME to [yourname]_invoice_db

<h4>test</h4>
run in shell window

```
python db.py
```

<h4>connect to db</h4>
use table plus to connect to postgres DB

```
DB_HOST = "node128.codingbc.com"
DB_PORT = "9001"
DB_USER = "postgres"
DB_PASSWORD = "Lesson2017890#"
DB_NAME = "[yourname]_invoice_db"
```
![DB Connection](images/tableplus.png)

edit main.py:
from db import *
init_db()

<h2>15 mins break</h2>

<h3>Alembic</h3>
run in shell window

```
alembic init alembic
```

models.py

```
from sqlalchemy import Column, Integer, String, Float, Date, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()



class Invoice(Base):
    __tablename__ = "invoices"

    id = Column(Integer, primary_key=True, index=True)
    amount = Column(Float, nullable=False)
    date = Column(Date, nullable=False)
    service = Column(String, nullable=False)
    category = Column(String, nullable=False)
    provider = Column(String, nullable=False)
    invoice_number = Column(String, nullable=False, unique=False)



```

edit alembic.ini

```
sqlalchemy.url = postgresql+psycopg2://postgres:Lesson2017890@node128.codingbc.com:9001/[your_name]_invoice_db
```

edit alembic/env.py 

```
from models import Base
target_metadata = Base.metadata
```

run in shell

```
alembic revision --autogenerate -m "create invoices table"
alembic upgrade head
```

<h3>Save to DB with API</h3>
edit invoice_reader.py

```
from db import *
from models import Invoice


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
```

edit main.py

```
from invoice_reader import save_invoice_to_db
@app.get("/read-invoice-by-url")
def read_invoice_by_url(url: str = Query(..., description="Direct image URL")):
    try:
        data = analyze_invoice_url(url)
        save_invoice_to_db(data)
        return {"status": "saved", "invoice": data}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
        
```
<h3>Save files to s3</h3>

aws_file_utils.py

```
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

```

main.py

```
from fastapi import File, UploadFile
from aws_file_utils import upload_and_get_presigned_url
from invoice_reader import analyze_invoice_url

@app.post("/upload-invoice-file")
def upload_invoice_file(file: UploadFile = File(...)):
    try:
        file_bytes = file.file.read()
        key, url = upload_and_get_presigned_url(file_bytes, file.filename, file.content_type)
        print (f"Presigned s3 url: {url}")
        data = analyze_invoice_url(url)
        save_invoice_to_db(data)
        return {"status": "success", "invoice": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

<h3>add file url to db</h3>

models.py

```
    file_key = Column(String, nullable=True)
```

run bash

```
alembic revision --autogenerate -m "add file_key to invoices"
alembic upgrade head
```

in main.pay add
```
        data["file_key"] = key
```

<h3>add users and jwt</h3>

models.py

```
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
```

auth.py

```
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from db import SessionLocal
from models import *

SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def hash_password(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Invalid credentials")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        username = payload.get("sub")
        if username is None:
            raise credentials_exception

        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise credentials_exception
        return user

    except JWTError:
        raise credentials_exception


```

users.py

```
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from db import SessionLocal
from models import User
from auth import hash_password, verify_password


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_by_username(username: str, db: Session = None) -> User | None:
    if not db:
        db = next(get_db())
    return db.query(User).filter(User.username == username).first()

def get_user_by_email(email: str, db: Session = None) -> User | None:
    if not db:
        db = next(get_db())
    return db.query(User).filter(User.email == email).first()

def get_user_by_id(user_id: int, db: Session = None) -> User | None:
    if not db:
        db = next(get_db())
    return db.query(User).filter(User.id == user_id).first()

def create_user(username: str, email: str, password: str, db: Session = None) -> User:
    if not db:
        db = next(get_db())
    hashed = hash_password(password)
    user = User(username=username, email=email, hashed_password=hashed)
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
        return user
    except IntegrityError:
        db.rollback()
        raise ValueError("Username or email already exists")

def validate_user_credentials(username: str, password: str, db: Session = None) -> User | None:
    if not db:
        db = next(get_db())
    user = get_user_by_username(username, db)
    if user and verify_password(password, user.hashed_password):
        return user
    return None

```

main.py

```
from fastapi import FastAPI, HTTPException, Form, Depends
from fastapi.security import OAuth2PasswordRequestForm
from users import *
from models import *
from auth import *

app = FastAPI()

@app.post("/signup")
def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    try:
        user = create_user(username, email, password)
        return {"msg": "User created", "user_id": user.id}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = validate_user_credentials(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token(data={"sub": str(user.username)})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me")
def read_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email
    }

```
<h3>add user id to invoice table and protect invoice adding</h3>

edit models.py
```
    user_id = Column(Integer, nullable=True)
```

run shell

```
alembic revision --autogenerate -m "add user_id to invoices"
alembic upgrade head
```

main.py

```
@app.post("/upload-invoice-file")
def upload_invoice_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    try:
        file_bytes = file.file.read()
        file_key, url = upload_and_get_presigned_url(file_bytes, file.filename, file.content_type)
        print(f"Presigned s3 url: {url}")
        data = analyze_invoice_url(url)
        data["file_key"] = file_key
        data["user_id"] = current_user.id
        save_invoice_to_db(data)
        return {"status": "success", "invoice": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

invoice_reader.py

```
from aws_file_utils import *
from models import Invoice
from sqlalchemy.orm import Session

def get_user_invoices(user_id: int, db: Session):
    invoices = db.query(Invoice).filter(Invoice.user_id == user_id).all()
    for invoice in invoices:
        if invoice.file_key:
            invoice.presigned_url = get_presigned_url_from_key(invoice.file_key)
    return invoices
```

main.py 

```
from fastapi import Depends
from users import get_db
from sqlalchemy.orm import Session
from invoice_reader import get_user_invoices

@app.get("/api/my-invoices")
def my_invoices(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    invoices = get_user_invoices(current_user.id, db)
    return [invoice.__dict__ for invoice in invoices]
```

<h2>LUNCH BREAK</h2>

<h3>UI Build with ChatGPT</h3>

static/style.css

```
body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background: #fefefe;
  padding: 2rem;
  max-width: 600px;
  margin: auto;
  color: #333;
}

h2 {
  text-align: center;
  color: #e91e63;
}

form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  background: #fff;
  padding: 1.5rem;
  border-radius: 12px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

input[type="text"],
input[type="email"],
input[type="password"],
input[type="file"],
button {
  padding: 0.75rem;
  border: 1px solid #ccc;
  border-radius: 8px;
  font-size: 1rem;
}

button {
  background-color: #e91e63;
  color: white;
  border: none;
  cursor: pointer;
  transition: 0.3s ease;
}

button:hover {
  background-color: #c2185b;
}

p, a {
  text-align: center;
}

a {
  color: #e91e63;
  text-decoration: none;
}

a:hover {
  text-decoration: underline;
}

.invoice-card {
  background: #fff;
  padding: 1rem;
  margin-top: 1rem;
  border-radius: 10px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.05);
}

.invoice-card p {
  margin: 0.2rem 0;
}

.logout {
  text-align: right;
  margin-bottom: 1rem;
}
.logout button {
  background-color: #607d8b;
}
.logout button:hover {
  background-color: #455a64;
}

```

templates/login.html

```
<!DOCTYPE html>
<html>
<head>    <title>Login</title>
  <link rel="stylesheet" href="/static/style.css" />
</head>
<body>
<div class="container">
    <h2>Login</h2>
  <form action="/login" method="post">
      <input type="text" name="username" placeholder="Username" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Login</button>
      <p>Don't have an account yet? <a href="/signup-form">Sign up here</a></p>
  </form>
</div>
    <script>
    document.querySelector("form").addEventListener("submit", async (e) => {
      e.preventDefault();

      const formData = new FormData(e.target);
      const response = await fetch("/login", {
        method: "POST",
        body: formData
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem("token", data.access_token);
        window.location.href = "/my-invoices";
      } else {
        alert("Login failed. Please check your credentials.");
      }
    });
    </script>

</body>
</html>

```

tepmlates/signup.html

```
<!DOCTYPE html>
<html>
<head>
    <title>Sign Up</title>
    <link rel="stylesheet" href="/static/style.css" />
</head>
<body>
    <h2>Sign Up</h2>
    <form id="signupForm">
        <input type="text" name="username" placeholder="Username" required /><br />
        <input type="email" name="email" placeholder="Email" required /><br />
        <input type="password" name="password" placeholder="Password" required /><br />
        <button type="submit">Sign Up</button>
    </form>
    <p>Already have an account? <a href="/login-form">Log in here</a></p>

    <script>
        document.getElementById("signupForm").addEventListener("submit", async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const res = await fetch("/signup", {
                method: "POST",
                body: formData
            });
            if (res.ok) {
                alert("Signup successful! Please log in.");
                window.location.href = "/login-form";
            } else {
                const err = await res.json();
                alert(err.detail || "Signup failed");
            }
        });
    </script>
</body>
</html>

```

templates/my_invoices.html

```
<!DOCTYPE html>
<html>
<head>
    <title>My Invoices</title>
    <link rel="stylesheet" href="/static/style.css" />
</head>
<body>
    <div class="logout"><button onclick="logout()">Logout</button></div>
    <h2>My Invoices</h2>
    <div id="invoicesList"></div>
    <p><a href="/upload-invoice-form">Upload another invoice</a></p>

    <script>
        async function fetchInvoices() {
            const token = localStorage.getItem("token");
            const res = await fetch("/api/my-invoices", {
                headers: {
                    Authorization: `Bearer ${token}`
                }
            });
            if (res.status === 401) {
                alert("You are not authenticated. Please login again.");
                window.location.href = "/login-form";
                return;
            }
            const invoices = await res.json();
            const container = document.getElementById("invoicesList");
            container.innerHTML = "";

            invoices.forEach(inv => {
                const div = document.createElement("div");
                div.className = "invoice-card";
                div.innerHTML = `
                    <p><strong>Provider:</strong> ${inv.provider}</p>
                    <p><strong>Amount:</strong> ${inv.amount}</p>
                    <p><strong>Date:</strong> ${inv.date}</p>
                    <p><strong>Invoice #:</strong> ${inv.invoice_number}</p>
                    ${inv.presigned_url ? `<a href="${inv.presigned_url}" target="_blank">Download File</a>` : ""}
                `;
                container.appendChild(div);
            });
        }

        function logout() {
            localStorage.removeItem("token");
            window.location.href = "/login-form";
        }

        fetchInvoices();
    </script>
</body>
</html>
```

templates/upload_invoice.html

```
<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/static/style.css" />
    <title>Upload Invoice</title>
</head>
<body>
    <h2>Upload Invoice</h2>
    <form id="uploadForm">
        <input type="file" name="file" required /><br />
        <button type="submit">Upload</button>
    </form>

    <script>
        document.getElementById("uploadForm").addEventListener("submit", async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const token = localStorage.getItem("token");

            const res = await fetch("/upload-invoice-file", {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`
                },
                body: formData
            });

            const data = await res.json();
            if (res.ok) {
                alert("Invoice uploaded successfully!");
                window.location.href = "/my-invoices";
            } else {
                alert(data.detail || "Upload failed");
            }
        });
    </script>
</body>
</html>

```

main.py

```

from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
from fastapi.responses import HTMLResponse

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/")
def root():
    return RedirectResponse(url="/signup-form")

@app.get("/signup-form")
def signup_form(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.get("/login-form")
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/upload-invoice-form")
def upload_invoice_form(request: Request):
    return templates.TemplateResponse("upload_invoice.html", {"request": request})

@app.get("/my-invoices", response_class=HTMLResponse)
def my_invoices_page(
    request: Request
):
    return templates.TemplateResponse("my_invoices.html", {"request": request})

```

 
<h3>Add the project to your github</h3>
use the replit Github tab

<h3>Dokcerize</h3>

requirements.txt

```
alembic
annotated-types
anyio
bcrypt
boto3
botocore
certifi
cffi
charset-normalizer
click
cryptography
distro
dotenv
ecdsa
fastapi
greenlet
h11
httpcore
httpx
idna
Jinja2
jiter
jmespath
jose
Mako
MarkupSafe
openai
passlib
psycopg2-binary
pyasn1
pycparser
pydantic
pydantic_core
python-dateutil
python-dotenv
python-jose
python-multipart
requests
rsa
s3transfer
six
sniffio
SQLAlchemy
starlette
tqdm
typing_extensions
urllib3
uvicorn
```

Dockerfile

```
# Base image with Python
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements (if you have one)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire app
COPY . .

# Expose FastAPI default port
EXPOSE 8000

# Run the app with uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

<h3> Docker Hub</h3>

setup an account and create a personal access token

<h3> Github Actions </h3>
create the following secrects on your github repo
settings -> actions -> secrets

```
DOCKERHUB_TOKEN
DOCKERHUB_USER
```

.github/workflows/dockerhub-push.yml

```
name: Build and Push Docker Image

on:
  push:
    branches:
      - main

jobs:
  build-and-push:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Log in to DockerHub
        run: echo "${{ secrets.DOCKERHUB_TOKEN }}" | docker login -u "${{ secrets.DOCKERHUB_USER }}" --password-stdin

      - name: Build Docker image with build number tag
        run: |
          IMAGE_TAG=${{ github.run_number }}
          docker build -t ${{ secrets.DOCKERHUB_USER }}/invoice-app:$IMAGE_TAG .

      - name: Push Docker image
        run: |
          IMAGE_TAG=${{ github.run_number }}
          docker push ${{ secrets.DOCKERHUB_USER }}/invoice-app:$IMAGE_TAG

```

<h3> Runmydocker.com </h3>
create a container (find the image in dockerhub)<br>

when creating the container add env variables:
```
OPENAI_API_KEY=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
```


