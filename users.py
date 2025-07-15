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