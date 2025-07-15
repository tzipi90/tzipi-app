import psycopg2
from psycopg2.extras import RealDictCursor
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Connection for creating the DB
DB_HOST = "node128.codingbc.com"
DB_PORT = "9001"
DB_USER = "postgres"
DB_PASSWORD = "Lesson2017890"
DB_NAME = "tzipi_invoice_db"

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
