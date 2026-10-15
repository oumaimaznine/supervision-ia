import time
import pymysql
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta

# Configuration
SECRET_KEY = "change-moi-avec-une-vraie-cle-secrete-longue-et-aleatoire"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 heures

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DB_CONFIG = {
    "host": "localhost",
    "port": 3307,  # le port externe defini pour mysql
    "user": "root",
    "password": "root",
    "database": "supervision_db"
}

def get_db_connection(retries=3, delay=1):
    """Se connecte a MySQL avec plusieurs tentatives en cas de coupure temporaire."""
    last_error = None
    for attempt in range(retries):
        try:
            return pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
        except Exception as e:
            last_error = e
            time.sleep(delay)
    raise last_error

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def create_user(username: str, email: str, password: str, role: str = "user"):
    """Cree un nouvel utilisateur dans la base."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            hashed = hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                (username, email, hashed, role)
            )
        conn.commit()
        return True
    except pymysql.err.IntegrityError:
        return False  # username ou email deja utilise
    finally:
        conn.close()

def get_user_by_username(username: str):
    """Recupere un utilisateur par son nom d'utilisateur."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            return cursor.fetchone()
    finally:
        conn.close()

def authenticate_user(username: str, password: str):
    """Verifie les identifiants, retourne l'utilisateur si valide, sinon None."""
    user = get_user_by_username(username)
    if not user:
        return None
    if not user["is_active"]:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user