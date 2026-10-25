from fastapi.middleware.cors import CORSMiddleware
import base64
import secrets
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jwt
import base64
import os
from datetime import datetime, timedelta, timezone

from database import get_connection, init_db

app = FastAPI(title="Crypto-Pro Secure Communication")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "https://cryptovault-frontend-7uuo.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# SECURITY CONFIGURATION
# =========================================================

password_hasher = PasswordHasher()

SECRET_KEY = "crypto-pro-secret-key-change-this-later"
ALGORITHM = "HS256"

security = HTTPBearer()


# =========================================================
# REQUEST MODELS
# =========================================================

class SignupRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


def ensure_password_reset_table():
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        connection.commit()
    finally:
        connection.close()

init_db()
ensure_password_reset_table()
class ForgotPasswordRequest(BaseModel):
    email: str

# =========================================================
# MESSAGING DATABASE
# =========================================================

def ensure_messages_table():
    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                ciphertext TEXT NOT NULL,
                signature TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (recipient_id) REFERENCES users(id)
            )
        """)

        connection.commit()

    finally:
        connection.close()


ensure_messages_table()


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
class SignatureRequest(BaseModel):
    message: str


class VerifySignatureRequest(BaseModel):
    message: str
    signature: str
    public_key: str


class EncryptionRequest(BaseModel):
    plaintext: str
    secret_key: str

class DecryptionRequest(BaseModel):
    ciphertext: str
    secret_key: str


class SendMessageRequest(BaseModel):
    recipient_username: str
    ciphertext: str
    signature: str = ""


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():
    return {
        "message": "Crypto-Pro Secure Communication Backend is running!"
    }


# =========================================================
# SIGN UP
# =========================================================

@app.post("/signup")
def signup(user: SignupRequest):

    password_hash = password_hasher.hash(
        user.password
    )

    connection = get_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO users
            (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (
                user.username,
                user.email,
                password_hash
            )
        )

        connection.commit()

        return {
            "message": "Account created successfully!",
            "username": user.username,
            "email": user.email
        }

    except Exception as error:

        connection.rollback()

        return {
            "message": "Account creation failed",
            "error": str(error)
        }

    finally:

        connection.close()


# =========================================================
# LOGIN
# =========================================================

@app.post("/login")
def login(user: LoginRequest):

    connection = get_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (user.username,)
        )

        existing_user = cursor.fetchone()

        if existing_user is None:

            return {
                "message": "Invalid username or password"
            }

        try:

            password_hasher.verify(
                existing_user["password_hash"],
                user.password
            )

        except Exception:

            return {
                "message": "Invalid username or password"
            }


        # Create JWT token

        token_data = {

            "user_id":
                existing_user["id"],

            "username":
                existing_user["username"],

            "exp":
                datetime.now(timezone.utc)
                + timedelta(minutes=30)
        }


        access_token = jwt.encode(
            token_data,
            SECRET_KEY,
            algorithm=ALGORITHM
        )


        return {

            "message":
                "Login successful!",

            "access_token":
                access_token,

            "token_type":
                "bearer",

            "username":
                existing_user["username"],

            "email":
                existing_user["email"]
        }

    finally:

        connection.close()


# =========================================================
# JWT AUTHENTICATION
# =========================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials =
        Depends(security)
):

    token = credentials.credentials

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        return payload

    except jwt.ExpiredSignatureError:

        raise HTTPException(
            status_code=401,
            detail="Token has expired"
        )

    except jwt.InvalidTokenError:

        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token"
        )


# =========================================================
# CURRENT USER
# =========================================================

@app.get("/me")
def get_me(
    current_user: dict =
        Depends(get_current_user)
):

    return {

        "message":
            "Authenticated user",

        "user_id":
            current_user["user_id"],

        "username":
            current_user["username"]
    }


# =========================================================
# AES-GCM KEY GENERATION
# =========================================================

def create_aes_key(secret_key: str):

    """
    Convert the user's secret key into
    a valid 256-bit AES key.

    SHA-256 produces exactly 32 bytes.
    32 bytes = 256 bits.
    """

    import hashlib

    return hashlib.sha256(
        secret_key.encode("utf-8")
    ).digest()


# =========================================================
# AES-GCM ENCRYPTION
# =========================================================

@app.post("/encrypt")
def encrypt_message(
    request: EncryptionRequest,
    current_user: dict =
        Depends(get_current_user)
):

    if not request.plaintext:

        raise HTTPException(
            status_code=400,
            detail="Plain text cannot be empty"
        )


    if not request.secret_key:

        raise HTTPException(
            status_code=400,
            detail="Secret key cannot be empty"
        )


    # Create AES-256 key

    aes_key = create_aes_key(
        request.secret_key
    )


    # Create random 12-byte nonce

    nonce = os.urandom(12)


    # Create AES-GCM cipher

    aes_gcm = AESGCM(aes_key)


    # Encrypt message

    encrypted_data = aes_gcm.encrypt(
        nonce,
        request.plaintext.encode("utf-8"),
        None
    )


    # Combine nonce + encrypted data

    final_data = nonce + encrypted_data


    # Convert binary data to Base64
    # so it can safely travel through JSON

    ciphertext = base64.b64encode(
        final_data
    ).decode("utf-8")


    return {

        "message":
            "Encryption successful",

        "algorithm":
            "AES-256-GCM",

        "ciphertext":
            ciphertext,

        "username":
            current_user["username"]
    }


# =========================================================
# AES-GCM DECRYPTION
# =========================================================

@app.post("/decrypt")
def decrypt_message(
    request: DecryptionRequest,
    current_user: dict =
        Depends(get_current_user)
):

    if not request.ciphertext:

        raise HTTPException(
            status_code=400,
            detail="Cipher text cannot be empty"
        )


    if not request.secret_key:

        raise HTTPException(
            status_code=400,
            detail="Secret key cannot be empty"
        )


    try:

        # Decode Base64

        encrypted_data = base64.b64decode(
            request.ciphertext
        )


        # First 12 bytes are the nonce

        nonce = encrypted_data[:12]


        # Remaining bytes are encrypted data

        ciphertext = encrypted_data[12:]


        # Create same AES-256 key

        aes_key = create_aes_key(
            request.secret_key
        )


        # Create AES-GCM cipher

        aes_gcm = AESGCM(aes_key)


        # Decrypt

        plaintext = aes_gcm.decrypt(
            nonce,
            ciphertext,
            None
        )


        return {

            "message":
                "Decryption successful",

            "algorithm":
                "AES-256-GCM",

            "plaintext":
                plaintext.decode("utf-8"),

            "username":
                current_user["username"]
        }


    except Exception:

        raise HTTPException(
            status_code=400,
            detail=
                "Decryption failed. "
                "Check the cipher text and secret key."
        )
    
@app.post("/signature/sign")
def sign_message(
    data: SignatureRequest,
    current_user: dict = Depends(get_current_user)
):
    # Generate an RSA key pair for this demonstration
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    signature = private_key.sign(
        data.message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return {
        "message": "Digital signature generated successfully",
        "signature": base64.b64encode(signature).decode("utf-8"),
        "public_key": public_pem
    }


@app.post("/signature/verify")
def verify_signature(
    data: VerifySignatureRequest,
    current_user: dict = Depends(get_current_user)
):
    try:
        public_key = serialization.load_pem_public_key(
            data.public_key.encode("utf-8")
        )

        signature_bytes = base64.b64decode(
            data.signature,
            validate=True
        )

        public_key.verify(
            signature_bytes,
            data.message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return {
            "valid": True,
            "message": "Signature is valid. The message has not been modified."
        }

    except Exception:
        return {
            "valid": False,
            "message": "Signature is invalid, or the message was modified."
        }
@app.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            "SELECT id FROM users WHERE email = ?",
            (data.email,)
        )
        user = cursor.fetchone()

        # Use a generic response so the API does not reveal
        # whether an email address has an account.
        response = {
            "message": "If the account exists, a reset request can be processed."
        }

        if user is None:
            return response

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        cursor.execute(
            """
            INSERT INTO password_reset_tokens
                (user_id, token_hash, expires_at, used)
            VALUES (?, ?, datetime('now', '+15 minutes'), 0)
            """,
            (user["id"], token_hash)
        )

        connection.commit()

        # Local student-demo only: show the token in the API response.
        # In production, send a reset link to the verified email instead.
        return {
            **response,
            "demo_reset_token": token,
            "demo_warning": "Development demo only. Never expose reset tokens in production."
        }

    finally:
        connection.close()
        
@app.post("/reset-password")
def reset_password(data: ResetPasswordRequest):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        token_hash = hashlib.sha256(
            data.token.encode()
        ).hexdigest()

        cursor.execute(
            """
            SELECT id, user_id
            FROM password_reset_tokens
            WHERE token_hash = ?
              AND used = 0
              AND expires_at > datetime('now')
            """,
            (token_hash,)
        )
        reset_record = cursor.fetchone()

        if reset_record is None:
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired reset token"
            )

        if len(data.new_password) < 8:
            raise HTTPException(
                status_code=400,
                detail="Password must contain at least 8 characters"
            )

        new_password_hash = password_hasher.hash(
            data.new_password
        )

        cursor.execute(
            """
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
            """,
            (new_password_hash, reset_record["user_id"])
        )

        cursor.execute(
            """
            UPDATE password_reset_tokens
            SET used = 1
            WHERE id = ?
            """,
            (reset_record["id"],)
        )

        connection.commit()

        return {
            "message": "Password reset successful. Please sign in with your new password."
        }

    finally:
        connection.close()
        # =========================================================
# LIST USERS FOR MESSAGING
# =========================================================

@app.get("/users")
def list_users(
    current_user: dict = Depends(get_current_user)
):
    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id, username
            FROM users
            WHERE id != ?
            ORDER BY username
            """,
            (current_user["user_id"],)
        )

        users = cursor.fetchall()

        return {
            "users": [
                {
                    "id": user["id"],
                    "username": user["username"]
                }
                for user in users
            ]
        }

    finally:
        connection.close()
        # =========================================================
# SEND ENCRYPTED MESSAGE
# =========================================================

@app.post("/messages/send")
def send_message(
    data: SendMessageRequest,
    current_user: dict = Depends(get_current_user)
):
    if not data.ciphertext.strip():
        raise HTTPException(
            status_code=400,
            detail="Cipher text cannot be empty"
        )

    connection = get_connection()

    try:
        cursor = connection.cursor()

        # Find the recipient
        cursor.execute(
            "SELECT id FROM users WHERE username = ?",
            (data.recipient_username,)
        )
        recipient = cursor.fetchone()

        if recipient is None:
            raise HTTPException(
                status_code=404,
                detail="Recipient username not found"
            )

        if recipient["id"] == current_user["user_id"]:
            raise HTTPException(
                status_code=400,
                detail="You cannot send a message to yourself"
            )

        # Store the encrypted message
        cursor.execute(
            """
            INSERT INTO messages
                (sender_id, recipient_id, ciphertext, signature)
            VALUES (?, ?, ?, ?)
            """,
            (
                current_user["user_id"],
                recipient["id"],
                data.ciphertext,
                data.signature
            )
        )

        connection.commit()

        return {
            "message": "Encrypted message sent successfully",
            "recipient": data.recipient_username
        }

    finally:
        connection.close()
        # =========================================================
# RECEIVE MESSAGES
# =========================================================

@app.get("/messages/inbox")
def receive_messages(
    current_user: dict = Depends(get_current_user)
):
    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                messages.id,
                sender.username AS sender_username,
                messages.ciphertext,
                messages.signature,
                messages.created_at
            FROM messages
            JOIN users AS sender
                ON messages.sender_id = sender.id
            WHERE messages.recipient_id = ?
            ORDER BY messages.created_at DESC
            """,
            (current_user["user_id"],)
        )

        rows = cursor.fetchall()

        return {
            "messages": [
                {
                    "id": row["id"],
                    "sender": row["sender_username"],
                    "ciphertext": row["ciphertext"],
                    "signature": row["signature"],
                    "created_at": row["created_at"]
                }
                for row in rows
            ]
        }

    finally:
        connection.close()