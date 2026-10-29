
import os
import base64
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from database import get_connection, init_db


app = FastAPI(title="CryptoVault Secure Communication")

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

password_hasher = PasswordHasher()
SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not configured in the environment.")

ALGORITHM = "HS256"
security = HTTPBearer()


# -------------------- REQUEST MODELS --------------------

class SignupRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


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


# -------------------- DATABASE INITIALIZATION --------------------

init_db()


# -------------------- HOME --------------------

@app.get("/")
def home():
    return {"message": "CryptoVault Secure Communication Backend is running!"}


# -------------------- SIGNUP --------------------

@app.post("/signup")
def signup(user: SignupRequest):
    password_hash = password_hasher.hash(user.password)
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (%s, %s, %s)
                """,
                (user.username, user.email, password_hash),
            )

        connection.commit()

        return {
            "message": "Account created successfully!",
            "username": user.username,
            "email": user.email,
        }

    except Exception as error:
        connection.rollback()

        # Do not expose database internals to clients.
        error_code = getattr(error, "sqlstate", None)

        if error_code == "23505":
            raise HTTPException(
                status_code=409,
                detail="Username or email already exists.",
            )

        raise HTTPException(
            status_code=400,
            detail="Account creation failed. Check the supplied details.",
        )

    finally:
        connection.close()


# -------------------- LOGIN --------------------

@app.post("/login")
def login(user: LoginRequest):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE username = %s",
                (user.username,),
            )
            existing_user = cursor.fetchone()

        if not existing_user:
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password.",
            )

        try:
            password_hasher.verify(
                existing_user["password_hash"],
                user.password,
            )
        except Exception:
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password.",
            )

        token_data = {
            "user_id": existing_user["id"],
            "username": existing_user["username"],
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        }

        access_token = jwt.encode(
            token_data,
            SECRET_KEY,
            algorithm=ALGORITHM,
        )

        return {
            "message": "Login successful!",
            "access_token": access_token,
            "token_type": "bearer",
            "username": existing_user["username"],
            "email": existing_user["email"],
        }

    finally:
        connection.close()


# -------------------- AUTHENTICATION --------------------

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        user_id = payload.get("user_id")
        username = payload.get("username")

        if user_id is None or username is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token.",
            )

        return {
            "user_id": user_id,
            "username": username,
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Session expired. Please log in again.",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token.",
        )


@app.get("/me")
def get_me(current_user=Depends(get_current_user)):
    return {
        "id": current_user["user_id"],
        "username": current_user["username"],
    }


# -------------------- ENCRYPTION --------------------

def create_aes_key(secret_key: str) -> bytes:
    return hashlib.sha256(secret_key.encode("utf-8")).digest()


@app.post("/encrypt")
def encrypt_message(data: EncryptionRequest):
    key = create_aes_key(data.secret_key)
    nonce = secrets.token_bytes(12)
    aes = AESGCM(key)

    encrypted_data = aes.encrypt(
        nonce,
        data.plaintext.encode("utf-8"),
        None,
    )

    ciphertext = base64.b64encode(
        nonce + encrypted_data
    ).decode("utf-8")

    return {
        "message": "Encryption successful!",
        "ciphertext": ciphertext,
    }


@app.post("/decrypt")
def decrypt_message(data: DecryptionRequest):
    try:
        raw_data = base64.b64decode(
            data.ciphertext,
            validate=True,
        )

        if len(raw_data) < 29:
            raise ValueError("Invalid ciphertext.")

        nonce = raw_data[:12]
        encrypted_data = raw_data[12:]

        key = create_aes_key(data.secret_key)
        aes = AESGCM(key)

        plaintext = aes.decrypt(
            nonce,
            encrypted_data,
            None,
        ).decode("utf-8")

        return {
            "message": "Decryption successful!",
            "plaintext": plaintext,
        }

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Decryption failed. Check the ciphertext and secret key.",
        )


# -------------------- DIGITAL SIGNATURES --------------------

@app.post("/signature/sign")
def sign_message(
    data: SignatureRequest,
    current_user=Depends(get_current_user),
):
    # Demonstration-only key pair.
    # A production application should securely store and reuse private keys.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    signature = private_key.sign(
        data.message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return {
        "message": "Digital signature created successfully!",
        "signature": base64.b64encode(signature).decode("utf-8"),
        "public_key": public_key_pem,
    }


@app.post("/signature/verify")
def verify_signature(
    data: VerifySignatureRequest,
    current_user=Depends(get_current_user),
):
    try:
        public_key = serialization.load_pem_public_key(
            data.public_key.encode("utf-8")
        )

        signature_bytes = base64.b64decode(
            data.signature,
            validate=True,
        )

        public_key.verify(
            signature_bytes,
            data.message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return {
            "valid": True,
            "message": "Signature is valid.",
        }

    except Exception:
        return {
            "valid": False,
            "message": "Signature verification failed.",
        }


# -------------------- FORGOT PASSWORD --------------------

@app.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM users WHERE email = %s",
                (data.email,),
            )
            user = cursor.fetchone()

            # Use the same public response whether the email exists or not.
            if not user:
                return {
                    "message": (
                        "If the account exists, password reset instructions "
                        "will be provided."
                    )
                }

            reset_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(
                reset_token.encode("utf-8")
            ).hexdigest()

            cursor.execute(
                """
                INSERT INTO password_reset_tokens
                    (user_id, token_hash, expires_at, used)
                VALUES (
                    %s, %s,
                    CURRENT_TIMESTAMP + INTERVAL '15 minutes',
                    0
                )
                """,
                (user["id"], token_hash),
            )

        connection.commit()

        # Demo only: production should email the token using a secure
        # email provider and should not return the token in the API response.
        return {
            "message": "Demo reset token created. It expires in 15 minutes.",
            "demo_reset_token": reset_token,
        }

    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not create a password reset token.",
        )

    finally:
        connection.close()


# -------------------- RESET PASSWORD --------------------

@app.post("/reset-password")
def reset_password(data: ResetPasswordRequest):
    if len(data.new_password) < 8:
        raise HTTPException(
            status_code=400,
            detail="New password must contain at least 8 characters.",
        )

    token_hash = hashlib.sha256(
        data.token.encode("utf-8")
    ).hexdigest()

    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, user_id
                FROM password_reset_tokens
                WHERE token_hash = %s
                  AND used = 0
                  AND expires_at > CURRENT_TIMESTAMP
                """,
                (token_hash,),
            )
            reset_record = cursor.fetchone()

            if not reset_record:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid, expired, or already-used reset token.",
                )

            new_password_hash = password_hasher.hash(
                data.new_password
            )

            cursor.execute(
                """
                UPDATE users
                SET password_hash = %s
                WHERE id = %s
                """,
                (new_password_hash, reset_record["user_id"]),
            )

            cursor.execute(
                """
                UPDATE password_reset_tokens
                SET used = 1
                WHERE id = %s
                """,
                (reset_record["id"],),
            )

        connection.commit()

        return {
            "message": "Password reset successful. Please log in again."
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not reset the password.",
        )

    finally:
        connection.close()


# -------------------- LIST USERS --------------------

@app.get("/users")
def get_users(current_user=Depends(get_current_user)):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username
                FROM users
                WHERE id != %s
                ORDER BY username
                """,
                (current_user["user_id"],),
            )
            users = cursor.fetchall()

        return {
            "users": [
                {
                    "id": user["id"],
                    "username": user["username"],
                }
                for user in users
            ]
        }

    finally:
        connection.close()


# -------------------- SEND MESSAGE --------------------

@app.post("/messages/send")
def send_message(
    data: SendMessageRequest,
    current_user=Depends(get_current_user),
):
    if not data.ciphertext.strip():
        raise HTTPException(
            status_code=400,
            detail="Ciphertext cannot be empty.",
        )

    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM users WHERE username = %s",
                (data.recipient_username,),
            )
            recipient = cursor.fetchone()

            if not recipient:
                raise HTTPException(
                    status_code=404,
                    detail="Recipient not found.",
                )

            if recipient["id"] == current_user["user_id"]:
                raise HTTPException(
                    status_code=400,
                    detail="You cannot send a message to yourself.",
                )

            cursor.execute(
                """
                INSERT INTO messages
                    (sender_id, recipient_id, ciphertext, signature)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    current_user["user_id"],
                    recipient["id"],
                    data.ciphertext,
                    data.signature,
                ),
            )

        connection.commit()

        return {
            "message": "Encrypted message sent successfully!",
            "recipient": data.recipient_username,
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not send the message.",
        )

    finally:
        connection.close()


# -------------------- MESSAGE INBOX --------------------

@app.get("/messages/inbox")
def get_inbox(current_user=Depends(get_current_user)):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
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
                WHERE messages.recipient_id = %s
                ORDER BY messages.created_at DESC
                """,
                (current_user["user_id"],),
            )
            messages = cursor.fetchall()

        return {
            "messages": [
                {
                    "id": message["id"],
                    "sender_username": message["sender_username"],
                    "ciphertext": message["ciphertext"],
                    "signature": message["signature"],
                    "created_at": message["created_at"],
                }
                for message in messages
            ]
        }

    finally:
        connection.close()
@app.get("/debug/database")
def debug_database():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    current_database() AS database_name,
                    current_schema() AS schema_name,
                    to_regclass('public.users') AS users_table,
                    (SELECT COUNT(*) FROM public.users) AS user_count
            """)
            return cursor.fetchone()