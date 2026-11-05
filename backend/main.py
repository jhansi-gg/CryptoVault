
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
class MessageDecryptionRequest(BaseModel):
    secret_key: str
from database import get_connection, init_db
import mimetypes
from cryptography.exceptions import InvalidTag

app = FastAPI(title="CryptoVault Secure Communication")

app.add_middleware(
    CORSMiddleware,
   allow_origins=[
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "https://cryptovault-frontend-7uuo.vercel.app",
    "https://cryptovault-frontend-h965.vercel.app",
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
class MessageDecryptionRequest(BaseModel):
     secret_key: str


class SendMessageRequest(BaseModel):
    recipient_username: str
    ciphertext: str
    signature: str = ""
class ShareFileRequest(BaseModel):
    recipient_username: str

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

# -------------------- PERSISTENT DIGITAL SIGNING KEYS --------------------

def get_signing_encryption_key() -> bytes:
    secret = os.getenv("SIGNING_KEY_ENCRYPTION_SECRET")

    if not secret:
        raise RuntimeError(
            "SIGNING_KEY_ENCRYPTION_SECRET is not configured."
        )

    return hashlib.sha256(secret.encode("utf-8")).digest()


def get_or_create_signing_keys(user_id: int):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT signing_public_key,
                       signing_private_key_encrypted
                FROM users
                WHERE id = %s
                FOR UPDATE
                """,
                (user_id,),
            )

            user = cursor.fetchone()

            if not user:
                raise HTTPException(
                    status_code=404,
                    detail="User not found.",
                )

            # Reuse the user's existing key pair.
            if (
                user["signing_public_key"]
                and user["signing_private_key_encrypted"]
            ):
                public_key_pem = user["signing_public_key"]
                encrypted_private_key = bytes(
                    user["signing_private_key_encrypted"]
                )

            else:
                # Generate a persistent RSA key pair.
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )

                public_key = private_key.public_key()

                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                public_key_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")

                # Encrypt the private key before storing it.
                nonce = secrets.token_bytes(12)

                encrypted_private_key = nonce + AESGCM(
                    get_signing_encryption_key()
                ).encrypt(
                    nonce,
                    private_key_pem,
                    None,
                )

                cursor.execute(
                    """
                    UPDATE users
                    SET signing_public_key = %s,
                        signing_private_key_encrypted = %s
                    WHERE id = %s
                    """,
                    (
                        public_key_pem,
                        encrypted_private_key,
                        user_id,
                    ),
                )
                
                
                connection.commit()

        return public_key_pem, encrypted_private_key

    finally:
        connection.close()


def sign_with_user_key(user_id: int, message: str):
    public_key_pem, encrypted_private_key = (
        get_or_create_signing_keys(user_id)
    )

    try:
        nonce = encrypted_private_key[:12]
        encrypted_data = encrypted_private_key[12:]

        private_key_pem = AESGCM(
            get_signing_encryption_key()
        ).decrypt(
            nonce,
            encrypted_data,
            None,
        )

        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
        )

        signature = private_key.sign(
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return (
            base64.b64encode(signature).decode("utf-8"),
            public_key_pem,
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not create the digital signature.",
        )


def verify_message_signature(
    message: str,
    signature: str,
    public_key_pem: str,
) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )

        signature_bytes = base64.b64decode(
            signature,
            validate=True,
        )

        public_key.verify(
            signature_bytes,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return True

    except Exception:
        return False


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
# -------------------- FILE ENCRYPTION --------------------

@app.post("/files/encrypt")
def encrypt_file(
    file: UploadFile = File(...),
    secret_key: str = Form(...),
    current_user=Depends(get_current_user),
):
    allowed_types = {
        ".pdf": "application/pdf",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".txt": "text/plain",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }

    filename = os.path.basename(file.filename or "file")
    extension = os.path.splitext(filename)[1].lower()

    if extension not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Only PDF, PNG, JPG, TXT, and DOCX files are supported.",
        )

    file_data = file.file.read()

    if not file_data:
        raise HTTPException(status_code=400, detail="File is empty.")

    if len(file_data) > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="Maximum file size is 10 MB.",
        )

    nonce = secrets.token_bytes(12)
    key = create_aes_key(secret_key)
    encrypted_data = AESGCM(key).encrypt(nonce, file_data, None)
    file_hash = hashlib.sha256(file_data).hexdigest()
    content_type = allowed_types[extension]

    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO encrypted_files (
                    user_id, original_filename, content_type,
                    encrypted_data, encryption_iv, file_hash
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    current_user["user_id"],
                    filename,
                    content_type,
                    encrypted_data,
                    nonce,
                    file_hash,
                ),
            )
            saved_file = cursor.fetchone()

        connection.commit()

        return {
            "message": "File encrypted and saved successfully!",
            "file_id": saved_file["id"],
            "filename": filename,
            "encrypted_size_bytes": len(encrypted_data),
        }

    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not save the encrypted file.",
        )

    finally:
        connection.close()
        file.file.close()

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


# -------------------- SEND SIGNED MESSAGE --------------------

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

    # Automatically sign the encrypted message.
    signature, public_key_pem = sign_with_user_key(
        current_user["user_id"],
        data.ciphertext,
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
                INSERT INTO messages (
                    sender_id,
                    recipient_id,
                    ciphertext,
                    signature,
                    sender_public_key
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    current_user["user_id"],
                    recipient["id"],
                    data.ciphertext,
                    signature,
                    public_key_pem,
                ),
            )

        connection.commit()

        return {
            "message": "Encrypted and digitally signed message sent successfully!",
            "recipient": data.recipient_username,
            "signature": signature,
            "sender_public_key": public_key_pem,
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not send the signed message.",
        )

    finally:
        connection.close()

        # -------------------- DOWNLOAD ENCRYPTED FILE --------------------

@app.get("/files/{file_id}/download")
def download_encrypted_file(
    file_id: int,
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT original_filename, encrypted_data
                FROM encrypted_files
                WHERE id = %s AND user_id = %s
                """,
                (file_id, current_user["user_id"]),
            )
            saved_file = cursor.fetchone()

        if not saved_file:
            raise HTTPException(
                status_code=404,
                detail="File not found.",
            )

        return Response(
            content=bytes(saved_file["encrypted_data"]),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="encrypted_{os.path.basename(saved_file["original_filename"])}"'
                )
            },
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
                    messages.sender_public_key,
                    messages.created_at
                FROM messages
                JOIN users AS sender
                    ON messages.sender_id = sender.id
                WHERE messages.recipient_id = %s
                  AND messages.recipient_deleted_at IS NULL
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
                    "sender_public_key": message["sender_public_key"],
                    "created_at": message["created_at"],
                    "signature_valid": verify_message_signature(
                        message["ciphertext"],
                        message["signature"] or "",
                        message["sender_public_key"] or "",
                    ),
                }
                for message in messages
            ]
        }

    finally:
        connection.close()

# -------------------- SENT MESSAGES --------------------

@app.get("/messages/sent")
def get_sent_messages(
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    messages.id,
                    recipient.username AS recipient_username,
                    messages.ciphertext,
                    messages.signature,
                    messages.sender_public_key,
                    messages.created_at
                FROM messages
                JOIN users AS recipient
                    ON messages.recipient_id = recipient.id
                WHERE messages.sender_id = %s
                  AND messages.sender_deleted_at IS NULL
                ORDER BY messages.created_at DESC
                """,
                (current_user["user_id"],),
            )

            messages = cursor.fetchall()

        return {"messages": messages}

    finally:
        connection.close()

        
# -------------------- CLEAR ALL MESSAGES --------------------

@app.delete("/messages/clear-all")
def clear_all_messages(
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:

            # Clear received messages from this user's account
            cursor.execute(
                """
                UPDATE messages
                SET recipient_deleted_at = CURRENT_TIMESTAMP
                WHERE recipient_id = %s
                  AND recipient_deleted_at IS NULL
                """,
                (current_user["user_id"],),
            )
            received_count = cursor.rowcount

            # Clear sent messages from this user's account
            cursor.execute(
                """
                UPDATE messages
                SET sender_deleted_at = CURRENT_TIMESTAMP
                WHERE sender_id = %s
                  AND sender_deleted_at IS NULL
                """,
                (current_user["user_id"],),
            )
            sent_count = cursor.rowcount

        connection.commit()

        return {
            "message": "All messages cleared from your account.",
            "received_messages_deleted": received_count,
            "sent_messages_deleted": sent_count,
        }

    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not clear messages.",
        )

    finally:
        connection.close()

# -------------------- DELETE MESSAGE --------------------

@app.delete("/messages/{message_id}")
def delete_message(
    message_id: int,
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:

            # First, try deleting the message from the recipient's account.
            cursor.execute(
                """
                UPDATE messages
                SET recipient_deleted_at = CURRENT_TIMESTAMP
                WHERE id = %s
                  AND recipient_id = %s
                  AND recipient_deleted_at IS NULL
                """,
                (message_id, current_user["user_id"]),
            )

            deleted = cursor.rowcount

            # If not found as a received message, try the sender's account.
            if deleted == 0:
                cursor.execute(
                    """
                    UPDATE messages
                    SET sender_deleted_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                      AND sender_id = %s
                      AND sender_deleted_at IS NULL
                    """,
                    (message_id, current_user["user_id"]),
                )

                deleted = cursor.rowcount

        connection.commit()

        if deleted == 0:
            raise HTTPException(
                status_code=404,
                detail="Message not found or already deleted.",
            )

        return {
            "message": "Message deleted from your account successfully!"
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not delete the message.",
        )

    finally:
        connection.close()


# -------------------- DECRYPT INBOX MESSAGE --------------------

@app.post("/messages/{message_id}/decrypt")
def decrypt_inbox_message(
    message_id: int,
    data: MessageDecryptionRequest,
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    messages.id,
                    messages.ciphertext,
                    messages.signature,
                    messages.sender_public_key,
                    sender.username AS sender_username
                FROM messages
                JOIN users AS sender
                    ON messages.sender_id = sender.id
                WHERE messages.id = %s
                  AND messages.recipient_id = %s
                """,
                (message_id, current_user["user_id"]),
            )

            message = cursor.fetchone()

        if not message:
            raise HTTPException(
                status_code=404,
                detail="Message not found or access denied.",
            )

        # Verify the sender's digital signature first.
        signature_valid = verify_message_signature(
            message["ciphertext"],
            message["signature"] or "",
            message["sender_public_key"] or "",
        )

        if not signature_valid:
            raise HTTPException(
                status_code=400,
                detail="Digital signature verification failed. Message cannot be trusted.",
            )

        # Decode the encrypted message.
        raw_data = base64.b64decode(
            message["ciphertext"],
            validate=True,
        )

        if len(raw_data) < 29:
            raise HTTPException(
                status_code=400,
                detail="Invalid encrypted message.",
            )

        nonce = raw_data[:12]
        encrypted_data = raw_data[12:]

        # Generate the same AES key used by the sender.
        key = create_aes_key(data.secret_key)

        # Decrypt the message.
        try:
            plaintext = AESGCM(key).decrypt(
                nonce,
                encrypted_data,
                None,
            ).decode("utf-8")

        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Decryption failed. Check the original sender's secret key.",
            )

        return {
            "message": "Message decrypted successfully!",
            "message_id": message["id"],
            "sender_username": message["sender_username"],
            "plaintext": plaintext,
            "signature_valid": True,
        }

    finally:
        connection.close()




        # -------------------- DECRYPT SAVED FILE --------------------

@app.post("/files/{file_id}/decrypt")
def decrypt_saved_file(
    file_id: int,
    secret_key: str = Form(...),
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT original_filename, content_type,
                       encrypted_data, encryption_iv, file_hash
                FROM encrypted_files
                WHERE id = %s AND user_id = %s
                """,
                (file_id, current_user["user_id"]),
            )
            saved_file = cursor.fetchone()

        if not saved_file:
            raise HTTPException(
                status_code=404,
                detail="File not found.",
            )

        key = create_aes_key(secret_key)

        try:
            original_data = AESGCM(key).decrypt(
                bytes(saved_file["encryption_iv"]),
                bytes(saved_file["encrypted_data"]),
                None,
            )
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Decryption failed. Check your secret key.",
            )

        actual_hash = hashlib.sha256(original_data).hexdigest()

        if not secrets.compare_digest(
            actual_hash, saved_file["file_hash"]
        ):
            raise HTTPException(
                status_code=400,
                detail="File integrity verification failed.",
            )

        return Response(
            content=original_data,
            media_type=saved_file["content_type"],
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{os.path.basename(saved_file["original_filename"])}"'
                ),
                "X-Integrity-Verified": "true",
            },
        )

    finally:
        connection.close()
        
# -------------------- SHARE ENCRYPTED FILE --------------------

@app.post("/files/{file_id}/share")
def share_encrypted_file(
    file_id: int,
    data: ShareFileRequest,
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:

            # Check whether the file belongs to the logged-in user
            cursor.execute(
                """
                SELECT id, original_filename
                FROM encrypted_files
                WHERE id = %s AND user_id = %s
                """,
                (file_id, current_user["user_id"]),
            )
            saved_file = cursor.fetchone()

            if not saved_file:
                raise HTTPException(
                    status_code=404,
                    detail="File not found or you do not own this file.",
                )

            # Find the registered recipient
            cursor.execute(
                """
                SELECT id, username
                FROM users
                WHERE username = %s
                """,
                (data.recipient_username,),
            )
            recipient = cursor.fetchone()

            if not recipient:
                raise HTTPException(
                    status_code=404,
                    detail="Recipient username not found.",
                )

            # Prevent sharing with yourself
            if recipient["id"] == current_user["user_id"]:
                raise HTTPException(
                    status_code=400,
                    detail="You cannot share a file with yourself.",
                )

            # Create the sharing permission
            cursor.execute(
                """
                INSERT INTO file_shares
                    (file_id, sender_id, recipient_id)
                VALUES (%s, %s, %s)
                """,
                (
                    file_id,
                    current_user["user_id"],
                    recipient["id"],
                ),
            )

        connection.commit()

        return {
            "message": "Encrypted file shared successfully!",
            "file_id": file_id,
            "filename": saved_file["original_filename"],
            "shared_with": recipient["username"],
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception as error:
        connection.rollback()

        if getattr(error, "sqlstate", None) == "23505":
            raise HTTPException(
                status_code=409,
                detail="This file has already been shared with this user.",
            )

        raise HTTPException(
            status_code=500,
            detail="Could not share the file.",
        )

    finally:
        connection.close()


# -------------------- SHARED WITH ME --------------------

@app.get("/files/shared-with-me")
def get_shared_files(
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    f.id,
                    f.original_filename,
                    f.content_type,
                    octet_length(f.encrypted_data) AS encrypted_size,
                    f.created_at,
                    sender.username AS shared_by,
                    fs.shared_at
                FROM file_shares AS fs
                JOIN encrypted_files AS f
                    ON fs.file_id = f.id
                JOIN users AS sender
                    ON fs.sender_id = sender.id
                WHERE fs.recipient_id = %s
                ORDER BY fs.shared_at DESC
                """,
                (current_user["user_id"],),
            )

            files = cursor.fetchall()

        return {"shared_files": files}
    finally:
            connection.close()


# -------------------- DECRYPT SAVED FILE --------------------
@app.get("/files/shared-with-me/{file_id}/download")
def download_shared_file(
    file_id: int,
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    f.original_filename,
                    f.encrypted_data
                FROM file_shares AS fs
                JOIN encrypted_files AS f
                    ON fs.file_id = f.id
                WHERE fs.file_id = %s
                  AND fs.recipient_id = %s
                """,
                (file_id, current_user["user_id"]),
            )

            shared_file = cursor.fetchone()

        if not shared_file:
            raise HTTPException(
                status_code=404,
                detail="Shared file not found or access denied.",
            )

        return Response(
            content=bytes(shared_file["encrypted_data"]),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": (
                    'attachment; filename="encrypted_'
                    + os.path.basename(shared_file["original_filename"])
                    + '"'
                )
            },
        )

    finally:
        connection.close()
        
# -------------------- MY UPLOADED FILES --------------------

@app.get("/files/my-files")
def get_my_files(
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    original_filename,
                    content_type,
                    created_at,
                    OCTET_LENGTH(encrypted_data) AS encrypted_size
                FROM encrypted_files
                WHERE user_id = %s
                ORDER BY created_at DESC
                """,
                (current_user["user_id"],),
            )

            files = cursor.fetchall()

        return {"files": files}

    finally:
        connection.close()


# -------------------- DELETE UPLOADED FILE --------------------

@app.delete("/files/{file_id}")
def delete_uploaded_file(
    file_id: int,
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM encrypted_files
                WHERE id = %s
                  AND user_id = %s
                """,
                (file_id, current_user["user_id"]),
            )

            deleted = cursor.rowcount

        connection.commit()

        if deleted == 0:
            raise HTTPException(
                status_code=404,
                detail="File not found or you do not own this file.",
            )

        return {
            "message": "File deleted successfully!"
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not delete the file.",
        )

    finally:
        connection.close()

# -------------------- DECRYPT SHARED FILE --------------------

@app.post("/files/shared-with-me/{file_id}/decrypt")
def decrypt_shared_file(
    file_id: int,
    secret_key: str = Form(...),
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    f.original_filename,
                    f.content_type,
                    f.encrypted_data,
                    f.encryption_iv,
                    f.file_hash
                FROM file_shares AS fs
                JOIN encrypted_files AS f
                    ON fs.file_id = f.id
                WHERE fs.file_id = %s
                  AND fs.recipient_id = %s
                """,
                (file_id, current_user["user_id"]),
            )

            shared_file = cursor.fetchone()

        if not shared_file:
            raise HTTPException(
                status_code=404,
                detail="Shared file not found or access denied.",
            )

        # Generate the AES key using the original secret key
        key = create_aes_key(secret_key)

        try:
            original_data = AESGCM(key).decrypt(
                bytes(shared_file["encryption_iv"]),
                bytes(shared_file["encrypted_data"]),
                None,
            )

        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Decryption failed. Check the original secret key.",
            )

        # Verify file integrity
        actual_hash = hashlib.sha256(original_data).hexdigest()

        if not secrets.compare_digest(
            actual_hash,
            shared_file["file_hash"],
        ):
            raise HTTPException(
                status_code=400,
                detail="File integrity verification failed.",
            )

        return Response(
            content=original_data,
            media_type=shared_file["content_type"],
            headers={
                "Content-Disposition": (
                    'attachment; filename="'
                    + os.path.basename(
                        shared_file["original_filename"]
                    )
                    + '"'
                ),
                "X-Integrity-Verified": "true",
            },
        )

    finally:
        connection.close()

# -------------------- REMOVE SHARED FILE --------------------

@app.delete("/files/shared-with-me/{file_id}")
def remove_shared_file(
    file_id: int,
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM file_shares
                WHERE file_id = %s
                  AND recipient_id = %s
                """,
                (file_id, current_user["user_id"]),
            )

            deleted = cursor.rowcount

        connection.commit()

        if deleted == 0:
            raise HTTPException(
                status_code=404,
                detail="Shared file not found in your account.",
            )

        return {
            "message": "Shared file removed from your account successfully!"
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not remove shared file.",
        )

    finally:
        connection.close()

# -------------------- CLEAR ALL FILES --------------------

@app.delete("/files/clear-all")
def clear_all_files(
    current_user=Depends(get_current_user),
):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:

            # Remove files shared with this user
            cursor.execute(
                """
                DELETE FROM file_shares
                WHERE recipient_id = %s
                """,
                (current_user["user_id"],),
            )
            shared_count = cursor.rowcount

            # Delete files uploaded by this user
            cursor.execute(
                """
                DELETE FROM encrypted_files
                WHERE user_id = %s
                """,
                (current_user["user_id"],),
            )
            uploaded_count = cursor.rowcount

        connection.commit()

        return {
            "message": "All files cleared from your account.",
            "uploaded_files_deleted": uploaded_count,
            "shared_files_removed": shared_count,
        }

    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not clear files.",
        )

    finally:
        connection.close()
