
import os
import sqlite3
from pathlib import Path

# Use an absolute path based on this file's location.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_NAME = os.getenv(
    "DATABASE_PATH",
    str(PROJECT_ROOT / "database" / "crypto_pro.db")
)

# Ensure the directory containing the database exists.
Path(DATABASE_NAME).parent.mkdir(parents=True, exist_ok=True)


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

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


if __name__ == "__main__":
    init_db()
    print("Database and tables created successfully!")
