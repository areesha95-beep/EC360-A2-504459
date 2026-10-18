import hashlib
import os


def hash_password(password: str, salt: bytes = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex() + ":" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split(":")
    salt = bytes.fromhex(salt_hex)
    return hash_password(password, salt) == stored


def register_user(users: dict, email: str, password: str) -> dict:
    if len(password) < 12:
        return {"status": 400, "error": "Password too short"}
    if email in users:
        return {"status": 409, "error": "An account with this email already exists"}
    users[email] = {"password": hash_password(password), "verified": False}
    return {"status": 201, "payload": "pending_verification"}