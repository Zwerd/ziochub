"""
Auth helpers: password hashing, user lookup, login/logout.
"""
from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(password: str) -> str:
    return generate_password_hash(password, method='scrypt')


def verify_password(password_hash: str | None, password: str) -> bool:
    if not password_hash:
        return False
    return check_password_hash(password_hash, password)
