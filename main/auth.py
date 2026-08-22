import os
import bcrypt
import hashlib
import base64
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from typing import Optional

from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from database.crud import get_user

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
EXPIRE_MIN = int(os.getenv("JWT_EXPIRE_MIN"))
TZ = ZoneInfo("Asia/Bangkok")


def _prepare_password(password: str) -> bytes:
    digest = hashlib.sha256(password.encode()).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prepare_password(password), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(_prepare_password(plain), hashed.encode())


def create_access_token(data: dict) -> str:
    payload = {**data, "exp": datetime.now(TZ) + timedelta(minutes=EXPIRE_MIN)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get("sub"):
            return None
        return payload
    except JWTError:
        return None


async def authenticate_user_db(db: AsyncSession, username: str, password: str):
    user = await get_user(db, username)
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user
