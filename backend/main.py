"""
wapChat — backend в одном файле.

Разделы:
  1. Настройки и база данных (SQLite)
  2. Пароли и сессии
  3. Ограничение частоты запросов
  4. Загрузка изображений
  5. Приложение FastAPI и схемы запросов
  6. Вспомогательные функции
  7. Маршруты: авторизация, пользователи, публикации, комментарии
  8. Раздача фронтенда
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

# =============================================================================
# 1. Настройки и база данных
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = Path(os.getenv("SEVEN_DB_PATH", BASE_DIR / "seven.db"))

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

PAGE_SIZE = 20
MAX_IMAGE_BYTES = 8 * 1024 * 1024
ALLOWED_MIME = {"image/jpeg", "image/png", "image/gif", "image/webp"}
USERNAME_RE = re.compile(r"[a-z0-9_]{3,30}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
USER_COLUMNS = "id, username, email, display_name, bio, avatar_url, created_at"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    bio TEXT NOT NULL DEFAULT '',
    avatar_url TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('photo', 'thought')),
    text TEXT NOT NULL DEFAULT '',
    image_url TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS likes (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, post_id)
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def db():
    """Соединение с автоматическим commit и rollback. Все запросы параметризованы."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


# =============================================================================
# 2. Пароли и сессии
# =============================================================================

SESSION_DAYS = 30
PBKDF2_ITERATIONS = 390_000
bearer_scheme = HTTPBearer(auto_error=False)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str) -> str:
    """PBKDF2-SHA256 с уникальной солью. Формат: алгоритм$итерации$соль$хеш."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def _token_hash(token: str) -> str:
    # В базе хранится только хеш токена, сам токен есть только у клиента.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat()
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_now(),))
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (_token_hash(token), user_id, expires_at),
        )
    return token


def delete_session(token: str) -> None:
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Войдите в аккаунт")
    with db() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.email, u.display_name, u.bio, u.avatar_url, u.created_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > ?
            """,
            (_token_hash(credentials.credentials), _now()),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Сессия истекла. Войдите снова")
    return dict(row)


# =============================================================================
# 3. Ограничение частоты запросов (в памяти процесса)
# =============================================================================

class RateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                retry = int(self.window - (now - hits[0])) + 1
                raise HTTPException(
                    status_code=429,
                    detail=f"Слишком много запросов. Попробуйте через {retry} с.",
                    headers={"Retry-After": str(retry)},
                )
            hits.append(now)


auth_limiter = RateLimiter(limit=10, window_seconds=60)   # вход и регистрация
write_limiter = RateLimiter(limit=60, window_seconds=60)  # публикации, лайки, комментарии


def rate_limit(limiter: RateLimiter):
    def dependency(request: Request) -> None:
        limiter.check(request.client.host if request.client else "unknown")

    return dependency


# =============================================================================
# 4. Загрузка изображений
# =============================================================================

def _sniff(head: bytes) -> Optional[str]:
    """Тип файла определяем по сигнатуре, а не по имени или заголовку."""
    if head.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return ".webp"
    return None


async def save_image(file: UploadFile, subdir: str) -> str:
    if file.content_type not in ALLOWED_MIME:
        raise HTTPException(status_code=415, detail="Допустимы только JPG, PNG, GIF и WEBP")

    data = await file.read(MAX_IMAGE_BYTES + 1)
    if not data:
        raise HTTPException(status_code=400, detail="Файл пустой")
    if len(data) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="Файл больше 8 МБ")

    extension = _sniff(data[:16])
    if extension is None:
        raise HTTPException(status_code=415, detail="Файл не похож на изображение")

    target_dir = UPLOAD_DIR / subdir
    target_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{uuid.uuid4().hex}{extension}"
    (target_dir / filename).write_bytes(data)
    return f"/uploads/{subdir}/{filename}"


def remove_upload(url: Optional[str]) -> None:
    """Удаляем только файлы внутри папки загрузок."""
    if not url or not url.startswith("/uploads/"):
        return
    path = (BASE_DIR / url.lstrip("/")).resolve()
    if UPLOAD_DIR.resolve() in path.parents and path.is_file():
        path.unlink(missing_ok=True)


# =============================================================================
# 5. Приложение и схемы запросов
# =============================================================================

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="wapChat", version="1.0.0", lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def check_username(cls, value: str) -> str:
        value = value.strip().lower()
        if not USERNAME_RE.fullmatch(value):
            raise ValueError("Логин: латинские буквы, цифры и _ (от 3 до 30 символов)")
        return value

    @field_validator("email")
    @classmethod
    def check_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not EMAIL_RE.fullmatch(value):
            raise ValueError("Некорректный email")
        return value


class LoginIn(BaseModel):
    login: str = Field(min_length=1, max_length=254)  # логин или email
    password: str = Field(min_length=1, max_length=128)


class ProfileIn(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=50)
    bio: Optional[str] = Field(default=None, max_length=300)


class CommentIn(BaseModel):
    text: str = Field(min_length=1, max_length=500)

    @field_validator("text")
    @classmethod
    def not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Комментарий не может быть пустым")
        return value


# =============================================================================
# 6. Вспомогательные функции
# =============================================================================

def escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def get_user(user_id: int) -> Optional[dict]:
    with db() as conn:
        row = conn.execute(f"SELECT {USER_COLUMNS} FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


POST_SELECT = """
SELECT p.id, p.kind, p.text, p.image_url, p.created_at,
       u.id AS author_id, u.username, u.display_name, u.avatar_url,
       (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS likes_count,
       (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comments_count,
       EXISTS(SELECT 1 FROM likes l WHERE l.post_id = p.id AND l.user_id = ?) AS liked_by_me
FROM posts p
JOIN users u ON u.id = p.user_id
"""

COMMENT_SELECT = """
SELECT c.id, c.text, c.created_at, c.user_id AS author_id,
       u.username, u.display_name, u.avatar_url
FROM comments c
JOIN users u ON u.id = c.user_id
"""


def serialize_post(row, viewer_id: int) -> dict:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "text": row["text"],
        "image_url": row["image_url"],
        "created_at": row["created_at"],
        "author": {
            "id": row["author_id"],
            "username": row["username"],
            "display_name": row["display_name"] or row["username"],
            "avatar_url": row["avatar_url"],
        },
        "likes_count": row["likes_count"],
        "comments_count": row["comments_count"],
        "liked_by_me": bool(row["liked_by_me"]),
        "is_mine": row["author_id"] == viewer_id,
    }


def fetch_posts(viewer_id: int, where_sql: str = "", params: tuple = (),
                before_id: Optional[int] = None, limit: int = PAGE_SIZE) -> list:
    # where_sql пишется только в коде, значения передаются параметрами.
    args: list = [viewer_id]
    conditions = []
    if where_sql:
        conditions.append(where_sql)
        args.extend(params)
    if before_id is not None:
        conditions.append("p.id < ?")
        args.append(before_id)

    sql = POST_SELECT
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY p.id DESC LIMIT ?"
    args.append(limit)

    with db() as conn:
        rows = conn.execute(sql, args).fetchall()
    return [serialize_post(row, viewer_id) for row in rows]


def serialize_comment(row, viewer_id: int) -> dict:
    return {
        "id": row["id"],
        "text": row["text"],
        "created_at": row["created_at"],
        "is_mine": row["author_id"] == viewer_id,
        "author": {
            "id": row["author_id"],
            "username": row["username"],
            "display_name": row["display_name"] or row["username"],
            "avatar_url": row["avatar_url"],
        },
    }


def post_exists(conn: sqlite3.Connection, post_id: int) -> bool:
    return conn.execute("SELECT 1 FROM posts WHERE id = ?", (post_id,)).fetchone() is not None


# =============================================================================
# 7. Маршруты
# =============================================================================

# ---------- авторизация ----------

@app.post("/api/auth/register", status_code=201, dependencies=[Depends(rate_limit(auth_limiter))])
def register(data: RegisterIn):
    try:
        with db() as conn:
            if conn.execute("SELECT 1 FROM users WHERE username = ?", (data.username,)).fetchone():
                raise HTTPException(status_code=409, detail="Этот логин уже занят")
            if conn.execute("SELECT 1 FROM users WHERE email = ?", (data.email,)).fetchone():
                raise HTTPException(status_code=409, detail="Этот email уже зарегистрирован")
            cursor = conn.execute(
                "INSERT INTO users (username, email, password_hash, display_name) VALUES (?, ?, ?, ?)",
                (data.username, data.email, hash_password(data.password), data.username),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Логин или email уже заняты")

    return {"token": create_session(user_id), "user": get_user(user_id)}


@app.post("/api/auth/login", dependencies=[Depends(rate_limit(auth_limiter))])
def login(data: LoginIn):
    identifier = data.login.strip().lower()
    with db() as conn:
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE email = ? OR username = ?",
            (identifier, identifier),
        ).fetchone()
    if row is None or not verify_password(data.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    return {"token": create_session(row["id"]), "user": get_user(row["id"])}


@app.post("/api/auth/logout")
def logout(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    _user: dict = Depends(get_current_user),
):
    delete_session(credentials.credentials)
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: dict = Depends(get_current_user)):
    return user


# ---------- пользователи ----------

@app.get("/api/users/search")
def search_users(q: str = Query(..., min_length=1, max_length=50),
                 _user: dict = Depends(get_current_user)):
    pattern = f"%{escape_like(q.strip())}%"
    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, username, display_name, avatar_url
            FROM users
            WHERE username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\'
            ORDER BY username
            LIMIT 20
            """,
            (pattern, pattern),
        ).fetchall()
    return [dict(row) for row in rows]


@app.patch("/api/users/me", dependencies=[Depends(rate_limit(write_limiter))])
def update_me(data: ProfileIn, user: dict = Depends(get_current_user)):
    # Имена колонок заданы в коде, значения передаются параметрами.
    fields, values = [], []
    if data.display_name is not None:
        fields.append("display_name = ?")
        values.append(data.display_name.strip() or user["username"])
    if data.bio is not None:
        fields.append("bio = ?")
        values.append(data.bio.strip())
    if fields:
        with db() as conn:
            conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", (*values, user["id"]))
    return get_user(user["id"])


@app.post("/api/users/me/avatar", dependencies=[Depends(rate_limit(write_limiter))])
async def upload_avatar(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    url = await save_image(file, "avatars")
    with db() as conn:
        old = conn.execute("SELECT avatar_url FROM users WHERE id = ?", (user["id"],)).fetchone()
        conn.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (url, user["id"]))
    remove_upload(old["avatar_url"] if old else None)
    return get_user(user["id"])


@app.get("/api/users/{username}")
def get_profile(username: str, user: dict = Depends(get_current_user)):
    with db() as conn:
        row = conn.execute(
            "SELECT id, username, display_name, bio, avatar_url, created_at FROM users WHERE username = ?",
            (username.lower(),),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        posts_count = conn.execute(
            "SELECT COUNT(*) FROM posts WHERE user_id = ?", (row["id"],)
        ).fetchone()[0]
    profile = dict(row)
    profile["posts_count"] = posts_count
    profile["is_me"] = row["id"] == user["id"]
    return profile


@app.get("/api/users/{username}/posts")
def user_posts(username: str, before: Optional[int] = Query(None, ge=1),
               user: dict = Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT id FROM users WHERE username = ?", (username.lower(),)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return fetch_posts(user["id"], "p.user_id = ?", (row["id"],), before_id=before)


# ---------- публикации ----------

@app.get("/api/posts")
def feed(
    before: Optional[int] = Query(None, ge=1),
    kind: Optional[Literal["photo", "thought"]] = None,
    user: dict = Depends(get_current_user),
):
    if kind:
        return fetch_posts(user["id"], "p.kind = ?", (kind,), before_id=before)
    return fetch_posts(user["id"], before_id=before)


@app.post("/api/posts", status_code=201, dependencies=[Depends(rate_limit(write_limiter))])
async def create_post(
    kind: Literal["photo", "thought"] = Form(...),
    text: str = Form(""),
    image: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user),
):
    text = text.strip()
    if len(text) > 1000:
        raise HTTPException(status_code=400, detail="Текст не длиннее 1000 символов")
    if kind == "thought" and not text:
        raise HTTPException(status_code=400, detail="Напишите мысль")
    if kind == "photo" and (image is None or not image.filename):
        raise HTTPException(status_code=400, detail="Выберите фото")

    image_url = await save_image(image, "posts") if kind == "photo" else None
    with db() as conn:
        cursor = conn.execute(
            "INSERT INTO posts (user_id, kind, text, image_url) VALUES (?, ?, ?, ?)",
            (user["id"], kind, text, image_url),
        )
        post_id = cursor.lastrowid
    return fetch_posts(user["id"], "p.id = ?", (post_id,), limit=1)[0]


@app.delete("/api/posts/{post_id}")
def delete_post(post_id: int, user: dict = Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT user_id, image_url FROM posts WHERE id = ?", (post_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Публикация не найдена")
        if row["user_id"] != user["id"]:
            raise HTTPException(status_code=403, detail="Можно удалять только свои публикации")
        conn.execute("DELETE FROM posts WHERE id = ? AND user_id = ?", (post_id, user["id"]))
    remove_upload(row["image_url"])
    return {"ok": True}


@app.post("/api/posts/{post_id}/like", dependencies=[Depends(rate_limit(write_limiter))])
def toggle_like(post_id: int, user: dict = Depends(get_current_user)):
    with db() as conn:
        if not post_exists(conn, post_id):
            raise HTTPException(status_code=404, detail="Публикация не найдена")
        removed = conn.execute(
            "DELETE FROM likes WHERE user_id = ? AND post_id = ?", (user["id"], post_id)
        ).rowcount
        if removed:
            liked = False
        else:
            conn.execute(
                "INSERT OR IGNORE INTO likes (user_id, post_id) VALUES (?, ?)", (user["id"], post_id)
            )
            liked = True
        likes_count = conn.execute(
            "SELECT COUNT(*) FROM likes WHERE post_id = ?", (post_id,)
        ).fetchone()[0]
    return {"liked": liked, "likes_count": likes_count}


# ---------- комментарии ----------

@app.get("/api/posts/{post_id}/comments")
def list_comments(post_id: int, user: dict = Depends(get_current_user)):
    with db() as conn:
        if not post_exists(conn, post_id):
            raise HTTPException(status_code=404, detail="Публикация не найдена")
        rows = conn.execute(
            COMMENT_SELECT + " WHERE c.post_id = ? ORDER BY c.id ASC LIMIT 200",
            (post_id,),
        ).fetchall()
    return [serialize_comment(row, user["id"]) for row in rows]


@app.post("/api/posts/{post_id}/comments", status_code=201,
          dependencies=[Depends(rate_limit(write_limiter))])
def add_comment(post_id: int, data: CommentIn, user: dict = Depends(get_current_user)):
    with db() as conn:
        if not post_exists(conn, post_id):
            raise HTTPException(status_code=404, detail="Публикация не найдена")
        cursor = conn.execute(
            "INSERT INTO comments (post_id, user_id, text) VALUES (?, ?, ?)",
            (post_id, user["id"], data.text),
        )
        row = conn.execute(COMMENT_SELECT + " WHERE c.id = ?", (cursor.lastrowid,)).fetchone()
    return serialize_comment(row, user["id"])


@app.delete("/api/comments/{comment_id}")
def delete_comment(comment_id: int, user: dict = Depends(get_current_user)):
    """Удалить может автор комментария или автор публикации."""
    with db() as conn:
        row = conn.execute(
            """
            SELECT c.user_id AS author_id, p.user_id AS post_owner_id
            FROM comments c JOIN posts p ON p.id = c.post_id
            WHERE c.id = ?
            """,
            (comment_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Комментарий не найден")
        if user["id"] not in (row["author_id"], row["post_owner_id"]):
            raise HTTPException(status_code=403, detail="Нельзя удалить чужой комментарий")
        conn.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    return {"ok": True}


@app.get("/api/health")
def health():
    return {"status": "ok"}


# =============================================================================
# 8. Раздача файлов: загрузки и фронтенд
# =============================================================================
# Монтируем в конце, чтобы маршруты /api имели приоритет.
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
