from __future__ import annotations

import base64
import enum
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator, model_validator

load_dotenv()

app = FastAPI(title="NOTO API", version="1.0.0")

security = HTTPBearer()
optional_security = HTTPBearer(auto_error=False)

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR.parent.parent / "Models_api" / "models_data.db"
DB_PATH = Path(os.getenv("NOTO_DB_PATH", DEFAULT_DB)).resolve()
STORAGE_ROOT = Path(os.getenv("NOTO_STORAGE_ROOT", BASE_DIR.parent / "storage")).resolve()
AUDIO_DIR = STORAGE_ROOT / "audio"
IMAGE_DIR = STORAGE_ROOT / "images"

STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
AUDIO_DIR.mkdir(parents=True, exist_ok=True)
IMAGE_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required.")

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password TEXT NOT NULL
    )
"""
)

cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS tokens (
        email TEXT PRIMARY KEY,
        token TEXT NOT NULL
    )
"""
)

cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS note_owners (
        owner_id TEXT PRIMARY KEY,
        owner_email TEXT NOT NULL,
        owner_name TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
"""
)

cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS noto_notes (
        note_id TEXT PRIMARY KEY,
        owner_email TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        owner_name TEXT,
        notes TEXT,
        transcript TEXT,
        upcoming_work TEXT,
        privacy TEXT NOT NULL,
        class_name TEXT,
        collection_name TEXT,
        extras TEXT,
        audio_path TEXT,
        audio_mime TEXT,
        cover_image_path TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
"""
)

try:
    cursor.execute("ALTER TABLE noto_notes ADD COLUMN extras TEXT")
except sqlite3.OperationalError:
    pass

conn.commit()

NOTE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:\\-]{4,128}$")
OWNER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:\\-]{4,128}$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class Privacy(str, enum.Enum):
    PRIVATE = "PRIVATE"
    PUBLIC = "PUBLIC"


class NoteMetadata(BaseModel):
    note_id: str = Field(..., description="Unique identifier for the note.")
    owner_id: str = Field(..., description="Immutable owner identifier.")
    owner_name: str = Field(..., description="Human readable owner name.")
    notes: str = Field(..., description="Rich note content.")
    transcript: Optional[str] = Field(None, description="Transcription text.")
    upcoming_work: Optional[str] = Field(
        None, description="Optional upcoming work or action items."
    )
    privacy: Privacy = Field(..., description="Privacy level (PRIVATE or PUBLIC).")
    class_name: Optional[str] = Field(
        None, description="Optional class/subject grouping."
    )
    collection_name: Optional[str] = Field(
        None, description="Optional collection grouping."
    )
    cd_pic: Optional[str] = Field(
        None,
        description="Optional cover/thumbnail image as base64 string.",
        alias="CD_pic",
    )
    extras: dict[str, Any] | None = Field(
        default=None, description="Additional metadata to persist."
    )

    @model_validator(mode="before")
    def _normalize_cd_pic(cls, values: dict[str, Any]) -> dict[str, Any]:
        if isinstance(values, dict):
            if "cd_pic" not in values and "CD_pic" in values:
                values["cd_pic"] = values["CD_pic"]
            if "privacy" in values and isinstance(values["privacy"], str):
                values["privacy"] = values["privacy"].strip().upper()
        return values

    @field_validator("privacy", mode="before")
    def _validate_privacy(cls, value: Any) -> str:
        if isinstance(value, Privacy):
            return value.value
        if isinstance(value, str):
            candidate = value.strip().upper()
            if candidate in Privacy.__members__:
                return candidate
        raise ValueError("privacy must be either PRIVATE or PUBLIC.")

    @field_validator("note_id")
    def _validate_note_id(cls, value: str) -> str:
        if not value:
            raise ValueError("note_id is required.")
        if not NOTE_ID_PATTERN.match(value):
            raise ValueError(
                "note_id may only contain letters, numbers, ., :, _, or - (min 4 chars)."
            )
        return value

    @field_validator("owner_id")
    def _validate_owner_id(cls, value: str) -> str:
        if not value:
            raise ValueError("owner_id is required.")
        if not OWNER_ID_PATTERN.match(value):
            raise ValueError(
                "owner_id may only contain letters, numbers, ., :, _, or - (min 4 chars)."
            )
        return value


class GetNoteRequest(BaseModel):
    note_id: str
    user_id: Optional[str] = None
    user_token: Optional[str] = None
    include_audio: bool = False
    include_image: bool = False


class GetClassesRequest(BaseModel):
    owner_id: str
    user_token: Optional[str] = None


class GetCollectionRequest(BaseModel):
    owner_id: str
    class_name: Optional[str] = None
    include_private: bool = False
    user_token: Optional[str] = None


def _decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return email


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    return _decode_token(credentials.credentials)


def optional_token_email(
    credentials: HTTPAuthorizationCredentials | None,
    inline_token: str | None,
) -> Optional[str]:
    tokens_to_try: list[str] = []
    if inline_token:
        tokens_to_try.append(inline_token)
    if credentials and credentials.credentials:
        tokens_to_try.append(credentials.credentials)
    for candidate in tokens_to_try:
        try:
            return _decode_token(candidate)
        except HTTPException:
            continue
    return None


def create_refresh_token(email: str) -> str:
    payload = {
        "email": email,
        "exp": int(datetime.now(timezone.utc).timestamp()) + 60 * 60 * 24 * 30,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def _owner_email_for_id(owner_id: str) -> Optional[str]:
    cursor.execute(
        "SELECT owner_email FROM note_owners WHERE owner_id = ?", (owner_id,)
    )
    row = cursor.fetchone()
    if not row:
        return None
    return row["owner_email"]


def _persist_owner(owner_id: str, owner_email: str, owner_name: str) -> None:
    timestamp = _now_iso()
    cursor.execute(
        """
        INSERT INTO note_owners (owner_id, owner_email, owner_name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(owner_id) DO UPDATE SET
            owner_email = excluded.owner_email,
            owner_name = excluded.owner_name,
            updated_at = excluded.updated_at
        """,
        (owner_id, owner_email, owner_name, timestamp, timestamp),
    )


def _load_note(note_id: str) -> sqlite3.Row | None:
    cursor.execute("SELECT * FROM noto_notes WHERE note_id = ?", (note_id,))
    return cursor.fetchone()


async def _store_upload(file: UploadFile, target_path: Path) -> tuple[str, str]:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("wb") as output:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)
    await file.close()
    relative_path = target_path.relative_to(STORAGE_ROOT)
    return str(relative_path), file.content_type or "application/octet-stream"


def _store_base64_image(data: str, note_id: str) -> str:
    if "," in data and data.split(",", 1)[0].startswith("data:"):
        header, payload = data.split(",", 1)
        mime_part = header.split(";")[0]
        extension = mime_part.split("/")[-1] or "png"
    else:
        payload = data
        extension = "png"
    binary = base64.b64decode(payload)
    filename = f"{note_id}_{uuid.uuid4().hex[:8]}.{extension}"
    target_path = IMAGE_DIR / filename
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("wb") as output:
        output.write(binary)
    return str(target_path.relative_to(STORAGE_ROOT))


def _note_access_allowed(
    note_row: sqlite3.Row,
    request_email: Optional[str],
    request_owner_id: Optional[str],
) -> bool:
    if request_email and request_email == note_row["owner_email"]:
        return True
    if request_owner_id and request_owner_id == note_row["owner_id"]:
        return True
    if note_row["privacy"] == Privacy.PUBLIC.value:
        return True
    return False


def _note_to_payload(
    note_row: sqlite3.Row,
    include_audio: bool = False,
    include_image: bool = False,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "note_id": note_row["note_id"],
        "owner_id": note_row["owner_id"],
        "owner_name": note_row["owner_name"],
        "notes": note_row["notes"],
        "transcript": note_row["transcript"],
        "upcoming_work": note_row["upcoming_work"],
        "privacy": note_row["privacy"],
        "class_name": note_row["class_name"],
        "collection_name": note_row["collection_name"],
        "extras": json.loads(note_row["extras"]) if note_row["extras"] else None,
        "created_at": note_row["created_at"],
        "updated_at": note_row["updated_at"],
        "audio_url": None,
        "cover_image_url": None,
    }
    if note_row["audio_path"]:
        payload["audio_url"] = f"/notes/{note_row['note_id']}/audio"
    if note_row["cover_image_path"]:
        payload["cover_image_url"] = f"/notes/{note_row['note_id']}/cover"

    if include_audio and note_row["audio_path"]:
        audio_path = STORAGE_ROOT / note_row["audio_path"]
        if audio_path.exists():
            payload["audio_base64"] = base64.b64encode(audio_path.read_bytes()).decode()
    if include_image and note_row["cover_image_path"]:
        image_path = STORAGE_ROOT / note_row["cover_image_path"]
        if image_path.exists():
            payload["cover_image_base64"] = base64.b64encode(
                image_path.read_bytes()
            ).decode()
    return payload


@app.post("/register")
def register(req: RegisterRequest):
    cursor.execute("SELECT email FROM users WHERE email = ?", (req.email,))
    if cursor.fetchone():
        raise HTTPException(status_code=409, detail="User already exists")
    hashed_pw = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    cursor.execute(
        "INSERT INTO users (email, password) VALUES (?, ?)", (req.email, hashed_pw)
    )
    conn.commit()
    return {"status": "User registered successfully"}


@app.post("/login")
def login(req: LoginRequest):
    cursor.execute("SELECT password FROM users WHERE email = ?", (req.email,))
    row = cursor.fetchone()
    if row and bcrypt.checkpw(req.password.encode(), row["password"].encode()):
        payload = {
            "email": req.email,
            "exp": int(datetime.now(timezone.utc).timestamp()) + 60 * 60 * 24 * 7,
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        cursor.execute(
            "REPLACE INTO tokens (email, token) VALUES (?, ?)", (req.email, token)
        )
        conn.commit()
        refresh_token = create_refresh_token(req.email)
        return {"token": token, "refresh_token": refresh_token}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/refresh")
def refresh_token(req: RefreshRequest):
    payload = jwt.decode(req.refresh_token, SECRET_KEY, algorithms=["HS256"])
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    new_payload = {
        "email": email,
        "exp": int(datetime.now(timezone.utc).timestamp()) + 60 * 60 * 24 * 7,
    }
    new_token = jwt.encode(new_payload, SECRET_KEY, algorithm="HS256")
    cursor.execute(
        "REPLACE INTO tokens (email, token) VALUES (?, ?)", (email, new_token)
    )
    conn.commit()
    return {"token": new_token}


@app.post("/save_note")
async def save_note(
    metadata: str = Form(..., description="JSON encoded metadata payload."),
    audio: UploadFile | None = File(
        default=None, description="Optional audio file (binary upload)."
    ),
    cover_image: UploadFile | None = File(
        default=None, description="Optional cover image upload."
    ),
    user_email: str = Depends(verify_token),
):
    try:
        payload = json.loads(metadata)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="metadata must be valid JSON.") from exc

    note_metadata = NoteMetadata.model_validate(payload)

    existing_owner_email = _owner_email_for_id(note_metadata.owner_id)
    if existing_owner_email and existing_owner_email != user_email:
        raise HTTPException(
            status_code=403,
            detail="owner_id already exists for a different account.",
        )

    audio_path: Optional[str] = None
    audio_mime: Optional[str] = None
    cover_path: Optional[str] = None

    existing_note = _load_note(note_metadata.note_id)
    if existing_note and existing_note["owner_email"] != user_email:
        raise HTTPException(status_code=403, detail="Cannot overwrite another user's note.")

    extras_json = (
        json.dumps(note_metadata.extras)
        if note_metadata.extras is not None
        else None
    )

    if existing_note:
        audio_path = existing_note["audio_path"]
        audio_mime = existing_note["audio_mime"]
        cover_path = existing_note["cover_image_path"]
        if extras_json is None:
            extras_json = existing_note["extras"]

    if audio is not None:
        extension = Path(audio.filename or "").suffix
        if not extension:
            extension = ".bin"
        target = AUDIO_DIR / f"{note_metadata.note_id}{extension}"
        audio_path, audio_mime = await _store_upload(audio, target)

    if cover_image is not None:
        extension = Path(cover_image.filename or "").suffix or ".bin"
        target = IMAGE_DIR / f"{note_metadata.note_id}{extension}"
        cover_path, _ = await _store_upload(cover_image, target)
    elif note_metadata.cd_pic:
        cover_path = _store_base64_image(note_metadata.cd_pic, note_metadata.note_id)

    timestamp = _now_iso()
    _persist_owner(note_metadata.owner_id, user_email, note_metadata.owner_name)

    cursor.execute(
        """
        INSERT INTO noto_notes (
            note_id,
            owner_email,
            owner_id,
            owner_name,
            notes,
            transcript,
            upcoming_work,
            privacy,
            class_name,
            collection_name,
            extras,
            audio_path,
            audio_mime,
            cover_image_path,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(note_id) DO UPDATE SET
            owner_email = excluded.owner_email,
            owner_id = excluded.owner_id,
            owner_name = excluded.owner_name,
            notes = excluded.notes,
            transcript = excluded.transcript,
            upcoming_work = excluded.upcoming_work,
            privacy = excluded.privacy,
            class_name = excluded.class_name,
            collection_name = excluded.collection_name,
            extras = excluded.extras,
            audio_path = excluded.audio_path,
            audio_mime = excluded.audio_mime,
            cover_image_path = excluded.cover_image_path,
            updated_at = excluded.updated_at
        """,
        (
            note_metadata.note_id,
            user_email,
            note_metadata.owner_id,
            note_metadata.owner_name,
            note_metadata.notes,
            note_metadata.transcript,
            note_metadata.upcoming_work,
            note_metadata.privacy.value,
            note_metadata.class_name,
            note_metadata.collection_name,
            extras_json,
            audio_path,
            audio_mime,
            cover_path,
            existing_note["created_at"] if existing_note else timestamp,
            timestamp,
        ),
    )

    conn.commit()

    saved_note = _load_note(note_metadata.note_id)
    response = _note_to_payload(saved_note)
    response["audio_uploaded"] = bool(audio_path)
    response["cover_uploaded"] = bool(cover_path)
    return response


@app.post("/get_note")
def get_note(
    request: GetNoteRequest,
    credentials: HTTPAuthorizationCredentials | None = Depends(optional_security),
):
    note_row = _load_note(request.note_id)
    if not note_row:
        raise HTTPException(status_code=404, detail="Note not found.")

    request_email = optional_token_email(credentials, request.user_token)
    request_owner_id = request.user_id

    if not _note_access_allowed(note_row, request_email, request_owner_id):
        raise HTTPException(status_code=403, detail="Not authorized to view this note.")

    return _note_to_payload(
        note_row,
        include_audio=request.include_audio,
        include_image=request.include_image,
    )


@app.post("/get_classes")
def get_classes(
    request: GetClassesRequest,
    credentials: HTTPAuthorizationCredentials | None = Depends(optional_security),
):
    owner_email = _owner_email_for_id(request.owner_id)
    request_email = optional_token_email(credentials, request.user_token)
    is_owner = owner_email and request_email and owner_email == request_email

    if not owner_email:
        return {"owner_id": request.owner_id, "classes": []}

    if is_owner:
        cursor.execute(
            """
            SELECT class_name, COUNT(*) as note_count
            FROM noto_notes
            WHERE owner_id = ?
            GROUP BY class_name
            ORDER BY class_name
            """,
            (request.owner_id,),
        )
    else:
        cursor.execute(
            """
            SELECT class_name, COUNT(*) as note_count
            FROM noto_notes
            WHERE owner_id = ? AND privacy = ?
            GROUP BY class_name
            ORDER BY class_name
            """,
            (request.owner_id, Privacy.PUBLIC.value),
        )

    classes = []
    for row in cursor.fetchall():
        classes.append(
            {
                "class_name": row["class_name"],
                "note_count": row["note_count"],
            }
        )

    return {"owner_id": request.owner_id, "classes": classes, "is_owner": bool(is_owner)}


@app.post("/get_collection")
def get_collection(
    request: GetCollectionRequest,
    credentials: HTTPAuthorizationCredentials | None = Depends(optional_security),
):
    owner_email = _owner_email_for_id(request.owner_id)
    request_email = optional_token_email(credentials, request.user_token)
    is_owner = owner_email and request_email and owner_email == request_email

    if not owner_email:
        return {"owner_id": request.owner_id, "notes": []}

    params = [request.owner_id]
    query = """
        SELECT note_id, owner_name, class_name, collection_name, privacy, upcoming_work, created_at, updated_at
        FROM noto_notes
        WHERE owner_id = ?
    """

    if request.class_name:
        query += " AND class_name = ?"
        params.append(request.class_name)

    if not is_owner:
        query += " AND privacy = ?"
        params.append(Privacy.PUBLIC.value)
    elif not request.include_private:
        query += " AND privacy = ?"
        params.append(Privacy.PUBLIC.value)

    query += " ORDER BY updated_at DESC"

    cursor.execute(query, tuple(params))
    notes = []
    for row in cursor.fetchall():
        notes.append(
            {
                "note_id": row["note_id"],
                "owner_name": row["owner_name"],
                "class_name": row["class_name"],
                "collection_name": row["collection_name"],
                "privacy": row["privacy"],
                "upcoming_work": row["upcoming_work"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )

    return {"owner_id": request.owner_id, "notes": notes, "is_owner": bool(is_owner)}


@app.get("/notes/{note_id}/audio")
def download_audio(
    note_id: str,
    token: str | None = None,
    credentials: HTTPAuthorizationCredentials | None = Depends(optional_security),
):
    note_row = _load_note(note_id)
    if not note_row or not note_row["audio_path"]:
        raise HTTPException(status_code=404, detail="Audio not found.")

    request_email = optional_token_email(credentials, token)

    if not _note_access_allowed(note_row, request_email, None):
        raise HTTPException(status_code=403, detail="Not authorized to read audio.")

    audio_path = STORAGE_ROOT / note_row["audio_path"]
    if not audio_path.exists():
        raise HTTPException(status_code=404, detail="Audio file missing.")

    return FileResponse(
        audio_path,
        media_type=note_row["audio_mime"] or "application/octet-stream",
        filename=audio_path.name,
    )


@app.get("/notes/{note_id}/cover")
def download_cover(
    note_id: str,
    token: str | None = None,
    credentials: HTTPAuthorizationCredentials | None = Depends(optional_security),
):
    note_row = _load_note(note_id)
    if not note_row or not note_row["cover_image_path"]:
        raise HTTPException(status_code=404, detail="Cover not found.")

    request_email = optional_token_email(credentials, token)

    if not _note_access_allowed(note_row, request_email, None):
        raise HTTPException(status_code=403, detail="Not authorized to read cover image.")

    cover_path = STORAGE_ROOT / note_row["cover_image_path"]
    if not cover_path.exists():
        raise HTTPException(status_code=404, detail="Cover image file missing.")

    return FileResponse(
        cover_path,
        media_type="image/*",
        filename=cover_path.name,
    )


@app.get("/healthz")
def healthcheck():
    return {"status": "ok"}
