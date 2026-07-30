# Secure JEE/NEET Self-Study MVP — FastAPI + Node SSR + PostgreSQL

> **Important security statement:** no system is absolutely “unhackable”. The implementation below follows strong security practices and OWASP-style guidelines: bcrypt password hashing, JWT auth with short-lived access tokens, refresh tokens, RBAC, Pydantic/server-side validation, ORM-only database access, CSRF protection on the Node SSR layer, secure HTTP headers, rate limiting, structured security event logging, and least-privilege PostgreSQL guidance. You must still operate it securely: HTTPS via reverse proxy, secret management, dependency updates, monitoring, backups, and penetration testing.

---

## 1. High-Level Architecture

```text
Browser
  |
  | HTTPS
  v
Node.js Express SSR frontend
  - Renders pages with EJS
  - Stores JWTs in HttpOnly Secure SameSite cookies
  - Proxies authenticated API calls to FastAPI
  - CSRF protection for browser -> Node requests
  - Helmet security headers
  |
  | Internal HTTP, Authorization: Bearer <access_token>
  v
FastAPI backend
  - Pydantic validation
  - JWT auth + RBAC
  - Rate limiting
  - Business services
  - SQLAlchemy ORM
  |
  | TLS/SCRAM authenticated PostgreSQL connection
  v
PostgreSQL
  - Normalized relational schema
  - Least-privilege application role
```

Design choices:

- The browser never receives JavaScript-accessible JWTs.
- JWTs are kept in `HttpOnly` cookies on the Node layer.
- Browser dynamic calls go to Node JSON endpoints, which proxy to FastAPI with the bearer token.
- CSRF is enforced for browser-to-Node state-changing requests using a double-submit cookie token.
- FastAPI trusts only its own validation and authorization logic.
- All DB access is through SQLAlchemy ORM / parameterized queries.

---

## 2. Project Structure

```text
secure-jee-neet-platform/
├── docker-compose.yml
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── .env.example
│   ├── alembic/
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── versions/
│   │       └── 0001_initial.py
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── config.py
│   │   │   ├── security.py
│   │   │   ├── logging.py
│   │   │   └── rate_limit.py
│   │   ├── db/
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   └── session.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── user.py
│   │   │   ├── routine.py
│   │   │   ├── study_slot.py
│   │   │   ├── question.py
│   │   │   ├── task.py
│   │   │   ├── battle.py
│   │   │   ├── battle_participation.py
│   │   │   └── ledger.py
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py
│   │   │   ├── routine.py
│   │   │   ├── question.py
│   │   │   ├── task.py
│   │   │   └── battle.py
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── deps.py
│   │   │   └── routes/
│   │   │       ├── __init__.py
│   │   │       ├── health.py
│   │   │       ├── auth.py
│   │   │       ├── routine.py
│   │   │       ├── tasks.py
│   │   │       ├── questions.py
│   │   │       ├── battles.py
│   │   │       └── economy.py
│   │   └── services/
│   │       ├── __init__.py
│   │       ├── auth_service.py
│   │       ├── economy_service.py
│   │       ├── routine_service.py
│   │       ├── task_service.py
│   │       ├── question_service.py
│   │       └── battle_service.py
│   └── tests/
│       ├── __init__.py
│       ├── conftest.py
│       ├── test_auth.py
│       ├── test_tasks.py
│       └── test_battles.py
└── frontend/
    ├── Dockerfile
    ├── package.json
    ├── .env.example
    ├── server.js
    └── src/
        ├── config.js
        ├── middleware/
        │   ├── csrf.js
        │   ├── auth.js
        │   ├── validation.js
        │   └── error.js
        ├── lib/
        │   └── api.js
        ├── routes/
        │   ├── auth.js
        │   ├── dashboard.js
        │   └── battles.js
        ├── views/
        │   ├── partials/
        │   │   ├── head.ejs
        │   │   ├── header.ejs
        │   │   └── footer.ejs
        │   ├── login.ejs
        │   ├── register.ejs
        │   ├── dashboard.ejs
        │   ├── battle-lobby.ejs
        │   └── battle-play.ejs
        └── public/
            ├── css/
            │   └── app.css
            └── js/
                ├── dashboard.js
                └── battle.js
```

All Python `__init__.py` files can be empty unless shown otherwise.

---

# 3. Backend Code

## 3.1 Backend requirements

```txt
# backend/requirements.txt

fastapi==0.115.6
uvicorn[standard]==0.32.1
SQLAlchemy==2.0.36
psycopg2-binary==2.9.10
alembic==1.14.0
pydantic==2.10.3
pydantic-settings==2.6.1
email-validator==2.2.0
passlib[bcrypt]==1.7.4
bcrypt==4.0.1
PyJWT==2.10.1
python-multipart==0.0.19
slowapi==0.1.9

# tests
pytest==8.3.4
httpx==0.28.1
```

---

## 3.2 Backend environment sample

```bash
# backend/.env.example

APP_NAME="Study Platform API"
ENV=development
DEBUG=false

# Required: generate with:
# python -c "import secrets; print(secrets.token_urlsafe(64))"
SECRET_KEY=CHANGE_ME

JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=14

# Local dev:
DATABASE_URL=postgresql+psycopg2://study_app:CHANGE_ME@localhost:5432/studyplatform

# Production example with TLS:
# DATABASE_URL=postgresql+psycopg2://study_app:CHANGE_ME@db-host:5432/studyplatform?sslmode=verify-full

CORS_ORIGINS=http://localhost:3000
RATE_LIMIT_ENABLED=true
PASSWORD_MIN_LENGTH=8
```

---

## 3.3 Core configuration and security

```python
# backend/app/core/config.py

from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    APP_NAME: str = "Study Platform API"
    ENV: str = "development"
    DEBUG: bool = False

    SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14

    DATABASE_URL: str

    CORS_ORIGINS: List[str] = []

    RATE_LIMIT_ENABLED: bool = True
    PASSWORD_MIN_LENGTH: int = 8

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, value):
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


settings = Settings()
```

```python
# backend/app/core/security.py

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _create_token(subject: int, expires_delta: timedelta, token_type: str) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": str(subject),
        "iat": now,
        "exp": now + expires_delta,
        "type": token_type,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_access_token(user_id: int) -> str:
    return _create_token(
        subject=user_id,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access",
    )


def create_refresh_token(user_id: int) -> str:
    return _create_token(
        subject=user_id,
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        token_type="refresh",
    )


def decode_token(token: str) -> Dict[str, Any]:
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )


def password_is_strong(password: str) -> bool:
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return False
    if not any(ch.islower() for ch in password):
        return False
    if not any(ch.isupper() for ch in password):
        return False
    if not any(ch.isdigit() for ch in password):
        return False
    return True
```

```python
# backend/app/core/logging.py

import json
import logging
import sys


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stdout,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def get_security_logger() -> logging.Logger:
    return logging.getLogger("security")


def log_security_event(event: str, **context) -> None:
    logger = get_security_logger()
    payload = {"event": event, **context}
    logger.warning(json.dumps(payload, default=str))
```

```python
# backend/app/core/rate_limit.py

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings

# Production note:
# Use Redis-backed storage for multi-process/multi-instance deployments:
# storage_uri="redis://redis:6379"
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    enabled=settings.RATE_LIMIT_ENABLED,
)
```

---

## 3.4 Database base and session

```python
# backend/app/db/base.py

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

naming_convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=naming_convention)
```

```python
# backend/app/db/session.py

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

connect_args = {}

if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    future=True,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)
```

---

## 3.5 SQLAlchemy models

```python
# backend/app/models/user.py

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    points_balance: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    coins_balance: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
```

```python
# backend/app/models/routine.py

from datetime import datetime, time
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, Time, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Routine(Base):
    __tablename__ = "routines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )

    wake_time: Mapped[time] = mapped_column(Time, nullable=False)
    sleep_time: Mapped[time] = mapped_column(Time, nullable=False)

    school_start: Mapped[Optional[time]] = mapped_column(Time, nullable=True)
    school_end: Mapped[Optional[time]] = mapped_column(Time, nullable=True)

    coaching_start: Mapped[Optional[time]] = mapped_column(Time, nullable=True)
    coaching_end: Mapped[Optional[time]] = mapped_column(Time, nullable=True)

    target_study_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=180)
    min_break_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=10)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
```

```python
# backend/app/models/study_slot.py

from datetime import date, datetime, time
from typing import Optional

from sqlalchemy import Date, DateTime, ForeignKey, Integer, String, Time, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class StudySlot(Base):
    __tablename__ = "study_slots"
    __table_args__ = (
        UniqueConstraint("user_id", "slot_date", "start_time", name="user_date_start"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    slot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    start_time: Mapped[time] = mapped_column(Time, nullable=False)
    end_time: Mapped[time] = mapped_column(Time, nullable=False)

    slot_type: Mapped[str] = mapped_column(String(20), nullable=False, default="study")
    capacity_minutes: Mapped[int] = mapped_column(Integer, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
```

```python
# backend/app/models/question.py

from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Question(Base):
    __tablename__ = "questions"
    __table_args__ = (
        CheckConstraint(
            "correct_option IN ('A', 'B', 'C', 'D')",
            name="questions_correct_option",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    subject: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    topic: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)

    option_a: Mapped[str] = mapped_column(String(255), nullable=False)
    option_b: Mapped[str] = mapped_column(String(255), nullable=False)
    option_c: Mapped[str] = mapped_column(String(255), nullable=False)
    option_d: Mapped[str] = mapped_column(String(255), nullable=False)

    correct_option: Mapped[str] = mapped_column(String(1), nullable=False)

    difficulty: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    created_by: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
```

```python
# backend/app/models/task.py

from datetime import date, datetime
from typing import Optional

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Task(Base):
    __tablename__ = "tasks"
    __table_args__ = (
        UniqueConstraint("user_id", "scheduled_date", "position", name="user_date_position"),
        CheckConstraint(
            "status IN ('scheduled', 'completed', 'missed', 'rescheduled')",
            name="tasks_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    scheduled_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(80), nullable=False)
    topic: Mapped[str] = mapped_column(String(120), nullable=False)

    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    video_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)

    status: Mapped[str] = mapped_column(String(20), nullable=False, default="scheduled")
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    points_awarded: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    source_task_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("tasks.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class TaskQuestion(Base):
    __tablename__ = "task_questions"

    task_id: Mapped[int] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"),
        primary_key=True,
    )
    question_id: Mapped[int] = mapped_column(
        ForeignKey("questions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
```

```python
# backend/app/models/battle.py

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Battle(Base):
    __tablename__ = "battles"
    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'live', 'finished', 'cancelled')",
            name="battles_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(80), nullable=False)

    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False)

    max_players: Mapped[int] = mapped_column(Integer, nullable=False, default=40)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")

    created_by: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class BattleQuestion(Base):
    __tablename__ = "battle_questions"

    battle_id: Mapped[int] = mapped_column(
        ForeignKey("battles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    question_id: Mapped[int] = mapped_column(
        ForeignKey("questions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
```

```python
# backend/app/models/battle_participation.py

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class BattleParticipation(Base):
    __tablename__ = "battle_participations"
    __table_args__ = (
        UniqueConstraint("battle_id", "user_id", name="battle_user"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    battle_id: Mapped[int] = mapped_column(
        ForeignKey("battles.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    correct_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    incorrect_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    raw_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    time_bonus: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    coins_earned: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rank: Mapped[Optional[int]] = mapped_column("leaderboard_rank", Integer, nullable=True)
```

```python
# backend/app/models/ledger.py

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PointLedger(Base):
    __tablename__ = "point_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    delta: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str] = mapped_column(String(80), nullable=False)

    reference_type: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    reference_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class CoinLedger(Base):
    __tablename__ = "coin_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    delta: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str] = mapped_column(String(80), nullable=False)

    reference_type: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    reference_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
```

```python
# backend/app/models/__init__.py

from app.db.base import Base
from app.models.user import User
from app.models.routine import Routine
from app.models.study_slot import StudySlot
from app.models.question import Question
from app.models.task import Task, TaskQuestion
from app.models.battle import Battle, BattleQuestion
from app.models.battle_participation import BattleParticipation
from app.models.ledger import PointLedger, CoinLedger

__all__ = [
    "Base",
    "User",
    "Routine",
    "StudySlot",
    "Question",
    "Task",
    "TaskQuestion",
    "Battle",
    "BattleQuestion",
    "BattleParticipation",
    "PointLedger",
    "CoinLedger",
]
```

---

## 3.6 Pydantic schemas

```python
# backend/app/schemas/auth.py

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.security import password_is_strong


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=2, max_length=120)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        if not password_is_strong(value):
            raise ValueError(
                "Password must be at least 8 characters and include uppercase, lowercase, and a digit."
            )
        return value


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    points_balance: int
    coins_balance: int


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str
```

```python
# backend/app/schemas/routine.py

from datetime import date, time
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RoutineUpsert(BaseModel):
    wake_time: time
    sleep_time: time

    school_start: Optional[time] = None
    school_end: Optional[time] = None

    coaching_start: Optional[time] = None
    coaching_end: Optional[time] = None

    target_study_minutes: int = Field(default=180, ge=60, le=720)
    min_break_minutes: int = Field(default=10, ge=0, le=120)

    @model_validator(mode="after")
    def validate_times(self):
        if self.sleep_time <= self.wake_time:
            raise ValueError("sleep_time must be after wake_time on the same day.")

        pairs = [
            ("school_start", "school_end", self.school_start, self.school_end),
            ("coaching_start", "coaching_end", self.coaching_start, self.coaching_end),
        ]

        for start_name, end_name, start_value, end_value in pairs:
            start_missing = start_value is None
            end_missing = end_value is None

            if start_missing != end_missing:
                raise ValueError(f"{start_name} and {end_name} must be provided together.")

            if not start_missing and not end_missing and end_value <= start_value:
                raise ValueError(f"{end_name} must be after {start_name}.")

        return self


class RoutineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    wake_time: time
    sleep_time: time
    school_start: Optional[time]
    school_end: Optional[time]
    coaching_start: Optional[time]
    coaching_end: Optional[time]
    target_study_minutes: int
    min_break_minutes: int


class StudySlotOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    slot_date: date
    start_time: time
    end_time: time
    slot_type: str
    capacity_minutes: int
```

```python
# backend/app/schemas/question.py

from pydantic import BaseModel, ConfigDict, Field


class QuestionCreate(BaseModel):
    subject: str = Field(min_length=2, max_length=80)
    topic: str = Field(min_length=2, max_length=120)
    prompt: str = Field(min_length=5, max_length=5000)

    option_a: str = Field(min_length=1, max_length=255)
    option_b: str = Field(min_length=1, max_length=255)
    option_c: str = Field(min_length=1, max_length=255)
    option_d: str = Field(min_length=1, max_length=255)

    correct_option: str = Field(pattern="^[A-D]$")
    difficulty: str = Field(default="medium", pattern="^(easy|medium|hard)$")


class QuestionUpdate(BaseModel):
    subject: str | None = Field(default=None, min_length=2, max_length=80)
    topic: str | None = Field(default=None, min_length=2, max_length=120)
    prompt: str | None = Field(default=None, min_length=5, max_length=5000)

    option_a: str | None = Field(default=None, min_length=1, max_length=255)
    option_b: str | None = Field(default=None, min_length=1, max_length=255)
    option_c: str | None = Field(default=None, min_length=1, max_length=255)
    option_d: str | None = Field(default=None, min_length=1, max_length=255)

    correct_option: str | None = Field(default=None, pattern="^[A-D]$")
    difficulty: str | None = Field(default=None, pattern="^(easy|medium|hard)$")


class QuestionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    subject: str
    topic: str
    prompt: str
    option_a: str
    option_b: str
    option_c: str
    option_d: str
    correct_option: str
    difficulty: str


class QuestionPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    subject: str
    topic: str
    prompt: str
    option_a: str
    option_b: str
    option_c: str
    option_d: str
```

```python
# backend/app/schemas/task.py

from datetime import date, datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.question import QuestionPublic


class TaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    scheduled_date: date
    position: int
    title: str
    subject: str
    topic: str
    status: str
    completed_at: Optional[datetime]
    points_awarded: int
    accessible: bool = False


class TaskDetailOut(TaskOut):
    notes: str
    video_url: Optional[str]
    questions: List[QuestionPublic] = []


class TaskAnswer(BaseModel):
    question_id: int
    selected_option: str = Field(pattern="^[A-D]$")


class TaskCompleteRequest(BaseModel):
    answers: List[TaskAnswer] = []


class TaskCompleteResponse(BaseModel):
    completed: bool
    correct_count: int
    points_awarded: int
    task: TaskOut
```

```python
# backend/app/schemas/battle.py

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.question import QuestionPublic


class BattleCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    subject: str = Field(min_length=2, max_length=80)
    scheduled_at: datetime
    duration_seconds: int = Field(ge=600, le=3600)
    max_players: int = Field(ge=20, le=40)
    question_ids: List[int] = Field(min_length=10, max_length=20)

    @field_validator("scheduled_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class BattleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    subject: str
    scheduled_at: datetime
    duration_seconds: int
    max_players: int
    status: str
    player_count: int = 0


class BattleParticipationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    battle_id: int
    user_id: int
    joined_at: datetime


class BattlePlayOut(BaseModel):
    battle: BattleOut
    questions: List[QuestionPublic]
    server_time: datetime


class BattleAnswer(BaseModel):
    question_id: int
    selected_option: str = Field(pattern="^[A-D]$")
    time_ms: int = Field(ge=0)


class BattleSubmitRequest(BaseModel):
    answers: List[BattleAnswer] = Field(min_length=10, max_length=20)


class LeaderboardEntry(BaseModel):
    user_id: int
    full_name: str
    total_score: int
    rank: Optional[int] = None
    coins_earned: Optional[int] = None


class BattleResultOut(BaseModel):
    battle_id: int
    status: str
    my_total_score: int
    leaderboard: List[LeaderboardEntry]
```

---

## 3.7 API dependencies

```python
# backend/app/api/deps.py

from typing import Generator

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.db.session import SessionLocal
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
        token_type = payload.get("type")
        user_id = payload.get("sub")

        if token_type != "access" or user_id is None:
            raise credentials_exception

        user = db.get(User, int(user_id))
    except (InvalidTokenError, ValueError, TypeError):
        raise credentials_exception

    if user is None or not user.is_active:
        raise credentials_exception

    return user


def get_current_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required.",
        )
    return current_user
```

---

## 3.8 Services

```python
# backend/app/services/auth_service.py

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.models.user import User
from app.schemas.auth import UserCreate


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))


def register_user(db: Session, payload: UserCreate) -> User:
    existing = get_user_by_email(db, payload.email)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered.",
        )

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role="user",
        is_active=True,
        points_balance=0,
        coins_balance=0,
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate(db: Session, email: str, password: str) -> User | None:
    user = get_user_by_email(db, email)
    if user is None:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    if not user.is_active:
        return None

    return user
```

```python
# backend/app/services/economy_service.py

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.ledger import CoinLedger, PointLedger
from app.models.user import User

POINT_CONVERSION_UNIT = 100
COINS_PER_UNIT = 10


def _adjust_balance(user: User, field: str, delta: int) -> int:
    current = getattr(user, field)

    if delta < 0:
        actual_delta = max(delta, -current)
    else:
        actual_delta = delta

    setattr(user, field, current + actual_delta)
    return actual_delta


def award_points(
    db: Session,
    user: User,
    delta: int,
    reason: str,
    reference_type: str | None = None,
    reference_id: int | None = None,
    commit: bool = False,
) -> int:
    actual_delta = _adjust_balance(user, "points_balance", delta)

    ledger = PointLedger(
        user_id=user.id,
        delta=actual_delta,
        reason=reason,
        reference_type=reference_type,
        reference_id=reference_id,
    )
    db.add(ledger)

    if commit:
        db.commit()
    else:
        db.flush()

    return actual_delta


def award_coins(
    db: Session,
    user: User,
    delta: int,
    reason: str,
    reference_type: str | None = None,
    reference_id: int | None = None,
    commit: bool = False,
) -> int:
    actual_delta = _adjust_balance(user, "coins_balance", delta)

    ledger = CoinLedger(
        user_id=user.id,
        delta=actual_delta,
        reason=reason,
        reference_type=reference_type,
        reference_id=reference_id,
    )
    db.add(ledger)

    if commit:
        db.commit()
    else:
        db.flush()

    return actual_delta


def convert_points_to_coins(db: Session, user: User) -> User:
    if user.points_balance < POINT_CONVERSION_UNIT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"At least {POINT_CONVERSION_UNIT} points are required for conversion.",
        )

    units = user.points_balance // POINT_CONVERSION_UNIT
    points_to_deduct = units * POINT_CONVERSION_UNIT
    coins_to_add = units * COINS_PER_UNIT

    award_points(
        db=db,
        user=user,
        delta=-points_to_deduct,
        reason="points_conversion",
        reference_type="user",
        reference_id=user.id,
    )

    award_coins(
        db=db,
        user=user,
        delta=coins_to_add,
        reason="points_conversion",
        reference_type="user",
        reference_id=user.id,
    )

    db.commit()
    db.refresh(user)
    return user
```

```python
# backend/app/services/routine_service.py

from datetime import date, time
from typing import List

from fastapi import HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models.routine import Routine
from app.models.study_slot import StudySlot
from app.models.user import User
from app.schemas.routine import RoutineUpsert

STUDY_SLOT_MINUTES = 50
MIN_USEFUL_SLOT_MINUTES = 25


def get_routine(db: Session, user: User) -> Routine | None:
    return db.scalar(select(Routine).where(Routine.user_id == user.id))


def upsert_routine(db: Session, user: User, payload: RoutineUpsert) -> Routine:
    routine = get_routine(db, user)

    if routine is None:
        routine = Routine(user_id=user.id)

    routine.wake_time = payload.wake_time
    routine.sleep_time = payload.sleep_time
    routine.school_start = payload.school_start
    routine.school_end = payload.school_end
    routine.coaching_start = payload.coaching_start
    routine.coaching_end = payload.coaching_end
    routine.target_study_minutes = payload.target_study_minutes
    routine.min_break_minutes = payload.min_break_minutes

    db.add(routine)
    db.commit()
    db.refresh(routine)
    return routine


def _minutes(value: time) -> int:
    return value.hour * 60 + value.minute


def _time_from_minutes(value: int) -> time:
    return time(hour=(value // 60) % 24, minute=value % 60)


def _subtract_interval(intervals, exclusion_start, exclusion_end):
    result = []

    for start, end in intervals:
        if exclusion_end <= start or exclusion_start >= end:
            result.append((start, end))
            continue

        if start < exclusion_start:
            result.append((start, exclusion_start))

        if exclusion_end < end:
            result.append((exclusion_end, end))

    return result


def compute_study_slots(
    db: Session,
    user: User,
    routine: Routine,
    target_date: date,
) -> List[StudySlot]:
    wake = _minutes(routine.wake_time)
    sleep = _minutes(routine.sleep_time)

    if sleep <= wake:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Routine sleep_time must be after wake_time.",
        )

    available = [(wake, sleep)]

    commitments = [
        (routine.school_start, routine.school_end),
        (routine.coaching_start, routine.coaching_end),
    ]

    for start_value, end_value in commitments:
        if start_value is None or end_value is None:
            continue

        start = max(_minutes(start_value), wake)
        end = min(_minutes(end_value), sleep)

        if end > start:
            available = _subtract_interval(available, start, end)

    db.execute(
        delete(StudySlot).where(
            StudySlot.user_id == user.id,
            StudySlot.slot_date == target_date,
        )
    )

    created_slots: List[StudySlot] = []
    used_minutes = 0
    break_minutes = routine.min_break_minutes
    target_minutes = routine.target_study_minutes

    for interval_start, interval_end in available:
        cursor = interval_start

        while cursor < interval_end and used_minutes < target_minutes:
            remaining = interval_end - cursor

            if remaining < MIN_USEFUL_SLOT_MINUTES:
                break

            slot_end = min(cursor + STUDY_SLOT_MINUTES, interval_end)
            duration = slot_end - cursor

            if duration < MIN_USEFUL_SLOT_MINUTES:
                break

            slot = StudySlot(
                user_id=user.id,
                slot_date=target_date,
                start_time=_time_from_minutes(cursor),
                end_time=_time_from_minutes(slot_end),
                slot_type="study",
                capacity_minutes=duration,
            )

            db.add(slot)
            created_slots.append(slot)

            used_minutes += duration
            cursor = slot_end + break_minutes

    db.commit()

    return db.scalars(
        select(StudySlot)
        .where(
            StudySlot.user_id == user.id,
            StudySlot.slot_date == target_date,
        )
        .order_by(StudySlot.start_time)
    ).all()
```

```python
# backend/app/services/task_service.py

from datetime import date, datetime, timedelta, timezone
from math import ceil
from typing import List

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.question import Question
from app.models.routine import Routine
from app.models.task import Task, TaskQuestion
from app.models.user import User
from app.schemas.question import QuestionPublic
from app.schemas.task import (
    TaskCompleteRequest,
    TaskCompleteResponse,
    TaskDetailOut,
    TaskOut,
)
from app.services import economy_service, routine_service

MAX_TASKS_PER_DAY = 3

STUB_TASK_CONTENT = [
    ("Physics", "Photoelectric Effect"),
    ("Chemistry", "Mole Concept"),
    ("Mathematics", "Quadratic Equations"),
    ("Biology", "Human Physiology"),
]


def _is_task_accessible(db: Session, task: Task) -> bool:
    previous_tasks = db.scalars(
        select(Task).where(
            Task.user_id == task.user_id,
            Task.scheduled_date == task.scheduled_date,
            Task.position < task.position,
        )
    ).all()

    return all(previous.status == "completed" for previous in previous_tasks)


def _to_task_out(task: Task, accessible: bool) -> TaskOut:
    return TaskOut.model_validate(task).model_copy(update={"accessible": accessible})


def get_tasks_for_date(db: Session, user: User, target_date: date) -> List[TaskOut]:
    tasks = db.scalars(
        select(Task)
        .where(
            Task.user_id == user.id,
            Task.scheduled_date == target_date,
        )
        .order_by(Task.position)
    ).all()

    return [_to_task_out(task, _is_task_accessible(db, task)) for task in tasks]


def generate_tasks_for_date(db: Session, user: User, target_date: date) -> List[TaskOut]:
    existing = db.scalars(
        select(Task).where(
            Task.user_id == user.id,
            Task.scheduled_date == target_date,
        )
    ).all()

    if existing:
        return get_tasks_for_date(db, user, target_date)

    routine: Routine | None = routine_service.get_routine(db, user)
    if routine is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Save a routine before generating tasks.",
        )

    slots = routine_service.compute_study_slots(db, user, routine, target_date)
    if not slots:
        return []

    for index, slot in enumerate(slots[:MAX_TASKS_PER_DAY], start=1):
        subject, topic = STUB_TASK_CONTENT[(index - 1) % len(STUB_TASK_CONTENT)]

        task = Task(
            user_id=user.id,
            scheduled_date=target_date,
            position=index,
            title=f"Task {index}: {topic}",
            subject=subject,
            topic=topic,
            notes=(
                f"Stub notes for {topic}. "
                "Replace with real curriculum content, markdown, or CMS references."
            ),
            video_url=None,
            status="scheduled",
            points_awarded=0,
        )

        db.add(task)
        db.flush()

        questions = db.scalars(
            select(Question).order_by(func.random()).limit(5)
        ).all()

        for question_position, question in enumerate(questions, start=1):
            db.add(
                TaskQuestion(
                    task_id=task.id,
                    question_id=question.id,
                    position=question_position,
                )
            )

    db.commit()
    return get_tasks_for_date(db, user, target_date)


def get_owned_task(db: Session, user: User, task_id: int) -> Task:
    task = db.get(Task, task_id)

    if task is None or task.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )

    return task


def get_task_detail(db: Session, user: User, task_id: int) -> TaskDetailOut:
    task = get_owned_task(db, user, task_id)

    if not _is_task_accessible(db, task):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Complete earlier tasks before accessing this task.",
        )

    questions = db.scalars(
        select(Question)
        .join(TaskQuestion, TaskQuestion.question_id == Question.id)
        .where(TaskQuestion.task_id == task.id)
        .order_by(TaskQuestion.position)
    ).all()

    return TaskDetailOut.model_validate(task).model_copy(
        update={
            "accessible": True,
            "questions": [QuestionPublic.model_validate(question) for question in questions],
        }
    )


def complete_task(
    db: Session,
    user: User,
    task_id: int,
    payload: TaskCompleteRequest,
) -> TaskCompleteResponse:
    task = get_owned_task(db, user, task_id)

    if task.status == "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Task is already completed.",
        )

    if task.status == "missed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missed tasks cannot be completed directly.",
        )

    if not _is_task_accessible(db, task):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Complete earlier tasks before completing this task.",
        )

    questions = db.scalars(
        select(Question)
        .join(TaskQuestion, TaskQuestion.question_id == Question.id)
        .where(TaskQuestion.task_id == task.id)
        .order_by(TaskQuestion.position)
    ).all()

    correct_count = 0

    if questions:
        expected_ids = {question.id for question in questions}
        provided_ids = {answer.question_id for answer in payload.answers}

        if expected_ids != provided_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Quiz answers are incomplete or invalid.",
            )

        answer_map = {answer.question_id: answer.selected_option for answer in payload.answers}

        for question in questions:
            if answer_map[question.id] == question.correct_option:
                correct_count += 1

        required_correct = max(1, ceil(len(questions) * 0.5))

        if correct_count < required_correct:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"At least {required_correct} correct answers are required.",
            )

    base_points = 10
    points_awarded = base_points + correct_count

    task.status = "completed"
    task.completed_at = datetime.now(timezone.utc)
    task.points_awarded = points_awarded

    economy_service.award_points(
        db=db,
        user=user,
        delta=points_awarded,
        reason="task_completed",
        reference_type="task",
        reference_id=task.id,
    )

    db.commit()
    db.refresh(task)

    return TaskCompleteResponse(
        completed=True,
        correct_count=correct_count,
        points_awarded=points_awarded,
        task=_to_task_out(task, True),
    )


def miss_task(db: Session, user: User, task_id: int) -> TaskOut:
    task = get_owned_task(db, user, task_id)

    if task.status == "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Completed tasks cannot be marked missed.",
        )

    if task.status == "missed":
        return _to_task_out(task, False)

    task.status = "missed"

    economy_service.award_points(
        db=db,
        user=user,
        delta=-5,
        reason="task_missed",
        reference_type="task",
        reference_id=task.id,
    )

    rescheduled_date = task.scheduled_date + timedelta(days=7)

    next_position = db.scalar(
        select(func.coalesce(func.max(Task.position), 0)).where(
            Task.user_id == user.id,
            Task.scheduled_date == rescheduled_date,
        )
    )

    rescheduled_task = Task(
        user_id=user.id,
        scheduled_date=rescheduled_date,
        position=next_position + 1,
        title=f"Rescheduled: {task.title}",
        subject=task.subject,
        topic=task.topic,
        notes=task.notes,
        video_url=task.video_url,
        status="scheduled",
        source_task_id=task.id,
        points_awarded=0,
    )

    db.add(rescheduled_task)
    db.commit()
    db.refresh(task)

    return _to_task_out(task, False)
```

```python
# backend/app/services/question_service.py

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.question import Question
from app.models.user import User
from app.schemas.question import QuestionCreate, QuestionUpdate


def create_question(db: Session, payload: QuestionCreate, admin: User) -> Question:
    question = Question(
        **payload.model_dump(),
        created_by=admin.id,
    )

    db.add(question)
    db.commit()
    db.refresh(question)
    return question


def list_questions(db: Session) -> list[Question]:
    return db.scalars(select(Question).order_by(Question.id.desc())).all()


def get_question(db: Session, question_id: int) -> Question:
    question = db.get(Question, question_id)

    if question is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Question not found.",
        )

    return question


def update_question(db: Session, question_id: int, payload: QuestionUpdate) -> Question:
    question = get_question(db, question_id)

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(question, field, value)

    db.commit()
    db.refresh(question)
    return question


def delete_question(db: Session, question_id: int) -> None:
    question = get_question(db, question_id)
    db.delete(question)
    db.commit()
```

```python
# backend/app/services/battle_service.py

from datetime import datetime, timezone
from typing import List

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.battle import Battle, BattleQuestion
from app.models.battle_participation import BattleParticipation
from app.models.question import Question
from app.models.user import User
from app.schemas.battle import (
    BattleCreate,
    BattleOut,
    BattleParticipationOut,
    BattlePlayOut,
    BattleSubmitRequest,
    LeaderboardEntry,
    BattleResultOut,
)
from app.schemas.question import QuestionPublic
from app.services import economy_service


def _battle_out(db: Session, battle: Battle) -> BattleOut:
    player_count = db.scalar(
        select(func.count())
        .select_from(BattleParticipation)
        .where(BattleParticipation.battle_id == battle.id)
    )

    return BattleOut.model_validate(battle).model_copy(update={"player_count": player_count})


def create_battle(db: Session, payload: BattleCreate, admin: User) -> BattleOut:
    unique_question_ids = set(payload.question_ids)

    if len(unique_question_ids) != len(payload.question_ids):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Duplicate question IDs are not allowed.",
        )

    questions = db.scalars(
        select(Question).where(Question.id.in_(payload.question_ids))
    ).all()

    if len(questions) != len(payload.question_ids):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="One or more question IDs are invalid.",
        )

    battle = Battle(
        title=payload.title,
        subject=payload.subject,
        scheduled_at=payload.scheduled_at,
        duration_seconds=payload.duration_seconds,
        max_players=payload.max_players,
        status="open",
        created_by=admin.id,
    )

    db.add(battle)
    db.flush()

    for position, question_id in enumerate(payload.question_ids, start=1):
        db.add(
            BattleQuestion(
                battle_id=battle.id,
                question_id=question_id,
                position=position,
            )
        )

    db.commit()
    db.refresh(battle)

    return _battle_out(db, battle)


def list_battles(db: Session) -> List[BattleOut]:
    battles = db.scalars(
        select(Battle)
        .where(Battle.status.in_(["open", "live"]))
        .order_by(Battle.scheduled_at)
    ).all()

    return [_battle_out(db, battle) for battle in battles]


def get_battle(db: Session, battle_id: int) -> Battle:
    battle = db.get(Battle, battle_id)

    if battle is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Battle not found.",
        )

    return battle


def get_battle_out(db: Session, battle_id: int) -> BattleOut:
    return _battle_out(db, get_battle(db, battle_id))


def join_battle(db: Session, battle_id: int, user: User) -> BattleParticipationOut:
    battle = get_battle(db, battle_id)

    if battle.status not in {"open", "live"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Battle is not open for joining.",
        )

    existing = db.scalar(
        select(BattleParticipation).where(
            BattleParticipation.battle_id == battle.id,
            BattleParticipation.user_id == user.id,
        )
    )

    if existing is not None:
        return BattleParticipationOut.model_validate(existing)

    player_count = db.scalar(
        select(func.count())
        .select_from(BattleParticipation)
        .where(BattleParticipation.battle_id == battle.id)
    )

    if player_count >= battle.max_players:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Battle is full.",
        )

    participation = BattleParticipation(
        battle_id=battle.id,
        user_id=user.id,
    )

    db.add(participation)
    db.commit()
    db.refresh(participation)

    return BattleParticipationOut.model_validate(participation)


def get_play_data(db: Session, battle_id: int, user: User) -> BattlePlayOut:
    battle = get_battle(db, battle_id)

    participation = db.scalar(
        select(BattleParticipation).where(
            BattleParticipation.battle_id == battle.id,
            BattleParticipation.user_id == user.id,
        )
    )

    if participation is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Join the battle before playing.",
        )

    if battle.status == "finished":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Battle has already finished.",
        )

    questions = db.scalars(
        select(Question)
        .join(BattleQuestion, BattleQuestion.question_id == Question.id)
        .where(BattleQuestion.battle_id == battle.id)
        .order_by(BattleQuestion.position)
    ).all()

    return BattlePlayOut(
        battle=_battle_out(db, battle),
        questions=[QuestionPublic.model_validate(question) for question in questions],
        server_time=datetime.now(timezone.utc),
    )


def _build_leaderboard(db: Session, battle: Battle) -> List[LeaderboardEntry]:
    rows = db.execute(
        select(BattleParticipation, User)
        .join(User, User.id == BattleParticipation.user_id)
        .where(
            BattleParticipation.battle_id == battle.id,
            BattleParticipation.submitted_at.is_not(None),
        )
        .order_by(
            BattleParticipation.total_score.desc(),
            BattleParticipation.submitted_at.asc(),
        )
    ).all()

    entries: List[LeaderboardEntry] = []

    for index, (participation, user) in enumerate(rows, start=1):
        entries.append(
            LeaderboardEntry(
                user_id=user.id,
                full_name=user.full_name,
                total_score=participation.total_score,
                rank=participation.rank if participation.rank is not None else index,
                coins_earned=participation.coins_earned,
            )
        )

    return entries


def submit_battle(
    db: Session,
    battle_id: int,
    user: User,
    payload: BattleSubmitRequest,
) -> BattleResultOut:
    battle = get_battle(db, battle_id)

    participation = db.scalar(
        select(BattleParticipation).where(
            BattleParticipation.battle_id == battle.id,
            BattleParticipation.user_id == user.id,
        )
    )

    if participation is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Join the battle before submitting answers.",
        )

    if participation.submitted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Answers have already been submitted.",
        )

    if battle.status == "finished":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Battle has already finished.",
        )

    questions = db.scalars(
        select(Question)
        .join(BattleQuestion, BattleQuestion.question_id == Question.id)
        .where(BattleQuestion.battle_id == battle.id)
    ).all()

    question_map = {question.id: question for question in questions}

    if len(payload.answers) != len(question_map):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid number of answers.",
        )

    raw_score = 0
    time_bonus = 0
    correct_count = 0
    incorrect_count = 0
    seen_question_ids = set()

    for answer in payload.answers:
        if answer.question_id not in question_map:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Answer contains invalid question ID.",
            )

        if answer.question_id in seen_question_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Duplicate answers for the same question are not allowed.",
            )

        seen_question_ids.add(answer.question_id)
        question = question_map[answer.question_id]

        if answer.selected_option == question.correct_option:
            correct_count += 1
            raw_score += 4

            seconds = answer.time_ms / 1000
            if seconds <= 10:
                time_bonus += 3
            elif seconds <= 20:
                time_bonus += 2
            elif seconds <= 30:
                time_bonus += 1
        else:
            incorrect_count += 1
            raw_score -= 1

    total_score = max(0, raw_score + time_bonus)

    participation.submitted_at = datetime.now(timezone.utc)
    participation.correct_count = correct_count
    participation.incorrect_count = incorrect_count
    participation.raw_score = raw_score
    participation.time_bonus = time_bonus
    participation.total_score = total_score

    if battle.status == "open":
        battle.status = "live"

    economy_service.award_points(
        db=db,
        user=user,
        delta=total_score,
        reason="battle_score",
        reference_type="battle_participation",
        reference_id=participation.id,
    )

    joined_count = db.scalar(
        select(func.count())
        .select_from(BattleParticipation)
        .where(BattleParticipation.battle_id == battle.id)
    )

    submitted_count = db.scalar(
        select(func.count())
        .select_from(BattleParticipation)
        .where(
            BattleParticipation.battle_id == battle.id,
            BattleParticipation.submitted_at.is_not(None),
        )
    )

    if joined_count == submitted_count and joined_count > 0:
        battle.status = "finished"

        submitted_participations = db.scalars(
            select(BattleParticipation)
            .where(
                BattleParticipation.battle_id == battle.id,
                BattleParticipation.submitted_at.is_not(None),
            )
            .order_by(
                BattleParticipation.total_score.desc(),
                BattleParticipation.submitted_at.asc(),
            )
        ).all()

        for rank, entry in enumerate(submitted_participations, start=1):
            entry.rank = rank

            if rank == 1:
                coins = 50
            elif rank == 2:
                coins = 30
            elif rank == 3:
                coins = 20
            else:
                coins = 5

            entry.coins_earned = coins

            participant_user = db.get(User, entry.user_id)
            economy_service.award_coins(
                db=db,
                user=participant_user,
                delta=coins,
                reason="battle_reward",
                reference_type="battle_participation",
                reference_id=entry.id,
            )

    db.commit()
    db.refresh(participation)

    return BattleResultOut(
        battle_id=battle.id,
        status=battle.status,
        my_total_score=participation.total_score,
        leaderboard=_build_leaderboard(db, battle),
    )
```

---

## 3.9 API routes

```python
# backend/app/api/routes/health.py

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
```

```python
# backend/app/api/routes/auth.py

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.core.logging import log_security_event
from app.core.rate_limit import limiter
from app.core.security import create_access_token, create_refresh_token, decode_token
from app.models.user import User
from app.schemas.auth import RefreshRequest, Token, UserCreate, UserOut
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    return auth_service.register_user(db, payload)


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = auth_service.authenticate(db, form_data.username, form_data.password)

    if user is None:
        log_security_event("login_failed", username=form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    log_security_event("login_success", user_id=user.id)

    return Token(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/refresh", response_model=Token)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token.",
    )

    try:
        decoded = decode_token(payload.refresh_token)

        if decoded.get("type") != "refresh":
            raise credentials_exception

        user = db.get(User, int(decoded.get("sub")))
    except (InvalidTokenError, ValueError, TypeError):
        raise credentials_exception

    if user is None or not user.is_active:
        raise credentials_exception

    return Token(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user
```

```python
# backend/app/api/routes/routine.py

from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.schemas.routine import RoutineOut, RoutineUpsert, StudySlotOut
from app.services import routine_service

router = APIRouter(prefix="/routine", tags=["routine"])


@router.get("", response_model=RoutineOut)
def get_routine(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    routine = routine_service.get_routine(db, current_user)

    if routine is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Routine not found.",
        )

    return routine


@router.put("", response_model=RoutineOut)
def save_routine(
    payload: RoutineUpsert,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return routine_service.upsert_routine(db, current_user, payload)


@router.post("/compute-slots", response_model=list[StudySlotOut])
def compute_slots(
    target_date: date | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    routine = routine_service.get_routine(db, current_user)

    if routine is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Save a routine first.",
        )

    effective_date = target_date or datetime.now(timezone.utc).date()
    return routine_service.compute_study_slots(db, current_user, routine, effective_date)
```

```python
# backend/app/api/routes/tasks.py

from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.schemas.task import (
    TaskCompleteRequest,
    TaskCompleteResponse,
    TaskDetailOut,
    TaskOut,
)
from app.services import task_service

router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.post("/generate", response_model=list[TaskOut])
def generate_tasks(
    target_date: date | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    effective_date = target_date or datetime.now(timezone.utc).date()
    return task_service.generate_tasks_for_date(db, current_user, effective_date)


@router.get("/today", response_model=list[TaskOut])
def todays_tasks(
    target_date: date | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    effective_date = target_date or datetime.now(timezone.utc).date()
    return task_service.get_tasks_for_date(db, current_user, effective_date)


@router.get("/{task_id}", response_model=TaskDetailOut)
def task_detail(
    task_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return task_service.get_task_detail(db, current_user, task_id)


@router.post("/{task_id}/complete", response_model=TaskCompleteResponse)
def complete_task(
    task_id: int,
    payload: TaskCompleteRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return task_service.complete_task(db, current_user, task_id, payload)


@router.post("/{task_id}/miss", response_model=TaskOut)
def miss_task(
    task_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return task_service.miss_task(db, current_user, task_id)
```

```python
# backend/app/api/routes/questions.py

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_admin, get_db
from app.models.user import User
from app.schemas.question import QuestionCreate, QuestionOut, QuestionUpdate
from app.services import question_service

router = APIRouter(prefix="/questions", tags=["questions"])


@router.post("", response_model=QuestionOut, status_code=status.HTTP_201_CREATED)
def create_question(
    payload: QuestionCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    return question_service.create_question(db, payload, admin)


@router.get("", response_model=list[QuestionOut])
def list_questions(
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    return question_service.list_questions(db)


@router.put("/{question_id}", response_model=QuestionOut)
def update_question(
    question_id: int,
    payload: QuestionUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    return question_service.update_question(db, question_id, payload)


@router.delete("/{question_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_question(
    question_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    question_service.delete_question(db, question_id)
```

```python
# backend/app/api/routes/battles.py

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_admin, get_current_user, get_db
from app.core.rate_limit import limiter
from app.models.user import User
from app.schemas.battle import (
    BattleCreate,
    BattleOut,
    BattleParticipationOut,
    BattlePlayOut,
    BattleResultOut,
    BattleSubmitRequest,
)
from app.services import battle_service

router = APIRouter(prefix="/battles", tags=["battles"])


@router.post("", response_model=BattleOut, status_code=status.HTTP_201_CREATED)
def create_battle(
    payload: BattleCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    return battle_service.create_battle(db, payload, admin)


@router.get("", response_model=list[BattleOut])
def list_battles(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return battle_service.list_battles(db)


@router.get("/{battle_id}", response_model=BattleOut)
def get_battle(
    battle_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return battle_service.get_battle_out(db, battle_id)


@router.post("/{battle_id}/join", response_model=BattleParticipationOut)
@limiter.limit("10/minute")
def join_battle(
    request: Request,
    battle_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return battle_service.join_battle(db, battle_id, current_user)


@router.get("/{battle_id}/play", response_model=BattlePlayOut)
def play_battle(
    battle_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return battle_service.get_play_data(db, battle_id, current_user)


@router.post("/{battle_id}/submit", response_model=BattleResultOut)
def submit_battle(
    battle_id: int,
    payload: BattleSubmitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return battle_service.submit_battle(db, battle_id, current_user, payload)
```

```python
# backend/app/api/routes/economy.py

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.schemas.auth import UserOut
from app.services import economy_service

router = APIRouter(prefix="/economy", tags=["economy"])


@router.post("/convert", response_model=UserOut)
def convert_points(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return economy_service.convert_points_to_coins(db, current_user)
```

---

## 3.10 FastAPI application entrypoint

```python
# backend/app/main.py

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.routes import auth, battles, economy, health, questions, routine, tasks
from app.core.config import settings
from app.core.logging import setup_logging
from app.core.rate_limit import limiter

setup_logging()

app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
    docs_url="/docs" if settings.ENV != "production" else None,
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Validation failed."},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Server-side logging only. Do not leak internals to clients.
    import logging

    logging.getLogger("app").exception("Unhandled exception")

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error."},
    )


app.include_router(health.router)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(routine.router, prefix="/api/v1")
app.include_router(tasks.router, prefix="/api/v1")
app.include_router(questions.router, prefix="/api/v1")
app.include_router(battles.router, prefix="/api/v1")
app.include_router(economy.router, prefix="/api/v1")
```

---

# 4. Database Migrations

## 4.1 Alembic configuration

```ini
# backend/alembic.ini

[alembic]
script_location = alembic
prepend_sys_path = .

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
```

```python
# backend/alembic/env.py

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings
from app.db.base import Base
from app import models  # noqa: F401

config = context.config
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=settings.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = settings.DATABASE_URL

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

```mako
# backend/alembic/script.py.mako

"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}
"""

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
```

---

## 4.2 Initial migration example

```python
# backend/alembic/versions/0001_initial.py

"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-07-31
"""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=120), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("points_balance", sa.Integer(), nullable=False),
        sa.Column("coins_balance", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    op.create_table(
        "routines",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("wake_time", sa.Time(), nullable=False),
        sa.Column("sleep_time", sa.Time(), nullable=False),
        sa.Column("school_start", sa.Time(), nullable=True),
        sa.Column("school_end", sa.Time(), nullable=True),
        sa.Column("coaching_start", sa.Time(), nullable=True),
        sa.Column("coaching_end", sa.Time(), nullable=True),
        sa.Column("target_study_minutes", sa.Integer(), nullable=False),
        sa.Column("min_break_minutes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE", name=op.f("fk_routines_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_routines")),
        sa.UniqueConstraint("user_id", name=op.f("uq_routines_user_id")),
    )
    op.create_index(op.f("ix_routines_user_id"), "routines", ["user_id"], unique=False)

    op.create_table(
        "study_slots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("slot_date", sa.Date(), nullable=False),
        sa.Column("start_time", sa.Time(), nullable=False),
        sa.Column("end_time", sa.Time(), nullable=False),
        sa.Column("slot_type", sa.String(length=20), nullable=False),
        sa.Column("capacity_minutes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE", name=op.f("fk_study_slots_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_study_slots")),
        sa.UniqueConstraint("user_id", "slot_date", "start_time", name=op.f("uq_study_slots_user_date_start")),
    )
    op.create_index(op.f("ix_study_slots_user_id"), "study_slots", ["user_id"], unique=False)
    op.create_index(op.f("ix_study_slots_slot_date"), "study_slots", ["slot_date"], unique=False)

    op.create_table(
        "questions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("subject", sa.String(length=80), nullable=False),
        sa.Column("topic", sa.String(length=120), nullable=False),
        sa.Column("prompt", sa.Text(), nullable=False),
        sa.Column("option_a", sa.String(length=255), nullable=False),
        sa.Column("option_b", sa.String(length=255), nullable=False),
        sa.Column("option_c", sa.String(length=255), nullable=False),
        sa.Column("option_d", sa.String(length=255), nullable=False),
        sa.Column("correct_option", sa.String(length=1), nullable=False),
        sa.Column("difficulty", sa.String(length=20), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("correct_option IN ('A', 'B', 'C', 'D')", name=op.f("ck_questions_correct_option")),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL", name=op.f("fk_questions_created_by_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_questions")),
    )
    op.create_index(op.f("ix_questions_subject"), "questions", ["subject"], unique=False)
    op.create_index(op.f("ix_questions_topic"), "questions", ["topic"], unique=False)

    op.create_table(
        "tasks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("scheduled_date", sa.Date(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=80), nullable=False),
        sa.Column("topic", sa.String(length=120), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("video_url", sa.String(length=2048), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("points_awarded", sa.Integer(), nullable=False),
        sa.Column("source_task_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "status IN ('scheduled', 'completed', 'missed', 'rescheduled')",
            name=op.f("ck_tasks_status"),
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE", name=op.f("fk_tasks_user_id_users")),
        sa.ForeignKeyConstraint(["source_task_id"], ["tasks.id"], ondelete="SET NULL", name=op.f("fk_tasks_source_task_id_tasks")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tasks")),
        sa.UniqueConstraint("user_id", "scheduled_date", "position", name=op.f("uq_tasks_user_date_position")),
    )
    op.create_index(op.f("ix_tasks_user_id"), "tasks", ["user_id"], unique=False)
    op.create_index(op.f("ix_tasks_scheduled_date"), "tasks", ["scheduled_date"], unique=False)

    op.create_table(
        "task_questions",
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("question_id", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="CASCADE", name=op.f("fk_task_questions_task_id_tasks")),
        sa.ForeignKeyConstraint(["question_id"], ["questions.id"], ondelete="CASCADE", name=op.f("fk_task_questions_question_id_questions")),
        sa.PrimaryKeyConstraint("task_id", "question_id", name=op.f("pk_task_questions")),
    )

    op.create_table(
        "battles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=80), nullable=False),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_seconds", sa.Integer(), nullable=False),
        sa.Column("max_players", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "status IN ('open', 'live', 'finished', 'cancelled')",
            name=op.f("ck_battles_status"),
        ),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL", name=op.f("fk_battles_created_by_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_battles")),
    )

    op.create_table(
        "battle_questions",
        sa.Column("battle_id", sa.Integer(), nullable=False),
        sa.Column("question_id", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["battle_id"], ["battles.id"], ondelete="CASCADE", name=op.f("fk_battle_questions_battle_id_battles")),
        sa.ForeignKeyConstraint(["question_id"], ["questions.id"], ondelete="CASCADE", name=op.f("fk_battle_questions_question_id_questions")),
        sa.PrimaryKeyConstraint("battle_id", "question_id", name=op.f("pk_battle_questions")),
    )

    op.create_table(
        "battle_participations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("battle_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("joined_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("correct_count", sa.Integer(), nullable=False),
        sa.Column("incorrect_count", sa.Integer(), nullable=False),
        sa.Column("raw_score", sa.Integer(), nullable=False),
        sa.Column("time_bonus", sa.Integer(), nullable=False),
        sa.Column("total_score", sa.Integer(), nullable=False),
        sa.Column("coins_earned", sa.Integer(), nullable=True),
        sa.Column("leaderboard_rank", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["battle_id"], ["battles.id"], ondelete="CASCADE", name=op.f("fk_battle_participations_battle_id_battles")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE", name=op.f("fk_battle_participations_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_battle_participations")),
        sa.UniqueConstraint("battle_id", "user_id", name=op.f("uq_battle_participations_battle_user")),
    )
    op.create_index(op.f("ix_battle_participations_battle_id"), "battle_participations", ["battle_id"], unique=False)
    op.create_index(op.f("ix_battle_participations_user_id"), "battle_participations", ["user_id"], unique=False)

    op.create_table(
        "point_ledger",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("delta", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=80), nullable=False),
        sa.Column("reference_type", sa.String(length=80), nullable=True),
        sa.Column("reference_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE", name=op.f("fk_point_ledger_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_point_ledger")),
    )
    op.create_index(op.f("ix_point_ledger_user_id"), "point_ledger", ["user_id"], unique=False)

    op.create_table(
        "coin_ledger",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("delta", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=80), nullable=False),
        sa.Column("reference_type", sa.String(length=80), nullable=True),
        sa.Column("reference_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE", name=op.f("fk_coin_ledger_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_coin_ledger")),
    )
    op.create_index(op.f("ix_coin_ledger_user_id"), "coin_ledger", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_table("coin_ledger")
    op.drop_table("point_ledger")
    op.drop_table("battle_participations")
    op.drop_table("battle_questions")
    op.drop_table("battles")
    op.drop_table("task_questions")
    op.drop_table("tasks")
    op.drop_table("questions")
    op.drop_table("study_slots")
    op.drop_table("routines")
    op.drop_table("users")
```

---

# 5. Backend Tests

```python
# backend/tests/conftest.py

import os

os.environ["ENV"] = "test"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("DATABASE_URL", "sqlite://")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.core.security import hash_password
from app.db.base import Base
from app.main import app
from app.models.question import Question
from app.models.user import User

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)


@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def user_token(client):
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "student@example.com",
            "password": "Passw0rd!",
            "full_name": "Student User",
        },
    )

    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "student@example.com",
            "password": "Passw0rd!",
        },
    )

    return response.json()["access_token"]


@pytest.fixture
def admin_token(client, db):
    admin = User(
        email="admin@example.com",
        full_name="Admin User",
        hashed_password=hash_password("AdminPassw0rd!"),
        role="admin",
        is_active=True,
        points_balance=0,
        coins_balance=0,
    )

    db.add(admin)
    db.commit()

    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "admin@example.com",
            "password": "AdminPassw0rd!",
        },
    )

    return response.json()["access_token"]


@pytest.fixture
def questions(db):
    created = []

    for index in range(10):
        question = Question(
            subject="Physics",
            topic="Photoelectric Effect",
            prompt=f"Question {index}",
            option_a="Correct",
            option_b="Wrong 1",
            option_c="Wrong 2",
            option_d="Wrong 3",
            correct_option="A",
            difficulty="medium",
            created_by=None,
        )
        db.add(question)
        created.append(question)

    db.commit()

    for question in created:
        db.refresh(question)

    return created
```

```python
# backend/tests/test_auth.py

def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_register_and_login(client):
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "new@example.com",
            "password": "Passw0rd!",
            "full_name": "New User",
        },
    )

    assert register_response.status_code == 201
    assert register_response.json()["email"] == "new@example.com"

    login_response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "new@example.com",
            "password": "Passw0rd!",
        },
    )

    assert login_response.status_code == 200
    body = login_response.json()
    assert "access_token" in body
    assert "refresh_token" in body


def test_weak_password_rejected(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "weak@example.com",
            "password": "weak",
            "full_name": "Weak Password",
        },
    )

    assert response.status_code == 422


def test_duplicate_email_rejected(client):
    payload = {
        "email": "duplicate@example.com",
        "password": "Passw0rd!",
        "full_name": "Duplicate User",
    }

    first = client.post("/api/v1/auth/register", json=payload)
    second = client.post("/api/v1/auth/register", json=payload)

    assert first.status_code == 201
    assert second.status_code == 400


def test_me_requires_auth(client):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_me_returns_user(client, user_token):
    response = client.get("/api/v1/auth/me", headers=auth_header(user_token))
    assert response.status_code == 200
    assert response.json()["email"] == "student@example.com"
```

```python
# backend/tests/test_tasks.py

def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def setup_routine(client, token):
    response = client.put(
        "/api/v1/routine",
        headers=auth_header(token),
        json={
            "wake_time": "06:00",
            "sleep_time": "22:00",
            "school_start": "08:00",
            "school_end": "14:00",
            "coaching_start": "17:00",
            "coaching_end": "19:00",
            "target_study_minutes": 150,
            "min_break_minutes": 10,
        },
    )

    assert response.status_code == 200


def test_task_gating(client, user_token, questions):
    setup_routine(client, user_token)

    generate_response = client.post(
        "/api/v1/tasks/generate",
        headers=auth_header(user_token),
    )

    assert generate_response.status_code == 200
    tasks = generate_response.json()
    assert len(tasks) >= 2

    task_one = tasks[0]
    task_two = tasks[1]

    blocked_response = client.post(
        f"/api/v1/tasks/{task_two['id']}/complete",
        headers=auth_header(user_token),
        json={"answers": []},
    )

    assert blocked_response.status_code == 403

    detail_response = client.get(
        f"/api/v1/tasks/{task_one['id']}",
        headers=auth_header(user_token),
    )

    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["accessible"] is True
    assert len(detail["questions"]) > 0

    answers = [
        {"question_id": question["id"], "selected_option": "A"}
        for question in detail["questions"]
    ]

    complete_response = client.post(
        f"/api/v1/tasks/{task_one['id']}/complete",
        headers=auth_header(user_token),
        json={"answers": answers},
    )

    assert complete_response.status_code == 200
    assert complete_response.json()["completed"] is True

    task_two_detail = client.get(
        f"/api/v1/tasks/{task_two['id']}",
        headers=auth_header(user_token),
    )

    assert task_two_detail.status_code == 200
    assert task_two_detail.json()["accessible"] is True
```

```python
# backend/tests/test_battles.py

from datetime import datetime, timedelta, timezone


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_battle_scoring_and_leaderboard(client, admin_token, user_token, questions):
    question_ids = [question.id for question in questions[:10]]

    create_response = client.post(
        "/api/v1/battles",
        headers=auth_header(admin_token),
        json={
            "title": "Physics Battle",
            "subject": "Physics",
            "scheduled_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "duration_seconds": 1200,
            "max_players": 20,
            "question_ids": question_ids,
        },
    )

    assert create_response.status_code == 201
    battle = create_response.json()

    join_response = client.post(
        f"/api/v1/battles/{battle['id']}/join",
        headers=auth_header(user_token),
    )

    assert join_response.status_code == 200

    play_response = client.get(
        f"/api/v1/battles/{battle['id']}/play",
        headers=auth_header(user_token),
    )

    assert play_response.status_code == 200
    play_data = play_response.json()
    assert len(play_data["questions"]) == 10

    answers = [
        {
            "question_id": question["id"],
            "selected_option": "A",
            "time_ms": 5000,
        }
        for question in play_data["questions"]
    ]

    submit_response = client.post(
        f"/api/v1/battles/{battle['id']}/submit",
        headers=auth_header(user_token),
        json={"answers": answers},
    )

    assert submit_response.status_code == 200
    result = submit_response.json()

    # 10 correct answers:
    # correctness = 10 * 4 = 40
    # time bonus = 10 * 3 = 30
    # total = 70
    assert result["my_total_score"] == 70
    assert result["status"] == "finished"
    assert result["leaderboard"][0]["coins_earned"] == 50
```

---

# 6. Frontend Code

## 6.1 Frontend package manifest

```json
{
  "name": "study-platform-frontend",
  "version": "1.0.0",
  "private": true,
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "node --watch server.js"
  },
  "dependencies": {
    "axios": "^1.7.9",
    "cookie-parser": "^1.4.7",
    "dotenv": "^16.4.7",
    "ejs": "^3.1.10",
    "express": "^4.21.2",
    "express-rate-limit": "^7.5.0",
    "express-validator": "^7.2.1",
    "helmet": "^8.0.0"
  }
}
```

---

## 6.2 Frontend environment sample

```bash
# frontend/.env.example

NODE_ENV=development
PORT=3000

# Used by server-side API client.
# For Docker Compose internal network, use:
# API_BASE_URL=http://backend:8000
API_BASE_URL=http://localhost:8000

# Generate with:
# node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
COOKIE_SECRET=CHANGE_ME
```

---

## 6.3 Frontend config

```javascript
// frontend/src/config.js

require("dotenv").config();

const nodeEnv = process.env.NODE_ENV || "development";

const config = {
  nodeEnv,
  isProduction: nodeEnv === "production",
  port: parseInt(process.env.PORT || "3000", 10),
  apiBaseUrl: process.env.API_BASE_URL || "http://localhost:8000",
  cookieSecret: process.env.COOKIE_SECRET,
  secureCookies: nodeEnv === "production",
};

if (config.isProduction && (!config.cookieSecret || config.cookieSecret === "CHANGE_ME")) {
  throw new Error("COOKIE_SECRET must be set to a strong value in production.");
}

module.exports = config;
```

---

## 6.4 Express server

```javascript
// frontend/server.js

const path = require("path");
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");

const config = require("./src/config");
const csrfMiddleware = require("./src/middleware/csrf");
const authRouter = require("./src/routes/auth");
const dashboardRouter = require("./src/routes/dashboard");
const battlesRouter = require("./src/routes/battles");
const { notFoundHandler, errorHandler } = require("./src/middleware/error");

const app = express();

app.set("trust proxy", 1);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "src", "views"));

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "same-site" },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: { action: "deny" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  })
);

app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser(config.cookieSecret));

app.use(
  "/static",
  express.static(path.join(__dirname, "src", "public"), {
    maxAge: "1d",
    immutable: false,
  })
);

app.use(csrfMiddleware);

app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken;
  res.locals.currentPath = req.path;
  next();
});

app.use("/", authRouter);
app.use("/", dashboardRouter);
app.use("/", battlesRouter);

app.get("/", (req, res) => {
  res.redirect("/dashboard");
});

app.use(notFoundHandler);
app.use(errorHandler);

app.listen(config.port, () => {
  console.log(`Frontend listening on port ${config.port}`);
});
```

---

## 6.5 Middleware

```javascript
// frontend/src/middleware/csrf.js

const crypto = require("crypto");
const config = require("../config");

function unsafeMethod(method) {
  return ["POST", "PUT", "PATCH", "DELETE"].includes(method);
}

function tokensMatch(provided, expected) {
  if (typeof provided !== "string" || typeof expected !== "string") {
    return false;
  }

  if (provided.length !== expected.length) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
}

module.exports = function csrfMiddleware(req, res, next) {
  let token = req.cookies.csrf_token;

  if (!token) {
    token = crypto.randomBytes(32).toString("hex");

    res.cookie("csrf_token", token, {
      httpOnly: true,
      secure: config.secureCookies,
      sameSite: "strict",
    });
  }

  req.csrfToken = token;

  if (unsafeMethod(req.method)) {
    const provided = req.get("x-csrf-token") || req.body._csrf;

    if (!tokensMatch(provided, req.cookies.csrf_token)) {
      return res.status(403).send("Invalid CSRF token.");
    }
  }

  next();
};
```

```javascript
// frontend/src/middleware/auth.js

const api = require("../lib/api");

async function requireAuth(req, res, next) {
  const token = req.cookies.access_token;

  if (!token) {
    return res.redirect("/login");
  }

  try {
    const user = await api.getMe(token);
    res.locals.currentUser = user;
    res.locals.accessToken = token;
    next();
  } catch (error) {
    if (error.status === 401) {
      res.clearCookie("access_token");
      res.clearCookie("refresh_token", { path: "/" });
      return res.redirect("/login");
    }

    next(error);
  }
}

function requireAnonymous(req, res, next) {
  if (req.cookies.access_token) {
    return res.redirect("/dashboard");
  }

  next();
}

module.exports = {
  requireAuth,
  requireAnonymous,
};
```

```javascript
// frontend/src/middleware/validation.js

const { body, validationResult } = require("express-validator");

const passwordRules = body("password")
  .isLength({ min: 8, max: 128 })
  .withMessage("Password must be at least 8 characters.")
  .matches(/[a-z]/)
  .withMessage("Password must include a lowercase letter.")
  .matches(/[A-Z]/)
  .withMessage("Password must include an uppercase letter.")
  .matches(/[0-9]/)
  .withMessage("Password must include a number.");

const loginValidation = [
  body("email").isEmail().normalizeEmail(),
  passwordRules,
];

const registerValidation = [
  body("email").isEmail().normalizeEmail(),
  body("full_name").trim().isLength({ min: 2, max: 120 }).escape(),
  passwordRules,
  body("confirm_password").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Passwords do not match.");
    }
    return true;
  }),
];

function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const view = req.path.includes("register") ? "register" : "login";

    return res.status(400).render(view, {
      errors: errors.array(),
      values: req.body,
    });
  }

  next();
}

module.exports = {
  loginValidation,
  registerValidation,
  handleValidationErrors,
};
```

```javascript
// frontend/src/middleware/error.js

function notFoundHandler(req, res) {
  res.status(404).send("Not found.");
}

function errorHandler(err, req, res, next) {
  console.error(err);

  if (err.type === "entity.parse.failed") {
    return res.status(400).send("Invalid request body.");
  }

  res.status(err.status || 500).send("Unexpected error.");
}

module.exports = {
  notFoundHandler,
  errorHandler,
};
```

---

## 6.6 Secure API client

```javascript
// frontend/src/lib/api.js

const axios = require("axios");
const config = require("../config");

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function messageFromDetail(detail) {
  if (typeof detail === "string") {
    return detail;
  }

  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg || "Validation error.").join(" ");
  }

  return "Request failed.";
}

async function request(path, { method = "GET", token = null, data = null, headers = {} } = {}) {
  const finalHeaders = { ...headers };

  if (token) {
    finalHeaders.Authorization = `Bearer ${token}`;
  }

  try {
    const response = await axios({
      url: `${config.apiBaseUrl}${path}`,
      method,
      data,
      headers: finalHeaders,
      timeout: 10000,
      validateStatus: () => true,
    });

    if (response.status >= 500) {
      throw new ApiError(502, "Upstream API error.");
    }

    if (response.status >= 400) {
      throw new ApiError(response.status, messageFromDetail(response.data?.detail));
    }

    return response.data;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }

    throw new ApiError(502, "Unable to reach API.");
  }
}

function register({ email, password, full_name }) {
  return request("/api/v1/auth/register", {
    method: "POST",
    data: { email, password, full_name },
  });
}

function login(email, password) {
  const params = new URLSearchParams();
  params.append("username", email);
  params.append("password", password);

  return request("/api/v1/auth/login", {
    method: "POST",
    data: params,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
  });
}

function getMe(token) {
  return request("/api/v1/auth/me", { token });
}

function saveRoutine(token, payload) {
  return request("/api/v1/routine", {
    method: "PUT",
    token,
    data: payload,
  });
}

function getRoutine(token) {
  return request("/api/v1/routine", { token });
}

function computeSlots(token) {
  return request("/api/v1/routine/compute-slots", {
    method: "POST",
    token,
  });
}

function generateTasks(token) {
  return request("/api/v1/tasks/generate", {
    method: "POST",
    token,
  });
}

function getTodayTasks(token) {
  return request("/api/v1/tasks/today", { token });
}

function getTask(token, taskId) {
  return request(`/api/v1/tasks/${taskId}`, { token });
}

function completeTask(token, taskId, answers) {
  return request(`/api/v1/tasks/${taskId}/complete`, {
    method: "POST",
    token,
    data: { answers },
  });
}

function missTask(token, taskId) {
  return request(`/api/v1/tasks/${taskId}/miss`, {
    method: "POST",
    token,
  });
}

function listBattles(token) {
  return request("/api/v1/battles", { token });
}

function getBattle(token, battleId) {
  return request(`/api/v1/battles/${battleId}`, { token });
}

function joinBattle(token, battleId) {
  return request(`/api/v1/battles/${battleId}/join`, {
    method: "POST",
    token,
  });
}

function getBattlePlay(token, battleId) {
  return request(`/api/v1/battles/${battleId}/play`, { token });
}

function submitBattle(token, battleId, answers) {
  return request(`/api/v1/battles/${battleId}/submit`, {
    method: "POST",
    token,
    data: { answers },
  });
}

module.exports = {
  ApiError,
  register,
  login,
  getMe,
  saveRoutine,
  getRoutine,
  computeSlots,
  generateTasks,
  getTodayTasks,
  getTask,
  completeTask,
  missTask,
  listBattles,
  getBattle,
  joinBattle,
  getBattlePlay,
  submitBattle,
};
```

---

## 6.7 Frontend routes

```javascript
// frontend/src/routes/auth.js

const express = require("express");
const rateLimit = require("express-rate-limit");

const api = require("../lib/api");
const config = require("../config");
const { requireAnonymous } = require("../middleware/auth");
const {
  loginValidation,
  registerValidation,
  handleValidationErrors,
} = require("../middleware/validation");

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many login attempts. Try again later.",
});

const cookieOptions = {
  httpOnly: true,
  secure: config.secureCookies,
  sameSite: "strict",
};

router.get("/login", requireAnonymous, (req, res) => {
  res.render("login", { errors: [], values: {} });
});

router.post(
  "/login",
  requireAnonymous,
  loginLimiter,
  loginValidation,
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const tokens = await api.login(req.body.email, req.body.password);

      res.cookie("access_token", tokens.access_token, {
        ...cookieOptions,
        maxAge: 30 * 60 * 1000,
      });

      res.cookie("refresh_token", tokens.refresh_token, {
        ...cookieOptions,
        path: "/",
        maxAge: 14 * 24 * 60 * 60 * 1000,
      });

      res.redirect("/dashboard");
    } catch (error) {
      if (error.status === 401 || error.status === 400) {
        return res.status(401).render("login", {
          errors: [{ msg: "Invalid email or password." }],
          values: req.body,
        });
      }

      next(error);
    }
  }
);

router.get("/register", requireAnonymous, (req, res) => {
  res.render("register", { errors: [], values: {} });
});

router.post(
  "/register",
  requireAnonymous,
  registerValidation,
  handleValidationErrors,
  async (req, res, next) => {
    try {
      await api.register({
        email: req.body.email,
        password: req.body.password,
        full_name: req.body.full_name,
      });

      res.redirect("/login");
    } catch (error) {
      if (error.status === 400 || error.status === 422) {
        return res.status(400).render("register", {
          errors: [{ msg: error.message }],
          values: req.body,
        });
      }

      next(error);
    }
  }
);

router.post("/logout", (req, res) => {
  res.clearCookie("access_token");
  res.clearCookie("refresh_token", { path: "/" });
  res.redirect("/login");
});

module.exports = router;
```

```javascript
// frontend/src/routes/dashboard.js

const express = require("express");

const api = require("../lib/api");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

router.get("/dashboard", requireAuth, async (req, res, next) => {
  try {
    const token = res.locals.accessToken;

    const [tasks, routine] = await Promise.all([
      api.getTodayTasks(token).catch(() => []),
      api.getRoutine(token).catch(() => null),
    ]);

    res.render("dashboard", {
      user: res.locals.currentUser,
      tasks,
      routine,
    });
  } catch (error) {
    next(error);
  }
});

router.post("/routine", requireAuth, async (req, res, next) => {
  try {
    const token = res.locals.accessToken;

    const payload = {
      wake_time: req.body.wake_time,
      sleep_time: req.body.sleep_time,
      school_start: req.body.school_start || null,
      school_end: req.body.school_end || null,
      coaching_start: req.body.coaching_start || null,
      coaching_end: req.body.coaching_end || null,
      target_study_minutes: parseInt(req.body.target_study_minutes || "180", 10),
      min_break_minutes: parseInt(req.body.min_break_minutes || "10", 10),
    };

    await api.saveRoutine(token, payload);
    await api.computeSlots(token);
    await api.generateTasks(token);

    res.redirect("/dashboard");
  } catch (error) {
    next(error);
  }
});

router.post("/tasks/generate", requireAuth, async (req, res, next) => {
  try {
    await api.generateTasks(res.locals.accessToken);
    res.redirect("/dashboard");
  } catch (error) {
    next(error);
  }
});

router.get("/tasks/:id/json", requireAuth, async (req, res) => {
  try {
    const task = await api.getTask(res.locals.accessToken, req.params.id);
    res.json(task);
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message });
  }
});

router.post("/tasks/:id/complete", requireAuth, async (req, res) => {
  try {
    const result = await api.completeTask(
      res.locals.accessToken,
      req.params.id,
      req.body.answers || []
    );

    res.json(result);
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message });
  }
});

router.post("/tasks/:id/miss", requireAuth, async (req, res) => {
  try {
    const result = await api.missTask(res.locals.accessToken, req.params.id);
    res.json(result);
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message });
  }
});

module.exports = router;
```

```javascript
// frontend/src/routes/battles.js

const express = require("express");

const api = require("../lib/api");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

router.get("/battles", requireAuth, async (req, res, next) => {
  try {
    const battles = await api.listBattles(res.locals.accessToken);
    res.render("battle-lobby", {
      user: res.locals.currentUser,
      battles,
    });
  } catch (error) {
    next(error);
  }
});

router.post("/battles/:id/join", requireAuth, async (req, res) => {
  try {
    const participation = await api.joinBattle(res.locals.accessToken, req.params.id);
    res.json(participation);
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message });
  }
});

router.get("/battles/:id/play", requireAuth, async (req, res, next) => {
  try {
    const battle = await api.getBattle(res.locals.accessToken, req.params.id);

    res.render("battle-play", {
      user: res.locals.currentUser,
      battle,
    });
  } catch (error) {
    next(error);
  }
});

router.get("/battles/:id/play/json", requireAuth, async (req, res) => {
  try {
    const playData = await api.getBattlePlay(res.locals.accessToken, req.params.id);
    res.json(playData);
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message });
  }
});

router.post("/battles/:id/submit", requireAuth, async (req, res) => {
  try {
    const result = await api.submitBattle(
      res.locals.accessToken,
      req.params.id,
      req.body.answers || []
    );

    res.json(result);
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message });
  }
});

module.exports = router;
```

---

## 6.8 Views

```html
<!-- frontend/src/views/partials/head.ejs -->
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Study Platform</title>
    <link rel="stylesheet" href="/static/css/app.css" />
    <meta name="csrf-token" content="<%= csrfToken %>" />
  </head>
  <body>
```

```html
<!-- frontend/src/views/partials/header.ejs -->
<header class="site-header">
  <div class="container">
    <strong>Study Platform</strong>

    <nav>
      <a href="/dashboard">Dashboard</a>
      <a href="/battles">Battle Lobby</a>

      <% if (typeof currentUser !== "undefined" && currentUser) { %>
        <span>Signed in as <%= currentUser.full_name %></span>
        <form method="POST" action="/logout" class="inline-form">
          <input type="hidden" name="_csrf" value="<%= csrfToken %>" />
          <button type="submit">Logout</button>
        </form>
      <% } %>
    </nav>
  </div>
</header>
```

```html
<!-- frontend/src/views/partials/footer.ejs -->
<footer class="site-footer">
  <div class="container">
    <small>Secure MVP foundation. Content can be replaced with real curriculum data.</small>
  </div>
</footer>

<% if (typeof scripts !== "undefined" && scripts.length) { %>
  <% scripts.forEach(function(src) { %>
    <script src="<%= src %>" defer></script>
  <% }); %>
<% } %>

</body>
</html>
```

```html
<!-- frontend/src/views/login.ejs -->
<%- include("partials/head") %>
<%- include("partials/header", { currentUser: null }) %>

<main class="container">
  <h1>Login</h1>

  <% if (errors && errors.length) { %>
    <div class="alert error"><%= errors[0].msg %></div>
  <% } %>

  <form method="POST" action="/login" class="stack">
    <input type="hidden" name="_csrf" value="<%= csrfToken %>" />

    <label>
      Email
      <input type="email" name="email" value="<%= values.email || "" %>" required />
    </label>

    <label>
      Password
      <input type="password" name="password" required />
    </label>

    <button type="submit">Login</button>
  </form>

  <p><a href="/register">Create an account</a></p>
</main>

<%- include("partials/footer") %>
```

```html
<!-- frontend/src/views/register.ejs -->
<%- include("partials/head") %>
<%- include("partials/header", { currentUser: null }) %>

<main class="container">
  <h1>Register</h1>

  <% if (errors && errors.length) { %>
    <div class="alert error"><%= errors[0].msg %></div>
  <% } %>

  <form method="POST" action="/register" class="stack">
    <input type="hidden" name="_csrf" value="<%= csrfToken %>" />

    <label>
      Full name
      <input type="text" name="full_name" value="<%= values.full_name || "" %>" required />
    </label>

    <label>
      Email
      <input type="email" name="email" value="<%= values.email || "" %>" required />
    </label>

    <label>
      Password
      <input type="password" name="password" required />
    </label>

    <label>
      Confirm password
      <input type="password" name="confirm_password" required />
    </label>

    <button type="submit">Register</button>
  </form>

  <p><a href="/login">Already have an account? Login</a></p>
</main>

<%- include("partials/footer") %>
```

```html
<!-- frontend/src/views/dashboard.ejs -->
<%- include("partials/head") %>
<%- include("partials/header", { currentUser: user }) %>

<main class="container">
  <h1>Dashboard</h1>

  <section class="card">
    <h2>Daily Routine</h2>

    <form method="POST" action="/routine" class="grid">
      <input type="hidden" name="_csrf" value="<%= csrfToken %>" />

      <label>
        Wake time
        <input type="time" name="wake_time" value="<%= routine ? routine.wake_time.slice(0, 5) : "06:00" %>" required />
      </label>

      <label>
        Sleep time
        <input type="time" name="sleep_time" value="<%= routine ? routine.sleep_time.slice(0, 5) : "22:00" %>" required />
      </label>

      <label>
        School start
        <input type="time" name="school_start" value="<%= routine && routine.school_start ? routine.school_start.slice(0, 5) : "" %>" />
      </label>

      <label>
        School end
        <input type="time" name="school_end" value="<%= routine && routine.school_end ? routine.school_end.slice(0, 5) : "" %>" />
      </label>

      <label>
        Coaching start
        <input type="time" name="coaching_start" value="<%= routine && routine.coaching_start ? routine.coaching_start.slice(0, 5) : "" %>" />
      </label>

      <label>
        Coaching end
        <input type="time" name="coaching_end" value="<%= routine && routine.coaching_end ? routine.coaching_end.slice(0, 5) : "" %>" />
      </label>

      <label>
        Target study minutes
        <input type="number" name="target_study_minutes" min="60" max="720" value="<%= routine ? routine.target_study_minutes : 180 %>" required />
      </label>

      <label>
        Break minutes
        <input type="number" name="min_break_minutes" min="0" max="120" value="<%= routine ? routine.min_break_minutes : 10 %>" required />
      </label>

      <button type="submit">Save Routine and Generate Tasks</button>
    </form>
  </section>

  <section class="card">
    <h2>Today's Tasks</h2>

    <form method="POST" action="/tasks/generate">
      <input type="hidden" name="_csrf" value="<%= csrfToken %>" />
      <button type="submit">Generate Today's Tasks</button>
    </form>

    <ol id="task-list">
      <% tasks.forEach(function(task) { %>
        <li
          class="task-item"
          data-task-id="<%= task.id %>"
          data-accessible="<%= task.accessible %>"
          data-status="<%= task.status %>"
        >
          <strong>Task <%= task.position %></strong>
          <span><%= task.title %></span>
          <span class="badge"><%= task.status %></span>

          <% if (task.accessible && task.status !== "completed") { %>
            <button type="button" class="open-task">Open</button>
            <button type="button" class="miss-task">Mark Missed</button>
          <% } %>
        </li>
      <% }); %>
    </ol>
  </section>

  <section id="task-modal" class="modal" hidden>
    <div class="modal-content">
      <button type="button" id="close-modal">Close</button>
      <div id="task-detail"></div>

      <form id="quiz-form"></form>

      <div id="task-message" class="alert" hidden></div>

      <button type="button" id="complete-task">Complete Task</button>
    </div>
  </section>
</main>

<%- include("partials/footer", { scripts: ["/static/js/dashboard.js"] }) %>
```

```html
<!-- frontend/src/views/battle-lobby.ejs -->
<%- include("partials/head") %>
<%- include("partials/header", { currentUser: user }) %>

<main class="container">
  <h1>Battle Lobby</h1>

  <section class="card">
    <% if (!battles.length) { %>
      <p>No open battles right now.</p>
    <% } %>

    <ul id="battle-list">
      <% battles.forEach(function(battle) { %>
        <li class="battle-item" data-battle-id="<%= battle.id %>">
          <strong><%= battle.title %></strong>
          <span><%= battle.subject %></span>
          <span>Players: <%= battle.player_count %>/<%= battle.max_players %></span>
          <span class="badge"><%= battle.status %></span>

          <button type="button" class="join-battle">Join</button>
          <a href="/battles/<%= battle.id %>/play">Play</a>
        </li>
      <% }); %>
    </ul>
  </section>
</main>

<%- include("partials/footer", { scripts: ["/static/js/battle.js"] }) %>
```

```html
<!-- frontend/src/views/battle-play.ejs -->
<%- include("partials/head") %>
<%- include("partials/header", { currentUser: user }) %>

<main class="container" data-battle-id="<%= battle.id %>">
  <h1><%= battle.title %></h1>

  <section class="card">
    <div id="battle-status">Loading battle...</div>
    <div id="battle-question"></div>

    <div class="actions">
      <button type="button" id="next-question" hidden>Next</button>
      <button type="button" id="submit-battle" hidden>Submit Battle</button>
    </div>

    <div id="battle-result"></div>
  </section>
</main>

<%- include("partials/footer", { scripts: ["/static/js/battle.js"] }) %>
```

---

## 6.9 Static assets

```css
/* frontend/src/public/css/app.css */

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: Arial, Helvetica, sans-serif;
  background: #f6f8fb;
  color: #1f2933;
}

.container {
  max-width: 980px;
  margin: 0 auto;
  padding: 16px;
}

.site-header {
  background: #102a43;
  color: white;
  padding: 12px 0;
}

.site-header .container {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.site-header a {
  color: #d9e2ec;
  margin-right: 12px;
  text-decoration: none;
}

.site-header nav {
  display: flex;
  align-items: center;
  gap: 12px;
}

.inline-form {
  display: inline;
}

.card {
  background: white;
  border: 1px solid #d9e2ec;
  border-radius: 10px;
  padding: 16px;
  margin: 16px 0;
}

.stack {
  display: flex;
  flex-direction: column;
  gap: 12px;
  max-width: 420px;
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
}

label {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 14px;
}

input,
button {
  padding: 10px;
  border-radius: 8px;
  border: 1px solid #bcccdc;
  font-size: 14px;
}

button {
  cursor: pointer;
  background: #2b6cb0;
  color: white;
  border: 1px solid #2c5282;
}

button:hover {
  background: #2c5282;
}

.badge {
  display: inline-block;
  padding: 4px 8px;
  border-radius: 999px;
  background: #e2e8f0;
  font-size: 12px;
}

.alert {
  padding: 10px 12px;
  border-radius: 8px;
  margin: 10px 0;
}

.alert.error {
  background: #fff5f5;
  border: 1px solid #feb2b2;
  color: #9b2c2c;
}

.alert.success {
  background: #f0fff4;
  border: 1px solid #9ae6b4;
  color: #276749;
}

.task-item,
.battle-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 0;
  border-bottom: 1px solid #e2e8f0;
}

.modal {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.55);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-content {
  width: min(720px, 92vw);
  max-height: 84vh;
  overflow: auto;
  background: white;
  border-radius: 12px;
  padding: 18px;
}

.question-block {
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  padding: 12px;
  margin: 12px 0;
}
```

```javascript
// frontend/src/public/js/dashboard.js

function getCsrfToken() {
  return document.querySelector('meta[name="csrf-token"]').content;
}

function jsonHeaders() {
  return {
    "Content-Type": "application/json",
    "X-CSRF-Token": getCsrfToken(),
  };
}

function showMessage(element, message, type) {
  element.hidden = false;
  element.textContent = message;
  element.className = `alert ${type}`;
}

const modal = document.getElementById("task-modal");
const detailContainer = document.getElementById("task-detail");
const quizForm = document.getElementById("quiz-form");
const messageBox = document.getElementById("task-message");
const closeButton = document.getElementById("close-modal");
const completeButton = document.getElementById("complete-task");

let activeTaskId = null;

function renderTaskDetail(task) {
  detailContainer.textContent = "";

  const title = document.createElement("h3");
  title.textContent = task.title;

  const subject = document.createElement("p");
  subject.textContent = `Subject: ${task.subject}`;

  const notes = document.createElement("p");
  notes.textContent = task.notes;

  detailContainer.append(title, subject, notes);

  quizForm.textContent = "";

  task.questions.forEach((question) => {
    const block = document.createElement("div");
    block.className = "question-block";

    const prompt = document.createElement("p");
    prompt.textContent = question.prompt;

    block.appendChild(prompt);

    ["A", "B", "C", "D"].forEach((optionKey) => {
      const optionValue = question[`option_${optionKey.toLowerCase()}`];

      const label = document.createElement("label");

      const input = document.createElement("input");
      input.type = "radio";
      input.name = `question-${question.id}`;
      input.value = optionKey;
      input.required = true;

      label.appendChild(input);
      label.appendChild(document.createTextNode(` ${optionKey}. ${optionValue}`));

      block.appendChild(label);
    });

    quizForm.appendChild(block);
  });
}

async function openTask(taskId) {
  activeTaskId = taskId;
  messageBox.hidden = true;

  const response = await fetch(`/tasks/${taskId}/json`);

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    alert(body.message || "Unable to open task.");
    return;
  }

  const task = await response.json();
  renderTaskDetail(task);
  modal.hidden = false;
}

async function completeTask() {
  if (!activeTaskId) {
    return;
  }

  const answers = [];

  quizForm.querySelectorAll(".question-block").forEach((block, index) => {
    const checked = block.querySelector("input:checked");

    if (checked) {
      const questionId = parseInt(checked.name.replace("question-", ""), 10);

      answers.push({
        question_id: questionId,
        selected_option: checked.value,
      });
    }
  });

  const response = await fetch(`/tasks/${activeTaskId}/complete`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({ answers }),
  });

  const body = await response.json().catch(() => ({}));

  if (!response.ok) {
    showMessage(messageBox, body.message || "Unable to complete task.", "error");
    return;
  }

  showMessage(
    messageBox,
    `Task completed. Correct answers: ${body.correct_count}. Points awarded: ${body.points_awarded}.`,
    "success"
  );

  setTimeout(() => window.location.reload(), 1200);
}

async function missTask(taskId) {
  const response = await fetch(`/tasks/${taskId}/miss`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({}),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    alert(body.message || "Unable to mark task missed.");
    return;
  }

  window.location.reload();
}

document.addEventListener("click", (event) => {
  const openButton = event.target.closest(".open-task");
  if (openButton) {
    const taskItem = openButton.closest(".task-item");
    openTask(taskItem.dataset.taskId);
    return;
  }

  const missButton = event.target.closest(".miss-task");
  if (missButton) {
    const taskItem = missButton.closest(".task-item");
    missTask(taskItem.dataset.taskId);
  }
});

if (closeButton) {
  closeButton.addEventListener("click", () => {
    modal.hidden = true;
  });
}

if (completeButton) {
  completeButton.addEventListener("click", completeTask);
}
```

```javascript
// frontend/src/public/js/battle.js

function getCsrfToken() {
  return document.querySelector('meta[name="csrf-token"]').content;
}

function jsonHeaders() {
  return {
    "Content-Type": "application/json",
    "X-CSRF-Token": getCsrfToken(),
  };
}

const main = document.querySelector("main[data-battle-id]");

if (main) {
  const battleId = main.dataset.battleId;

  const statusBox = document.getElementById("battle-status");
  const questionBox = document.getElementById("battle-question");
  const nextButton = document.getElementById("next-question");
  const submitButton = document.getElementById("submit-battle");
  const resultBox = document.getElementById("battle-result");

  let questions = [];
  let currentIndex = 0;
  let questionStartedAt = null;
  const answers = [];

  function renderQuestion() {
    const question = questions[currentIndex];
    questionStartedAt = Date.now();

    questionBox.textContent = "";

    const title = document.createElement("h3");
    title.textContent = `Question ${currentIndex + 1} of ${questions.length}`;

    const prompt = document.createElement("p");
    prompt.textContent = question.prompt;

    questionBox.append(title, prompt);

    ["A", "B", "C", "D"].forEach((optionKey) => {
      const optionText = question[`option_${optionKey.toLowerCase()}`];

      const label = document.createElement("label");

      const input = document.createElement("input");
      input.type = "radio";
      input.name = "battle-answer";
      input.value = optionKey;

      label.appendChild(input);
      label.appendChild(document.createTextNode(` ${optionKey}. ${optionText}`));

      questionBox.appendChild(label);
    });

    nextButton.hidden = currentIndex === questions.length - 1;
    submitButton.hidden = currentIndex !== questions.length - 1;
  }

  function collectCurrentAnswer() {
    const selected = questionBox.querySelector('input[name="battle-answer"]:checked');

    if (!selected) {
      alert("Select an answer first.");
      return null;
    }

    const timeMs = Date.now() - questionStartedAt;

    return {
      question_id: questions[currentIndex].id,
      selected_option: selected.value,
      time_ms: timeMs,
    };
  }

  async function loadBattle() {
    const response = await fetch(`/battles/${battleId}/play/json`);

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      statusBox.textContent = body.message || "Unable to load battle.";
      return;
    }

    const data = await response.json();
    questions = data.questions;

    statusBox.textContent = `Battle loaded. ${questions.length} questions.`;
    renderQuestion();
  }

  nextButton.addEventListener("click", () => {
    const answer = collectCurrentAnswer();

    if (!answer) {
      return;
    }

    answers.push(answer);
    currentIndex += 1;
    renderQuestion();
  });

  submitButton.addEventListener("click", async () => {
    const answer = collectCurrentAnswer();

    if (!answer) {
      return;
    }

    answers.push(answer);

    const response = await fetch(`/battles/${battleId}/submit`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({ answers }),
    });

    const body = await response.json().catch(() => ({}));

    if (!response.ok) {
      resultBox.textContent = body.message || "Unable to submit battle.";
      return;
    }

    resultBox.textContent = "";

    const score = document.createElement("p");
    score.textContent = `Your score: ${body.my_total_score}`;

    const list = document.createElement("ol");

    body.leaderboard.forEach((entry) => {
      const item = document.createElement("li");
      item.textContent = `${entry.full_name} — ${entry.total_score} points`;
      list.appendChild(item);
    });

    resultBox.append(score, list);
  });

  loadBattle();
}

document.addEventListener("click", async (event) => {
  const joinButton = event.target.closest(".join-battle");

  if (!joinButton) {
    return;
  }

  const battleItem = joinButton.closest(".battle-item");
  const battleId = battleItem.dataset.battleId;

  const response = await fetch(`/battles/${battleId}/join`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({}),
  });

  const body = await response.json().catch(() => ({}));

  if (!response.ok) {
    alert(body.message || "Unable to join battle.");
    return;
  }

  window.location.href = `/battles/${battleId}/play`;
});
```

---

# 7. Docker Compose and Deployment Basics

## 7.1 Backend Dockerfile

```dockerfile
# backend/Dockerfile

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential libpq-dev curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m appuser && chown -R appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 7.2 Frontend Dockerfile

```dockerfile
# frontend/Dockerfile

FROM node:20-alpine

WORKDIR /app

COPY package.json ./

RUN npm install --omit=dev

COPY . .

USER node

EXPOSE 3000

CMD ["node", "server.js"]
```

---

## 7.3 Docker Compose

```yaml
# docker-compose.yml

services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: study_app
      POSTGRES_PASSWORD: CHANGE_ME_STRONG_DB_PASSWORD
      POSTGRES_DB: studyplatform
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U study_app -d studyplatform"]
      interval: 5s
      timeout: 5s
      retries: 10
    networks:
      - internal

  backend:
    build:
      context: ./backend
    env_file:
      - ./backend/.env
    environment:
      DATABASE_URL: postgresql+psycopg2://study_app:CHANGE_ME_STRONG_DB_PASSWORD@db:5432/studyplatform
    depends_on:
      db:
        condition: service_healthy
    command: sh -c "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"
    ports:
      - "8000:8000"
    networks:
      - internal

  frontend:
    build:
      context: ./frontend
    env_file:
      - ./frontend/.env
    environment:
      API_BASE_URL: http://backend:8000
      NODE_ENV: development
    depends_on:
      - backend
    ports:
      - "3000:3000"
    networks:
      - internal

volumes:
  pgdata:

networks:
  internal:
    driver: bridge
```

---

## 7.4 Running the Stack

1. Copy environment files:

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

2. Replace all `CHANGE_ME` secrets.

3. Build and start:

```bash
docker compose up --build
```

4. Open:

```text
http://localhost:3000
```

5. Backend docs in non-production:

```text
http://localhost:8000/docs
```

---

# 8. PostgreSQL Hardening Guidance

For production, do not use the default `postgres` superuser as the application user.

Example least-privilege setup:

```sql
-- Run as PostgreSQL admin

-- Application login role
CREATE ROLE study_app LOGIN PASSWORD 'CHANGE_ME_STRONG_APP_PASSWORD';

-- Optional migration role with DDL rights
CREATE ROLE study_migrator LOGIN PASSWORD 'CHANGE_ME_STRONG_MIGRATOR_PASSWORD';

GRANT CONNECT ON DATABASE studyplatform TO study_app;
GRANT CONNECT ON DATABASE studyplatform TO study_migrator;

\c studyplatform

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO study_app;
GRANT USAGE, CREATE ON SCHEMA public TO study_migrator;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO study_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO study_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO study_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT USAGE ON SEQUENCES TO study_app;
```

PostgreSQL configuration recommendations:

```conf
# postgresql.conf

password_encryption = scram-sha-256
ssl = on
ssl_cert_file = '/etc/postgresql/certs/server.crt'
ssl_key_file = '/etc/postgresql/certs/server.key'
listen_addresses = 'localhost,db-internal-ip'
```

```text
# pg_hba.conf

# Reject insecure local network access
hostssl all all 10.0.0.0/8 scram-sha-256
hostssl all all 172.16.0.0/12 scram-sha-256
hostssl all all 192.168.0.0/16 scram-sha-256

# Reject everything else
host all all 0.0.0.0/0 reject
```

Application connection string example:

```text
postgresql+psycopg2://study_app:CHANGE_ME@db-host:5432/studyplatform?sslmode=verify-full
```

---

# 9. Security Mechanisms Implemented

## Authentication

- Passwords hashed with bcrypt via Passlib.
- Plaintext passwords never stored.
- Password strength enforced on backend and frontend.
- JWT access tokens are short-lived.
- Refresh tokens are issued for token renewal.
- OAuth2 bearer flow used by FastAPI.
- Failed logins are logged as security events.
- Login endpoint is rate limited.

## Authorization

- Role-based access control:
  - normal users can access their own resources,
  - admins can manage questions and battles.
- Task ownership is validated before access or mutation.
- Battle participation is validated before play or submission.

## Input Validation

- Pydantic validates all backend request bodies and query parameters.
- Express Validator validates frontend forms.
- Backend does not trust frontend validation.
- Enum-like fields are constrained with patterns and DB checks.

## SQL Injection Protection

- All database access uses SQLAlchemy ORM.
- No string-built SQL queries.
- Alembic migrations use structured DDL.

## XSS Protection

- EJS uses escaped output with `<%= %>`.
- Dynamic DOM updates in browser JS use `textContent`, not `innerHTML`.
- Helmet sets a strict CSP:
  - `default-src 'self'`
  - `script-src 'self'`
  - `object-src 'none'`
  - `frame-ancestors 'none'`
  - `form-action 'self'`

## CSRF Protection

- Node SSR layer uses double-submit CSRF cookies.
- Forms include a hidden `_csrf` field.
- JSON fetch requests send `X-CSRF-Token`.
- Token comparison uses timing-safe equality.
- Auth cookies use `HttpOnly`, `Secure` in production, and `SameSite=Strict`.

## Secure Headers

Node sets:

- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy

FastAPI also adds defensive headers for API responses.

## Error Handling

- FastAPI generic exception handler returns only `Internal server error`.
- Stack traces are logged server-side, not returned to clients.
- Validation errors are normalized.
- Node error handler avoids leaking internals.

## Rate Limiting

- FastAPI:
  - login: `5/minute`
  - battle join: `10/minute`
- Node:
  - login form: `10` attempts per 15 minutes

For production, replace in-memory rate-limit storage with Redis.

## Monitoring Hooks

- Security logger records:
  - failed logins,
  - successful logins.
- You should forward logs to a SIEM or centralized logging system.
- Add alerts for repeated failed logins and abnormal battle join rates.

---

# 10. Assumptions and Stubbed Areas

These are intentional MVP stubs:

1. **Content is stubbed**
   - Task notes and topics are placeholders.
   - Replace with real curriculum content, CMS, or markdown renderer.

2. **Question seeding**
   - Admins create questions through `/api/v1/questions`.
   - Task generation assigns random existing questions.
   - For production, add subject/topic-aware selection and difficulty progression.

3. **Holiday/buffer rescheduling**
   - Missed tasks are rescheduled 7 days later.
   - A production system should use a dedicated academic calendar table with holiday/buffer days.

4. **Battle finalization**
   - Battles finalize when all joined participants submit.
   - Production should add a background worker/cron to finalize battles whose time expires.

5. **Refresh token rotation**
   - The refresh endpoint issues new tokens but does not implement refresh token revocation or rotation storage.
   - Production should store refresh token hashes or use a token allowlist/denylist.

6. **Redis**
   - Rate limiting uses in-memory storage.
   - Production should use Redis for rate limits and possibly session/cache state.

7. **HTTPS**
   - The app assumes it runs behind Nginx/TLS terminating proxy in production.
   - Secure cookies are enabled when `NODE_ENV=production`.

---

This gives you a secure, cohesive, runnable MVP foundation with clean separation between API, services, ORM models, SSR frontend, and database schema. From here, the safest extension path is: add real content, add refresh-token revocation, add Redis-backed rate limiting, add background workers for battle expiration, and add centralized logging/alerting.
