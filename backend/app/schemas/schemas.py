import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, ConfigDict

from app.models.models import RoleEnum, TaskStatusEnum


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: str
    role: RoleEnum
    points: int
    coins: int


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class TaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    description: str | None
    status: TaskStatusEnum
    order_index: int
    points_reward: int


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    order_index: int = 0
    points_reward: int = 10


class StudySlotCreate(BaseModel):
    subject: str = Field(min_length=1, max_length=100)
    start_time: datetime
    end_time: datetime


class StudySlotOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    subject: str
    start_time: datetime
    end_time: datetime
    completed: bool


class BattleCreate(BaseModel):
    opponent_id: uuid.UUID


class BattleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    challenger_id: uuid.UUID
    opponent_id: uuid.UUID
    status: str
    winner_id: uuid.UUID | None
    expires_at: datetime
