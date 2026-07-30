import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_admin
from app.models.models import Task, TaskStatusEnum, User
from app.schemas.schemas import TaskOut, TaskCreate

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


@router.get("", response_model=list[TaskOut])
def list_tasks(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    tasks = (
        db.query(Task)
        .filter(Task.user_id == current_user.id)
        .order_by(Task.order_index.asc())
        .all()
    )
    return tasks


@router.post("", response_model=TaskOut, status_code=status.HTTP_201_CREATED)
def create_task(payload: TaskCreate, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    task = Task(**payload.model_dump())
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def _is_unlockable(db: Session, user_id: uuid.UUID, order_index: int) -> bool:
    """Gating logic: a task unlocks only if all tasks with a lower order_index are completed."""
    incomplete_prior = (
        db.query(Task)
        .filter(
            Task.user_id == user_id,
            Task.order_index < order_index,
            Task.status != TaskStatusEnum.completed,
        )
        .count()
    )
    return incomplete_prior == 0


@router.post("/{task_id}/complete", response_model=TaskOut)
def complete_task(task_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    task = db.get(Task, task_id)
    if not task or task.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    if task.status == TaskStatusEnum.completed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Task already completed")

    if not _is_unlockable(db, current_user.id, task.order_index):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Prior tasks not completed; task is gated/locked")

    task.status = TaskStatusEnum.completed
    current_user.points += task.points_reward
    current_user.coins += max(1, task.points_reward // 5)
    db.commit()
    db.refresh(task)

    # Unlock next tasks that are now eligible
    next_tasks = (
        db.query(Task)
        .filter(Task.user_id == current_user.id, Task.status == TaskStatusEnum.locked)
        .all()
    )
    for nt in next_tasks:
        if _is_unlockable(db, current_user.id, nt.order_index):
            nt.status = TaskStatusEnum.unlocked
    db.commit()

    return task
