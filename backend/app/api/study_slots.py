import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import StudySlot, User
from app.schemas.schemas import StudySlotCreate, StudySlotOut

router = APIRouter(prefix="/api/study-slots", tags=["study-slots"])


@router.get("", response_model=list[StudySlotOut])
def list_slots(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return (
        db.query(StudySlot)
        .filter(StudySlot.user_id == current_user.id)
        .order_by(StudySlot.start_time.asc())
        .all()
    )


@router.post("", response_model=StudySlotOut, status_code=status.HTTP_201_CREATED)
def create_slot(payload: StudySlotCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if payload.end_time <= payload.start_time:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="end_time must be after start_time")

    slot = StudySlot(user_id=current_user.id, **payload.model_dump())
    db.add(slot)
    db.commit()
    db.refresh(slot)
    return slot


@router.post("/{slot_id}/complete", response_model=StudySlotOut)
def complete_slot(slot_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    slot = db.get(StudySlot, slot_id)
    if not slot or slot.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Study slot not found")
    slot.completed = True
    current_user.points += 5
    db.commit()
    db.refresh(slot)
    return slot


@router.delete("/{slot_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_slot(slot_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    slot = db.get(StudySlot, slot_id)
    if not slot or slot.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Study slot not found")
    db.delete(slot)
    db.commit()
    return None
