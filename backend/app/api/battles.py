import random
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Battle, User
from app.schemas.schemas import BattleCreate, BattleOut

router = APIRouter(prefix="/api/battles", tags=["battles"])

BATTLE_EXPIRY_MINUTES = 10


@router.post("", response_model=BattleOut, status_code=status.HTTP_201_CREATED)
def create_battle(payload: BattleCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if payload.opponent_id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot battle yourself")

    opponent = db.get(User, payload.opponent_id)
    if not opponent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Opponent not found")

    battle = Battle(
        challenger_id=current_user.id,
        opponent_id=payload.opponent_id,
        status="pending",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=BATTLE_EXPIRY_MINUTES),
    )
    db.add(battle)
    db.commit()
    db.refresh(battle)
    return battle


@router.post("/{battle_id}/resolve", response_model=BattleOut)
def resolve_battle(battle_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    battle = db.get(Battle, battle_id)
    if not battle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Battle not found")

    if current_user.id not in (battle.challenger_id, battle.opponent_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a participant in this battle")

    if battle.status != "pending":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Battle already resolved")

    now = datetime.now(timezone.utc)
    if battle.expires_at < now:
        battle.status = "expired"
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Battle expired")

    # Deterministic-but-fair resolution stub: server-side randomness, never trust client input for outcome
    winner_id = random.choice([battle.challenger_id, battle.opponent_id])
    battle.status = "completed"
    battle.winner_id = winner_id

    winner = db.get(User, winner_id)
    if winner:
        winner.points += 20
        winner.coins += 5

    db.commit()
    db.refresh(battle)
    return battle


@router.get("/{battle_id}", response_model=BattleOut)
def get_battle(battle_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    battle = db.get(Battle, battle_id)
    if not battle or current_user.id not in (battle.challenger_id, battle.opponent_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Battle not found")
    return battle
