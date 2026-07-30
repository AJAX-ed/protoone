import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_admin
from app.models.models import ShopItem, User
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/shop", tags=["shop"])


class ShopItemOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    price_coins: int
    stock: int

    class Config:
        from_attributes = True


class ShopItemCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    price_coins: int = Field(gt=0)
    stock: int = -1


@router.get("", response_model=list[ShopItemOut])
def list_items(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(ShopItem).all()


@router.post("", response_model=ShopItemOut, status_code=status.HTTP_201_CREATED)
def create_item(payload: ShopItemCreate, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    item = ShopItem(**payload.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.post("/{item_id}/purchase", response_model=ShopItemOut)
def purchase_item(item_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    item = db.get(ShopItem, item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    if item.stock == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Item out of stock")
    if current_user.coins < item.price_coins:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient coins")

    current_user.coins -= item.price_coins
    if item.stock > 0:
        item.stock -= 1
    db.commit()
    db.refresh(item)
    return item
