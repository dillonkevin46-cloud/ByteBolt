from fastapi import APIRouter, Depends, HTTPException, status
# --- [FIX] Corrected imports ---
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_  # or_ comes from sqlalchemy directly
# --- End of Fix ---
from typing import List, Optional
from pydantic import BaseModel # <-- Import BaseModel

from app.db import models
from app.schemas import asset as asset_schema
from app.api.deps import get_db_session, get_current_user
from app.db.models import AssetStatus # <-- Import Enum

router = APIRouter()

@router.post("/", response_model=asset_schema.Asset)
def create_asset(
    asset: asset_schema.AssetCreate, 
    db: Session = Depends(get_db_session),
    current_user: models.User = Depends(get_current_user)
):
    if current_user.role == models.UserRole.view:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
            
    db_asset = models.Asset(**asset.model_dump())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset

@router.get("/{asset_id}", response_model=asset_schema.Asset)
def read_asset(
    asset_id: int, 
    db: Session = Depends(get_db_session),
    current_user: models.User = Depends(get_current_user)
):
    db_asset = (
        db.query(models.Asset)
        .options(
            joinedload(models.Asset.category),
            joinedload(models.Asset.location),
            joinedload(models.Asset.department),
        )
        .filter(models.Asset.id == asset_id)
        .first()
    )
    if db_asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return db_asset

@router.get("/", response_model=List[asset_schema.Asset])
def read_assets(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db_session),
    search_term: Optional[str] = None, 
    department: Optional[str] = None,
    location: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None, # <--- NEW: Status filter
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.Asset).options(
        joinedload(models.Asset.category),
        joinedload(models.Asset.location),
        joinedload(models.Asset.department),
    )
    
    if search_term:
        search_like = f"%{search_term}%"
        query = query.filter(
            or_(
                models.Asset.serial_number.ilike(search_like),
                models.Asset.device_name.ilike(search_like),
                models.Asset.allocated_user.ilike(search_like),
                models.Asset.ip_address.ilike(search_like),
                models.Asset.make.ilike(search_like),
                models.Asset.model.ilike(search_like)
            )
        )

    if department:
        query = query.join(models.Department).filter(models.Department.name.ilike(f"%{department}%"))
    if location:
        query = query.join(models.Location).filter(models.Location.name.ilike(f"%{location}%"))
    if category:
        query = query.join(models.Category).filter(models.Category.name.ilike(f"%{category}%"))
    
    # --- [NEW] Status Filter Logic ---
    if status and status.lower() in [AssetStatus.active, AssetStatus.decommissioned]:
        query = query.filter(models.Asset.status == AssetStatus(status.lower()))
    
    assets = query.order_by(models.Asset.id.desc()).offset(skip).limit(limit).all()
    return assets

@router.put("/{asset_id}", response_model=asset_schema.Asset)
def update_asset(
    asset_id: int,
    asset: asset_schema.AssetCreate,
    db: Session = Depends(get_db_session),
    current_user: models.User = Depends(get_current_user)
):
    if current_user.role == models.UserRole.view:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    db_asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if db_asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Exclude status from this update, as it's handled by a separate endpoint
    update_data = asset.model_dump(exclude_unset=True, exclude={"status"})
    for key, value in update_data.items():
        setattr(db_asset, key, value)
    
    db.commit()
    db.refresh(db_asset)
    return db_asset

@router.delete("/{asset_id}", response_tmodel=asset_schema.Asset)
def delete_asset(
    asset_id: int, 
    db: Session = Depends(get_db_session),
    current_user: models.User = Depends(get_current_user)
):
    if current_user.role != models.UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
            
    db_asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if db_asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    db.delete(db_asset)
    db.commit()
    return db_asset

# --- [NEW] Schema for Status Update ---
class AssetUpdateStatus(BaseModel):
    status: AssetStatus

# --- [NEW] Endpoint to Update Status ---
@router.put("/{asset_id}/status", response_model=asset_schema.Asset)
def update_asset_status(
    asset_id: int,
    status_in: AssetUpdateStatus, # Use new schema
    db: Session = Depends(get_db_session),
    current_user: models.User = Depends(get_current_user)
):
    if current_user.role == models.UserRole.view:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to change asset status")

    db_asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if db_asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    db_asset.status = status_in.status
    
    db.commit()
    db.refresh(db_asset)
    return db_asset