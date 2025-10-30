from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.db import models
from app.schemas import user as user_schema
from app.api.deps import get_db_session, get_current_admin_user
from app.core.security import get_password_hash

router = APIRouter()

@router.post("/", response_model=user_schema.User, status_code=status.HTTP_201_CREATED)
def create_user(
    user_in: user_schema.UserCreate,
    db: Session = Depends(get_db_session),
    admin_user: models.User = Depends(get_current_admin_user)
):
    """
    Create a new user. (Admin only)
    """
    db_user = db.query(models.User).filter(models.User.username == user_in.username).first()
    if db_user:
        raise HTTPException(
            status_code=400,
            detail="Username already registered",
        )
    hashed_password = get_password_hash(user_in.password)
    db_user = models.User(
        username=user_in.username,
        hashed_password=hashed_password,
        role=user_in.role
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.get("/", response_model=List[user_schema.User])
def read_users(
    db: Session = Depends(get_db_session),
    admin_user: models.User = Depends(get_current_admin_user)
):
    """
    Retrieve all users. (Admin only)
    """
    return db.query(models.User).all()

@router.put("/{user_id}/role", response_model=user_schema.User)
def update_user_role(
    user_id: int,
    user_in: user_schema.UserUpdateRole,
    db: Session = Depends(get_db_session),
    admin_user: models.User = Depends(get_current_admin_user)
):
    """
    Update a user's role. (Admin only)
    """
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db_user.role = user_in.role
    db.commit()
    db.refresh(db_user)
    return db_user

@router.put("/{user_id}/reset-password", response_model=user_schema.User)
def reset_user_password(
    user_id: int,
    user_in: user_schema.UserUpdatePassword,
    db: Session = Depends(get_db_session),
    admin_user: models.User = Depends(get_current_admin_user)
):
    """
    Reset a user's password. (Admin only)
    """
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db_user.hashed_password = get_password_hash(user_in.password)
    db.commit()
    db.refresh(db_user)
    return db_user