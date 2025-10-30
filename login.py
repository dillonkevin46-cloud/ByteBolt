from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta

from app.core import security
from app.core.config import ACCESS_TOKEN_EXPIRE_MINUTES
from app.schemas import token as token_schema
from app.schemas import user as user_schema
from app.db import models
from app.api.deps import get_db_session, get_current_user 

router = APIRouter()

@router.post("/token", response_model=token_schema.Token)
def login_for_access_token(
    db: Session = Depends(get_db_session), 
    form_data: OAuth2PasswordRequestForm = Depends()
):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=user_schema.User)
# --- THIS IS THE CORRECTED LINE ---
def read_users_me(current_user: models.User = Depends(get_current_user)):
    """
    Fetch the currently logged-in user.
    """
    return current_user