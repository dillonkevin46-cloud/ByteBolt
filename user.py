from pydantic import BaseModel
from app.db.models import UserRole # Import the Enum

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    role: UserRole = UserRole.view

class UserUpdateRole(BaseModel):
    role: UserRole
    
class UserUpdatePassword(BaseModel):
    password: str

class User(UserBase):
    id: int
    role: UserRole

    class Config:
        from_attributes = True