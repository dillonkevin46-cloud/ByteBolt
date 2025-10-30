from pydantic import BaseModel
from typing import Optional

# Base schema
class DropdownBase(BaseModel):
    name: str

class DropdownCreate(DropdownBase):
    pass

# Schema for reading (will include ID)
class DropdownItem(DropdownBase):
    id: int

    class Config:
        from_attributes = True