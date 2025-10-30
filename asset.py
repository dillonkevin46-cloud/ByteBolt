from pydantic import BaseModel
from typing import Optional
from .dropdowns import DropdownItem  # <-- Import new schema
from app.db.models import AssetStatus # <-- Import new Enum

# Base model for common fields
class AssetBase(BaseModel):
    serial_number: str
    device_name: str
    make: str
    model: str
    allocated_user: Optional[str] = None
    ip_address: Optional[str] = None
    value_zar: Optional[float] = None
    
    # --- [NEW] Status field (defaults to active) ---
    status: Optional[AssetStatus] = AssetStatus.active
    
    # --- [NEW] Use IDs for creation/updates ---
    category_id: Optional[int] = None
    location_id: Optional[int] = None
    department_id: Optional[int] = None

# Model for creating a new asset (what the API expects)
class AssetCreate(AssetBase):
    pass

# Model for reading an asset (what the API returns)
class Asset(AssetBase):
    id: int
    
    # --- [NEW] Return the full related object ---
    category: Optional[DropdownItem] = None
    location: Optional[DropdownItem] = None
    department: Optional[DropdownItem] = None

    class Config:
        from_attributes = True