from sqlalchemy import Column, Integer, String, Float, ForeignKey, Enum
from sqlalchemy.orm import relationship # <-- Import relationship
from .base import Base
import enum

# Enum for roles
class UserRole(str, enum.Enum):
    admin = "admin"
    edit = "edit"
    view = "view"

# --- [NEW] Enum for Asset Status ---
class AssetStatus(str, enum.Enum):
    active = "active"
    decommissioned = "decommissioned"

# --- [NEW] Generic model for dropdown items ---
class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    assets = relationship("Asset", back_populates="category")

class Location(Base):
    __tablename__ = "locations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    assets = relationship("Asset", back_populates="location")

class Department(Base):
    __tablename__ = "departments"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    assets = relationship("Asset", back_populates="department")

# --- [MODIFIED] Asset Model ---
class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    serial_number = Column(String, unique=True, index=True, nullable=False)
    device_name = Column(String, index=True)
    allocated_user = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    make = Column(String)
    model = Column(String)
    value_zar = Column(Float, nullable=True)
    
    # --- [NEW] Status Column ---
    status = Column(Enum(AssetStatus), nullable=False, default=AssetStatus.active, index=True)
    
    # --- Changed from String to ForeignKey ---
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=True)
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True)
    
    # --- New ForeignKey ---
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)

    # --- Relationships for easy API access ---
    location = relationship("Location", back_populates="assets")
    department = relationship("Department", back_populates="departments")
    category = relationship("Category", back_populates="assets")

# --- User Model (Unchanged) ---
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.view)