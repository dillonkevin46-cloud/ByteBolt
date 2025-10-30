from fastapi import FastAPI
from app.api.api import api_router
from app.db.base import Base, engine, SessionLocal
from app.db import models # Import models
from app.core.security import get_password_hash # Import hasher

def create_default_admin():
    """Create a default admin user if one doesn't exist."""
    db = SessionLocal()
    try:
        # Check if any user exists
        user = db.query(models.User).filter(models.User.username == "Admin").first()
        if not user:
            print("Creating default admin user...")
            hashed_password = get_password_hash("Admin") # Hash the password
            default_admin = models.User(
                username="Admin",
                hashed_password=hashed_password,
                role=models.UserRole.admin
            )
            db.add(default_admin)
            db.commit()
            print("Default admin user created.")
    finally:
        db.close()

# Create the database tables
Base.metadata.create_all(bind=engine)

# --- NEW: Create default user on startup ---
create_default_admin()

# Create the main FastAPI app instance
app = FastAPI(
    title="ByteBolt IT Multi-App",
    description="Server-side API for all ByteBolt IT tools.",
    version="1.0.0"
)

# Include the main router
app.include_router(api_router, prefix="/api/v1")

@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Welcome to the ByteBolt API"}