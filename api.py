from fastapi import APIRouter
from app.api.endpoints import assets, login, users
# --- [NEW] Import dropdown routers ---
from app.api.endpoints.dropdowns import categories_router, locations_router, departments_router

api_router = APIRouter()

# Login and User routers
api_router.include_router(login.router, prefix="/login", tags=["Login"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])

# Asset router
api_router.include_router(assets.router, prefix="/assets", tags=["Assets"])

# --- [NEW] Dropdown management routers ---
api_router.include_router(categories_router, prefix="/categories", tags=["Categories"])
api_router.include_router(locations_router, prefix="/locations", tags=["Locations"])
api_router.include_router(departments_router, prefix="/departments", tags=["Departments"])