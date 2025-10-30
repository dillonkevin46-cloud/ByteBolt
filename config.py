import secrets

# WARNING: This should be in a .env file, not hardcoded
# For this example, we'll generate one.
# You can generate your own with: openssl rand -hex 32
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60