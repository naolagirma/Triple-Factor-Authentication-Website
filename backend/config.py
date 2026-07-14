import os

# secret key used to sign JWTs and Flask session cookies
# a 64-char hex string = 32 bytes, satisfying RFC 7518 minimum for HMAC-SHA256
# in production: load from environment variable, never commit a real key
SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "a3f8c2e1d4b7a9f0e5c3b2d1a8f6e4c7b3d2a1f9e8c7b6a5d4c3b2a1f0e9d8"
)

# how long before a JWT token expires (in seconds)
JWT_EXPIRY = 3600  # 1 hour

# brute force protection
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 60  # seconds

# totp window - 30 seconds is the RFC 6238 standard
TOTP_INTERVAL = 30

# --- in-memory state (replace with a real database in production) ---
users          = {}  # username -> User object
failed_attempts = {}  # username -> [count, last_timestamp]
used_otps      = {}  # "username:code" -> used_at timestamp

# --- out-of-band delivery ---
# Telegram: create a bot via @BotFather, paste the token below
# then have each user send any message to the bot and run /getUpdates
# to find their chat_id
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8979856544:AAErnDwND_iCmS9o4ZJjbI0eqPiBr97Xm0g")
TELEGRAM_CHAT_IDS  = {"james007": 6875428404}


# Email via SMTP (e.g. Gmail with an App Password)
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = 587
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
USER_EMAILS = {
    # "username": "user@example.com"
}
