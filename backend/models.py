import bcrypt
import pyotp
import time
import config

# i decided to keep this simple - just a class that holds user data
# and handles password stuff. no database for now.

class User:
    def __init__(self, username, password_plain):
        self.username = username
        # hash the password right away, never store it in plain text
        self.password_hash = self._hash_password(password_plain)
        # generate a secret for TOTP - each user gets their own
        self.totp_secret = pyotp.random_base32()
        # we'll use this to track if the user is "registered" with an authenticator app
        self.totp_enabled = False
        self.created_at = time.time()

    def _hash_password(self, plain):
        # bcrypt automatically adds salt, which is nice
        # cost factor 12 is a bit slow but thats the point - makes brute force harder
        hashed = bcrypt.hashpw(plain.encode('utf-8'), bcrypt.gensalt(rounds=12))
        return hashed

    def check_password(self, plain):
        # bcrypt handles the salt comparison internally
        return bcrypt.checkpw(plain.encode('utf-8'), self.password_hash)

    def get_totp_uri(self):
        # this is the URI format that authenticator apps like google authenticator read
        totp = pyotp.TOTP(self.totp_secret)
        return totp.provisioning_uri(name=self.username, issuer_name="TripleAuthApp")

    def verify_totp(self, code):
        totp = pyotp.TOTP(self.totp_secret)
        # valid_window=1 means we accept the code from the previous 30s window too
        # this helps if the user is a bit slow typing
        return totp.verify(code, valid_window=1)


def register_user(username, password):
    """add a new user to our in-memory store"""
    if username in config.users:
        return False, "username already taken"

    # minimum password length - short passwords are too easy to brute force
    if len(password) < 8:
        return False, "password must be at least 8 characters"

    user = User(username, password)
    config.users[username] = user
    return True, user


def get_user(username):
    return config.users.get(username, None)


def is_locked_out(username):
    """check if this user has too many failed attempts"""
    if username not in config.failed_attempts:
        return False

    attempts, last_time = config.failed_attempts[username]

    # if enough time has passed, reset the counter
    if time.time() - last_time > config.LOCKOUT_TIME:
        del config.failed_attempts[username]
        return False

    return attempts >= config.MAX_LOGIN_ATTEMPTS


def record_failed_attempt(username):
    """increment the failed attempt counter for a user"""
    if username not in config.failed_attempts:
        config.failed_attempts[username] = [0, time.time()]

    config.failed_attempts[username][0] += 1
    config.failed_attempts[username][1] = time.time()


def reset_attempts(username):
    """clear failed attempts after a successful login"""
    if username in config.failed_attempts:
        del config.failed_attempts[username]
