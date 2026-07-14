# Triple Factor Authentication for terminal-only demo

A Python/Flask implementation of triple factor authentication (3FA) for a social media login scenario. Requires three independent steps to log in, and actively demonstrates four real attack techniques being blocked.

---

## The three factors

| Factor | What | Tech |
|--------|------|------|
| 1 — Password | Something you know | bcrypt (cost 12), lockout after 5 failures |
| 2 — TOTP | Something you have (phone) | pyotp, RFC 6238, nonce cache replay prevention |
| 3 — Device JWT + OOB OTP | Out-of-band channel | PyJWT HS256, Telegram bot or email |

## Attacks implemented and blocked

| Attack | Mitigation |
|--------|-----------|
| Brute force / credential stuffing | Lockout (HTTP 429) + bcrypt slows each attempt to ~250ms |
| TOTP replay | Nonce cache: used codes rejected for 90 seconds |
| JWT signature tampering | HMAC-SHA256 covers header+payload; any change breaks it |
| JWT none-algorithm (CVE-2015-9235) | `algorithms=['HS256']` whitelist in `jwt.decode()` |

---

## Quickstart

```bash
# install dependencies
pip install -r requirements.txt

# start the server
python app.py

# run all 16 end-to-end tests (in a separate terminal)
python test_e2e.py

# run the narrated attack demonstrations
python attacks.py
```

The server starts on `http://localhost:5000`.

---

## Login flow

```
POST /register              -> get TOTP secret + QR code
POST /login/step1           -> submit password
POST /login/step2           -> submit TOTP code
POST /login/step3/request   -> submit device JWT, receive OOB OTP
POST /login/step3/verify    -> submit OOB OTP, receive Bearer token
```

View the QR code for any registered user in a browser:
```
http://localhost:5000/qr/<username>
```

---

## Telegram OTP setup (optional)

By default the server falls back to returning the OTP in the response body (`dev_otp` field) when no delivery channel is configured. To enable real Telegram delivery:

1. Message `@BotFather` on Telegram → `/newbot` → copy the token
2. Message your new bot, then call:
   ```
   https://api.telegram.org/bot<TOKEN>/getUpdates
   ```
   Find your `chat.id` in the response.
3. Set environment variables (or edit `config.py` directly for testing):
   ```bash
   export TELEGRAM_BOT_TOKEN="your_token_here"
   ```
4. Add the username → chat_id mapping in `config.py`:
   ```python
   TELEGRAM_CHAT_IDS = {
       "your_username": "your_chat_id"
   }
   ```
5. Restart the server.

---

## Project structure

```
app.py            main Flask app, registration, Factor 1
models.py         User class, bcrypt hashing, lockout logic
totp_routes.py    Factor 2 — TOTP verification + replay prevention
jwt_utils.py      JWT generation/verification, OTP generation
device_routes.py  Factor 3 — device JWT check + OOB OTP delivery
config.py         constants and shared in-memory state
attacks.py        four attack demonstrations (all blocked)
test_e2e.py       16 automated end-to-end HTTP tests
templates/qr.html QR code display page
```

---

## Running the tests

`test_e2e.py` starts its own server internally so you do not need the server running first. Just run:

```bash
python test_e2e.py
```

Expected output:
```
=== REGISTRATION ===
  ✓ register 201 (got 201)
  ✓ has totp_secret
  ✓ has qr_code
...
  16 passed  |  0 failed
```

---

## Notes

- All state is in-memory. Restarting the server wipes all users.
- The `SECRET_KEY` in `config.py` defaults to a hardcoded value for development. In production, set it via the `SECRET_KEY` environment variable.
- The `/reset` endpoint wipes server state and exists only for testing.
