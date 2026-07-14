# Triple Factor Authentication for Social Media

A Python/Flask implementation of triple factor authentication (3FA) for a social media login scenario, with a PHP/jQuery frontend and a real-time attack simulator.

---

## Architecture

The project runs two Docker containers:

| Container | Stack | Role |
|-----------|-------|------|
| **frontend** | Nginx + PHP-FPM | Serves the UI, proxies API calls, runs attack simulations |
| **backend** | Python / Flask | Authentication API (password, TOTP, device JWT, OOB OTP) |

```
Browser  ──►  Nginx (:80)  ──►  PHP-FPM (index.php, attack_proxy.php)
                │
                └── /api/*  ──►  Flask (:5000)
```

---

## The three factors

| Factor | What | Tech |
|--------|------|------|
| 1 — Password | Something you know | bcrypt (cost 12), lockout after 5 failures |
| 2 — TOTP | Something you have (phone) | pyotp, RFC 6238, nonce cache replay prevention |
| 3 — Device JWT + OOB OTP | Out-of-band channel | PyJWT HS256, Telegram bot or email |

---

## Attacks demonstrated

The attack simulator panel runs real HTTP requests against the live server and shows each response:

| Attack | What happens | Mitigation |
|--------|-------------|-----------|
| Brute force | 8 common passwords tried | Account locked after 5 failures (HTTP 429) |
| TOTP replay | Valid code reused in a second session | Nonce cache rejects used codes for 90s |
| JWT tampering | Payload modified, signature kept | HMAC-SHA256 detects the mismatch |
| JWT none-alg (CVE-2015-9235) | Token forged with `alg: none` | Algorithm whitelist rejects it |

---

## Quickstart

### Prerequisites

- Docker and Docker Compose installed
- Port 80 available

### Run

```bash
git clone <this-repo>
cd triple-auth

docker-compose up --build
```

Open `http://localhost` in your browser.

### Stop

```bash
docker-compose down
```

---

## Demo walkthrough

1. **Register** — enter a username and password. You get a QR code and TOTP secret.
2. **Step 1** — enter the same username and password.
3. **Step 2** — enter the 6-digit code from your authenticator app (Google Authenticator, Authy, etc).
4. **Step 3** — click "Send Device Token". Since no Telegram/email is configured, the OTP appears directly in the UI. Enter it to complete login.
5. **Attack panel** — click the sword icon in the top-right corner. Run each attack and watch the server block it in real time.

---

## Running without Docker

### Backend (terminal 1)

```bash
cd backend
pip install -r requirements.txt
python app.py
```

### Frontend

Point any PHP-capable web server (XAMPP, MAMP, `php -S`) at the `frontend/` directory. Update the `$BACKEND` variable in `attack_proxy.php` and `generate_token.php` to point to `http://localhost:5000`.

---

## Running the tests

The backend includes 16 automated end-to-end tests and 5 narrated attack demonstrations:

```bash
cd backend
python test_e2e.py      # 16 HTTP tests
python attacks.py        # narrated attack demos (starts its own server)
```

---

## Project structure

```
triple-auth/
├── docker-compose.yml
├── .gitignore
├── README.md
│
├── frontend/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── nginx.conf
│   ├── index.php              main UI
│   ├── attack_proxy.php       runs attacks server-side via curl
│   ├── generate_token.php     generates device JWTs for step 3
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── app.js             jQuery: login flow + attack panel
│
├── backend/
│   ├── Dockerfile
│   ├── app.py                 Flask app, registration, factor 1
│   ├── models.py              User class, bcrypt, lockout logic
│   ├── totp_routes.py         factor 2: TOTP verification
│   ├── device_routes.py       factor 3: device JWT + OOB OTP
│   ├── jwt_utils.py           JWT generation/verification
│   ├── config.py              constants, shared state
│   ├── attacks.py             CLI attack demonstrations
│   ├── test_e2e.py            automated tests
│   ├── requirements.txt
│   └── templates/
│       └── qr.html            QR code display page
```

---

## Notes

- All state is in-memory. Restarting the backend container wipes all users.
- The `SECRET_KEY` defaults to a hardcoded value for development. In production, set it via environment variable.
- The attack proxy uses the same default key to generate and tamper with JWTs. This is intentional for the demo.
