<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TripleAuth — Triple Factor Authentication</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>

<!-- top bar -->
<nav class="topbar">
    <div class="topbar-left">
        <span class="logo">&#x1f512; TripleAuth</span>
        <span class="tagline">Triple Factor Authentication Demo</span>
    </div>
    <div class="topbar-right">
        <a href="#" id="nav-register" class="nav-link">Register</a>
        <a href="#" id="nav-login" class="nav-link">Login</a>
        <button id="btn-toggle-attack" class="btn btn-attack-toggle" title="Toggle attack simulator">
            &#9876; Attacks
        </button>
    </div>
</nav>

<!-- toast container for inline errors/success messages -->
<div id="toast-container"></div>

<div class="layout">

    <!-- ==================== MAIN CONTENT ==================== -->
    <main class="main-content">

        <!-- progress stepper (hidden on landing, shown during login) -->
        <div class="stepper" id="stepper" style="display:none;">
            <div class="step" id="indicator-s1">
                <div class="step-dot">1</div>
                <div class="step-label">Password</div>
            </div>
            <div class="step-line"></div>
            <div class="step" id="indicator-s2">
                <div class="step-dot">2</div>
                <div class="step-label">TOTP</div>
            </div>
            <div class="step-line"></div>
            <div class="step" id="indicator-s3">
                <div class="step-dot">3</div>
                <div class="step-label">Device + OTP</div>
            </div>
        </div>

        <!-- ---- LANDING ---- -->
        <div class="card" id="section-landing">
            <div class="landing-hero">
                <div class="landing-icon">&#x1f512;</div>
                <h2>Triple Factor Authentication</h2>
                <p class="card-desc">Three independent verification steps before you get in.<br>
                    Password, TOTP code, and an out-of-band OTP.</p>
            </div>
            <div class="landing-actions">
                <button id="btn-land-register" class="btn btn-primary btn-lg">Create Account</button>
                <button id="btn-land-login" class="btn btn-secondary btn-lg">Login</button>
            </div>
            <p class="landing-sub">Open the <strong>Attack Simulator</strong> to see four real attacks get blocked live.</p>
        </div>

        <!-- ---- REGISTER ---- -->
        <div class="card" id="section-register" style="display:none;">
            <h2>Create Account</h2>
            <p class="card-desc">Register a new user to get your TOTP secret and QR code.</p>
            <form id="form-register" autocomplete="off">
                <div class="field">
                    <label for="reg-user">Username</label>
                    <input type="text" id="reg-user" placeholder="e.g. alice" required>
                </div>
                <div class="field">
                    <label for="reg-pass">Password</label>
                    <input type="password" id="reg-pass" placeholder="min 8 characters" required>
                </div>
                <button type="submit" class="btn btn-primary" id="btn-register">Register</button>
            </form>

            <!-- qr code appears here after registration -->
            <div id="qr-result" style="display:none;">
                <hr>
                <h3>Scan this QR code with your authenticator app</h3>
                <img id="qr-image" src="" alt="QR Code">
                <p class="secret-display">Manual key: <code id="totp-secret-text"></code></p>
                <button id="btn-goto-login" class="btn btn-primary">Proceed to Login &rarr;</button>
            </div>

            <p class="switch-link">Already registered? <a href="#" id="link-to-login">Login instead</a></p>
        </div>

        <!-- ---- STEP 1: PASSWORD ---- -->
        <div class="card" id="section-step1" style="display:none;">
            <h2>Step 1 — Password</h2>
            <p class="card-desc">First factor: something you <strong>know</strong>.</p>
            <form id="form-step1" autocomplete="off">
                <div class="field">
                    <label for="login-user">Username</label>
                    <input type="text" id="login-user" required>
                </div>
                <div class="field">
                    <label for="login-pass">Password</label>
                    <input type="password" id="login-pass" required>
                </div>
                <button type="submit" class="btn btn-primary" id="btn-step1">Verify Password</button>
            </form>
            <p class="switch-link">Need an account? <a href="#" id="link-to-register">Register</a></p>
        </div>

        <!-- ---- STEP 2: TOTP ---- -->
        <div class="card" id="section-step2" style="display:none;">
            <h2>Step 2 — TOTP Code</h2>
            <p class="card-desc">Second factor: something you <strong>have</strong> (authenticator app).</p>
            <form id="form-step2" autocomplete="off">
                <div class="field">
                    <label for="totp-code">6-digit code from your authenticator</label>
                    <input type="text" id="totp-code" maxlength="6" pattern="[0-9]{6}" placeholder="000000" required>
                </div>
                <button type="submit" class="btn btn-primary" id="btn-step2">Verify TOTP</button>
            </form>
        </div>

        <!-- ---- STEP 3: DEVICE + OOB OTP ---- -->
        <div class="card" id="section-step3" style="display:none;">
            <h2>Step 3 — Device Verification</h2>
            <p class="card-desc">Third factor: <strong>out-of-band</strong> channel (Telegram / email).</p>

            <!-- step 3a: submit device token -->
            <div id="step3-request">
                <p>Your device token will be sent automatically.<br>
                   The server will issue an OTP via an out-of-band channel.</p>
                <button id="btn-step3-request" class="btn btn-primary">Send Device Token</button>
            </div>

            <!-- step 3b: enter oob otp -->
            <div id="step3-verify" style="display:none;">
                <form id="form-step3" autocomplete="off">
                    <div class="field">
                        <label for="oob-otp">OTP received out-of-band</label>
                        <input type="text" id="oob-otp" maxlength="6" pattern="[0-9]{6}" placeholder="000000" required>
                    </div>
                    <button type="submit" class="btn btn-primary" id="btn-step3">Verify OTP</button>
                </form>
                <p class="hint" id="otp-hint" style="display:none;"></p>
            </div>
        </div>

        <!-- ---- SUCCESS ---- -->
        <div class="card card-success" id="section-success" style="display:none;">
            <div class="success-icon">&#10003;</div>
            <h2>Authentication Complete</h2>
            <p>All three factors verified successfully.</p>
            <div class="token-box">
                <label>Access Token (Bearer)</label>
                <code id="access-token-text"></code>
            </div>
            <div class="token-box">
                <label>Expires In</label>
                <code id="token-expiry"></code>
            </div>
            <button id="btn-logout" class="btn btn-secondary">Logout</button>
            <button id="btn-reset" class="btn btn-danger btn-sm">Reset Server (wipes all users)</button>
        </div>

        <!-- response log -->
        <div class="log-panel">
            <div class="log-header">
                <h3>&#128462; Server Responses</h3>
                <button id="btn-clear-log" class="btn btn-small">Clear</button>
            </div>
            <div id="response-log"></div>
        </div>

    </main>

    <!-- ==================== ATTACK PANEL (sidebar) ==================== -->
    <aside class="attack-panel" id="attack-panel">
        <div class="attack-header">
            <h2>&#9876; Attack Simulator</h2>
            <p>Run real attacks against the live server and watch them get blocked.</p>
            <p class="attack-warn">&#9888; Each attack resets the server and registers its own test users.
               Your current login session will be unaffected but registered users will be wiped.</p>
        </div>

        <!-- attack 1 -->
        <div class="attack-card">
            <div class="attack-title">
                <span class="attack-num">1</span>
                Brute Force / Credential Stuffing
            </div>
            <p class="attack-desc">
                Tries 8 common passwords against a known username.
                The server locks the account after 5 failures (HTTP 429).
            </p>
            <button class="btn btn-danger btn-attack" data-attack="brute_force">
                &#9889; Run Attack
            </button>
            <div class="attack-log" id="log-brute_force"></div>
        </div>

        <!-- attack 2 -->
        <div class="attack-card">
            <div class="attack-title">
                <span class="attack-num">2</span>
                TOTP Replay Attack
            </div>
            <p class="attack-desc">
                Intercepts a valid TOTP code and tries to reuse it in a second session.
                The nonce cache blocks the replay.
            </p>
            <button class="btn btn-danger btn-attack" data-attack="totp_replay">
                &#9889; Run Attack
            </button>
            <div class="attack-log" id="log-totp_replay"></div>
        </div>

        <!-- attack 3 -->
        <div class="attack-card">
            <div class="attack-title">
                <span class="attack-num">3</span>
                JWT Signature Tampering
            </div>
            <p class="attack-desc">
                Takes a valid token for &ldquo;carol&rdquo; and changes the subject claim
                to &ldquo;admin&rdquo; while keeping the old signature. HMAC-SHA256 catches it.
            </p>
            <button class="btn btn-danger btn-attack" data-attack="jwt_tamper">
                &#9889; Run Attack
            </button>
            <div class="attack-log" id="log-jwt_tamper"></div>
        </div>

        <!-- attack 4 -->
        <div class="attack-card">
            <div class="attack-title">
                <span class="attack-num">4</span>
                JWT &ldquo;none&rdquo; Algorithm (CVE-2015-9235)
            </div>
            <p class="attack-desc">
                Forges a token with <code>alg: none</code> and an empty signature.
                The algorithm whitelist rejects it instantly.
            </p>
            <button class="btn btn-danger btn-attack" data-attack="jwt_none">
                &#9889; Run Attack
            </button>
            <div class="attack-log" id="log-jwt_none"></div>
        </div>
    </aside>

</div><!-- /layout -->

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="/js/app.js"></script>
</body>
</html>
