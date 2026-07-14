<?php
/*
 * attack_proxy.php
 *
 * runs attack demonstrations server-side using curl.
 * each attack gets its own cookie jar so sessions are independent
 * from the browser's main login session.
 *
 * called by app.js via ajax, returns json with step-by-step results.
 */

header('Content-Type: application/json');

$BACKEND = getenv('BACKEND_URL') ?: 'http://backend:5000';

// which attack to run
$attack = isset($_POST['attack']) ? $_POST['attack'] : '';

switch ($attack) {
    case 'brute_force':
        echo json_encode(attack_brute_force());
        break;
    case 'totp_replay':
        echo json_encode(attack_totp_replay());
        break;
    case 'jwt_tamper':
        echo json_encode(attack_jwt_tamper());
        break;
    case 'jwt_none':
        echo json_encode(attack_jwt_none());
        break;
    default:
        echo json_encode(['error' => 'unknown attack type']);
        http_response_code(400);
}
exit;


// =========================================================
//  ATTACK 1: Brute Force
// =========================================================

function attack_brute_force() {
    global $BACKEND;
    $steps = [];

    // reset server state
    http_post("$BACKEND/reset", []);
    $steps[] = step(200, 'Reset server state', 'Clean slate for the test');

    // register target user
    $r = http_post("$BACKEND/register", [
        'username' => 'alice',
        'password' => 'correcthorsebatterystaple'
    ]);
    $steps[] = step($r['status'], 'Registered user "alice"', 'Password: correcthorsebatterystaple');

    // try common passwords
    $passwords = ['password', '123456', 'qwerty', 'admin', 'letmein', 'welcome', 'monkey', 'dragon'];
    $blocked = false;

    foreach ($passwords as $i => $pw) {
        $r = http_post("$BACKEND/login/step1", [
            'username' => 'alice',
            'password' => $pw
        ]);
        $num = $i + 1;

        if ($r['status'] == 429) {
            $steps[] = step(429, "Attempt $num: \"$pw\"", 'LOCKED OUT - HTTP 429');
            $blocked = true;
            break;
        } elseif ($r['status'] == 200) {
            $steps[] = step(200, "Attempt $num: \"$pw\"", 'Password matched!');
            break;
        } else {
            $steps[] = step(401, "Attempt $num: \"$pw\"", 'Wrong password');
        }
    }

    return [
        'steps' => $steps,
        'blocked' => $blocked,
        'summary' => $blocked
            ? "Account locked after " . count($steps) - 2 . " failed attempts. Attacker must wait 60s."
            : "Brute force was NOT stopped."
    ];
}


// =========================================================
//  ATTACK 2: TOTP Replay
// =========================================================

function attack_totp_replay() {
    global $BACKEND;
    $steps = [];

    http_post("$BACKEND/reset", []);
    $steps[] = step(200, 'Reset server state', '');

    // register bob
    $r = http_post("$BACKEND/register", ['username' => 'bob', 'password' => 'Password123']);
    $secret = $r['body']['totp_secret'] ?? '';
    $steps[] = step($r['status'], 'Registered user "bob"', "TOTP secret: $secret");

    // legitimate user completes step 1
    $jar_legit = tempnam(sys_get_temp_dir(), 'atk_');
    $r = http_post("$BACKEND/login/step1", ['username' => 'bob', 'password' => 'Password123'], $jar_legit);
    $steps[] = step($r['status'], 'Legitimate user: step 1 (password)', '');

    // generate TOTP code
    $code = totp_code($secret);
    $steps[] = step(0, "Intercepted TOTP code: $code", 'Attacker captures this via phishing/shoulder surfing');

    // legitimate user uses the code
    $r = http_post("$BACKEND/login/step2", ['code' => $code], $jar_legit);
    $steps[] = step($r['status'], "Legitimate user: step 2 (TOTP code $code)", $r['body']['message'] ?? '');

    // attacker opens new session and tries the same code
    $jar_attacker = tempnam(sys_get_temp_dir(), 'atk_');
    $r = http_post("$BACKEND/login/step1", ['username' => 'bob', 'password' => 'Password123'], $jar_attacker);
    $steps[] = step($r['status'], 'Attacker: step 1 (password)', 'New session');

    $r = http_post("$BACKEND/login/step2", ['code' => $code], $jar_attacker);
    $steps[] = step($r['status'], "Attacker: replays same code $code", $r['body']['error'] ?? $r['body']['message'] ?? '');

    $blocked = ($r['status'] == 401);

    // cleanup
    @unlink($jar_legit);
    @unlink($jar_attacker);

    return [
        'steps' => $steps,
        'blocked' => $blocked,
        'summary' => $blocked
            ? "Replayed TOTP code rejected. Nonce cache prevents reuse within the valid window."
            : "Replay was NOT blocked."
    ];
}


// =========================================================
//  ATTACK 3: JWT Signature Tampering
// =========================================================

function attack_jwt_tamper() {
    global $BACKEND;
    $steps = [];

    http_post("$BACKEND/reset", []);
    $steps[] = step(200, 'Reset server state', '');

    // register carol and admin
    $r = http_post("$BACKEND/register", ['username' => 'carol', 'password' => 'Password123']);
    $secret_carol = $r['body']['totp_secret'] ?? '';
    $steps[] = step($r['status'], 'Registered user "carol"', '');

    http_post("$BACKEND/register", ['username' => 'admin', 'password' => 'AdminPass99']);
    $steps[] = step(201, 'Registered user "admin"', 'The impersonation target');

    // carol logs in through step 1 + step 2
    $jar = tempnam(sys_get_temp_dir(), 'atk_');
    http_post("$BACKEND/login/step1", ['username' => 'carol', 'password' => 'Password123'], $jar);
    $code = totp_code($secret_carol);
    http_post("$BACKEND/login/step2", ['code' => $code], $jar);
    $steps[] = step(200, 'Carol completed step 1 + step 2', '');

    // generate a valid device token for carol
    $valid_token = generate_jwt('carol');
    $steps[] = step(0, 'Generated valid JWT for carol', 'sub: carol');

    // decode, tamper, re-encode with WRONG signature
    $parts = explode('.', $valid_token);
    $payload = json_decode(base64url_decode($parts[1]), true);
    $payload['sub'] = 'admin';
    $tampered_payload = base64url_encode(json_encode($payload));
    $tampered_token = $parts[0] . '.' . $tampered_payload . '.' . $parts[2];
    $steps[] = step(0, 'Tampered payload: sub changed to "admin"', 'Kept original signature (now invalid)');

    // try the tampered token
    $r = http_post("$BACKEND/login/step3/request", ['device_token' => $tampered_token], $jar);
    $steps[] = step($r['status'], 'Submitted tampered JWT to step 3', $r['body']['error'] ?? $r['body']['message'] ?? '');

    $blocked = ($r['status'] == 401);
    @unlink($jar);

    return [
        'steps' => $steps,
        'blocked' => $blocked,
        'summary' => $blocked
            ? "HMAC-SHA256 detected the modified payload. Signature mismatch."
            : "Tampered JWT was NOT rejected."
    ];
}


// =========================================================
//  ATTACK 4: JWT "none" Algorithm
// =========================================================

function attack_jwt_none() {
    global $BACKEND;
    $steps = [];

    http_post("$BACKEND/reset", []);
    $steps[] = step(200, 'Reset server state', '');

    $r = http_post("$BACKEND/register", ['username' => 'dave', 'password' => 'Password123']);
    $secret = $r['body']['totp_secret'] ?? '';
    $steps[] = step($r['status'], 'Registered user "dave"', '');

    // dave logs in through step 1 + 2
    $jar = tempnam(sys_get_temp_dir(), 'atk_');
    http_post("$BACKEND/login/step1", ['username' => 'dave', 'password' => 'Password123'], $jar);
    $code = totp_code($secret);
    http_post("$BACKEND/login/step2", ['code' => $code], $jar);
    $steps[] = step(200, 'Dave completed step 1 + step 2', '');

    // forge a token with alg=none - no key needed
    $header = base64url_encode(json_encode(['alg' => 'none', 'typ' => 'JWT']));
    $payload = base64url_encode(json_encode([
        'sub' => 'dave',
        'exp' => 9999999999,
        'iat' => time(),
        'jti' => 'forged-no-key'
    ]));
    $forged = $header . '.' . $payload . '.';
    $steps[] = step(0, 'Forged JWT with alg: none', 'No signing key used, empty signature');

    // submit forged token
    $r = http_post("$BACKEND/login/step3/request", ['device_token' => $forged], $jar);
    $steps[] = step($r['status'], 'Submitted forged JWT to step 3', $r['body']['error'] ?? $r['body']['message'] ?? '');

    $blocked = ($r['status'] == 401);
    @unlink($jar);

    return [
        'steps' => $steps,
        'blocked' => $blocked,
        'summary' => $blocked
            ? "Algorithm whitelist rejected alg=none. Only HS256 is accepted."
            : "Forged JWT was NOT rejected."
    ];
}


// =========================================================
//  HELPERS
// =========================================================

function step($status, $label, $detail) {
    return ['status' => $status, 'label' => $label, 'detail' => $detail];
}


/**
 * send a POST request with JSON body, optionally using a cookie jar for sessions
 */
function http_post($url, $data, $cookie_file = null) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);

    if ($cookie_file) {
        curl_setopt($ch, CURLOPT_COOKIEJAR, $cookie_file);
        curl_setopt($ch, CURLOPT_COOKIEFILE, $cookie_file);
    }

    $response = curl_exec($ch);
    $status   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return [
        'status' => (int)$status,
        'body'   => json_decode($response, true) ?: []
    ];
}


/**
 * generate a TOTP code from a base32 secret (RFC 6238)
 */
function totp_code($secret) {
    $key  = base32_decode($secret);
    $time = intdiv(time(), 30);
    $msg  = pack('N*', 0) . pack('N*', $time);
    $hash = hash_hmac('sha1', $msg, $key, true);

    $offset = ord(substr($hash, -1)) & 0x0F;
    $code = (
        ((ord($hash[$offset])     & 0x7F) << 24) |
        ((ord($hash[$offset + 1]) & 0xFF) << 16) |
        ((ord($hash[$offset + 2]) & 0xFF) << 8)  |
         (ord($hash[$offset + 3]) & 0xFF)
    ) % 1000000;

    return str_pad($code, 6, '0', STR_PAD_LEFT);
}

function base32_decode($input) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $input    = strtoupper(rtrim($input, '='));
    $output   = '';
    $buffer   = 0;
    $bitsLeft = 0;

    for ($i = 0; $i < strlen($input); $i++) {
        $val = strpos($alphabet, $input[$i]);
        if ($val === false) continue;
        $buffer   = ($buffer << 5) | $val;
        $bitsLeft += 5;
        if ($bitsLeft >= 8) {
            $bitsLeft -= 8;
            $output .= chr(($buffer >> $bitsLeft) & 0xFF);
        }
    }
    return $output;
}


/**
 * generate a signed JWT (HS256) matching what jwt_utils.py produces.
 * uses the same default SECRET_KEY from config.py.
 */
function generate_jwt($username) {
    $key = getenv('SECRET_KEY')
        ?: 'a3f8c2e1d4b7a9f0e5c3b2d1a8f6e4c7b3d2a1f9e8c7b6a5d4c3b2a1f0e9d8';

    $header = base64url_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload = base64url_encode(json_encode([
        'sub' => $username,
        'iat' => time(),
        'exp' => time() + 3600,
        'jti' => bin2hex(random_bytes(16)),
        'ua'  => 'TripleAuth-Frontend/1.0',
        'ip'  => '172.18.0.1'      // docker bridge ip, close enough
    ]));
    $signature = base64url_encode(
        hash_hmac('sha256', "$header.$payload", $key, true)
    );

    return "$header.$payload.$signature";
}

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}
