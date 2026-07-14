<?php
/*
 * generate_token.php
 *
 * generates a signed JWT device token for step 3 of the login flow.
 * the browser can't do this because it doesn't have the secret key,
 * so we do it server-side in php using the same key as config.py.
 *
 * in a real application the device token would come from a previously
 * registered device, not generated on the fly like this.
 */

header('Content-Type: application/json');

$username = isset($_POST['username']) ? trim($_POST['username']) : '';

if (!$username) {
    http_response_code(400);
    echo json_encode(['error' => 'missing username']);
    exit;
}

$key = getenv('SECRET_KEY')
    ?: 'a3f8c2e1d4b7a9f0e5c3b2d1a8f6e4c7b3d2a1f9e8c7b6a5d4c3b2a1f0e9d8';

$header = base64url_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
$payload = base64url_encode(json_encode([
    'sub' => $username,
    'iat' => time(),
    'exp' => time() + 3600,
    'jti' => bin2hex(random_bytes(16)),
    'ua'  => 'TripleAuth-Frontend/1.0',
    'ip'  => '172.18.0.1'
]));
$signature = base64url_encode(
    hash_hmac('sha256', "$header.$payload", $key, true)
);

$token = "$header.$payload.$signature";

echo json_encode(['token' => $token]);


function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
