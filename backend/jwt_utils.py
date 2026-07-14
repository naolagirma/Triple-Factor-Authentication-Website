import jwt
import time
import uuid
import config

# i chose HS256 (HMAC-SHA256) because its simpler than RSA for this project
# but we MUST explicitly whitelist the algorithm - this is what prevents the
# "none" algorithm attack where an attacker strips the signature entirely
ALLOWED_ALGORITHMS = ['HS256']


def generate_device_token(username, user_agent, ip_address):
    """
    create a signed JWT that represents a trusted device session.
    we bind it to the user agent and ip so a stolen token cant easily be reused
    from a different machine.
    """
    now = time.time()
    payload = {
        'sub': username,            # subject - who the token belongs to
        'iat': now,                 # issued at
        'exp': now + config.JWT_EXPIRY,  # expiry
        'jti': str(uuid.uuid4()),   # unique token id - helps with revocation later
        # binding the token to device info makes it harder to steal and reuse
        'ua':  user_agent[:100] if user_agent else 'unknown',
        'ip':  ip_address
    }
    token = jwt.encode(payload, config.SECRET_KEY, algorithm='HS256')
    return token


def verify_device_token(token, user_agent, ip_address):
    """
    verify a JWT token.
    returns (True, payload) if valid, (False, error_message) if not.
    """
    if not token:
        return False, "no token provided"

    try:
        # IMPORTANT: we pass algorithms= explicitly here
        # if we used jwt.decode(token, key) without algorithms=, older versions of
        # PyJWT would accept algorithm="none" in the header, which means NO signature.
        # an attacker could forge any payload and the server would trust it.
        # always whitelist algorithms explicitly.
        payload = jwt.decode(
            token,
            config.SECRET_KEY,
            algorithms=ALLOWED_ALGORITHMS
        )
    except jwt.ExpiredSignatureError:
        return False, "token expired"
    except jwt.InvalidTokenError as e:
        # catching broad InvalidTokenError covers tampered signature, malformed token, etc
        return False, f"invalid token: {str(e)}"

    # check device binding - warn if it doesnt match but dont hard fail
    # (ip can change on mobile networks, so we just log it for now)
    token_ua = payload.get('ua', '')
    if token_ua and user_agent and token_ua != user_agent[:100]:
        # in a real system this would trigger a step-up auth or alert
        # for now we just note it in the response
        return True, {**payload, '_ua_mismatch': True}

    return True, payload


def generate_oob_otp():
    """
    generate a simple 6-digit OTP for out-of-band delivery.
    using secrets module instead of random because random isnt
    cryptographically secure - secrets uses the OS entropy source.
    """
    import secrets
    # secrets.randbelow gives uniform distribution up to N
    # zero-pad to always get 6 digits (e.g. 000123)
    return str(secrets.randbelow(1000000)).zfill(6)
