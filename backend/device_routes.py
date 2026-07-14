from flask import Blueprint, request, jsonify, session
import time
import smtplib
import config
import models
import jwt_utils

device_bp = Blueprint('device', __name__) 

# store pending OOB otps: username -> (otp_code, issued_at)
# in a real app this would go in a database or redis
pending_oobs = {}


@device_bp.route('/login/step3/request', methods=['POST'])
def step3_request():
    """
    first part of step 3.
    client sends their device token. if valid, we generate an OOB otp
    and 'send' it via telegram/email. client then calls step3/verify.
    """
    if session.get('auth_step') != 2:
        return jsonify({'error': 'complete step 2 first'}), 403

    # check step2 didnt expire
    if time.time() - session.get('step2_time', 0) > 300:
        session.clear()
        return jsonify({'error': 'session expired, start over'}), 401

    data = request.get_json()
    if not data or 'device_token' not in data:
        return jsonify({'error': 'missing device_token'}), 400

    username = session.get('auth_user')
    token = data['device_token']
    ua = request.headers.get('User-Agent', '')
    ip = request.remote_addr

    ok, result = jwt_utils.verify_device_token(token, ua, ip)
    if not ok:
        return jsonify({'error': f'device token invalid: {result}'}), 401

    payload = result

    # make sure the token belongs to the right user
    if payload.get('sub') != username:
        return jsonify({'error': 'token does not belong to this user'}), 401

    ua_mismatch = payload.get('_ua_mismatch', False)

    # generate the OOB otp and store it
    otp = jwt_utils.generate_oob_otp()
    pending_oobs[username] = (otp, time.time())

    # try to send it - we use email here since telegram needs a bot token
    # which i dont want to hardcode. swap in send_telegram() easily.
    delivery_ok = _send_oob_otp(username, otp)

    response = {
        'message': 'device token ok, OTP sent via out-of-band channel',
        'next_step': '/login/step3/verify'
    }
    if ua_mismatch:
        response['warning'] = 'device user-agent changed since token was issued'
    if not delivery_ok:
        # for testing: if no email is configured, just return the OTP directly
        # remove this in production obviously
        response['dev_otp'] = otp
        response['note'] = 'OTP delivery not configured - shown here for testing only'

    return jsonify(response), 200


@device_bp.route('/login/step3/verify', methods=['POST'])
def step3_verify():
    """
    second part of step 3.
    user enters the OTP they received out-of-band.
    if correct, login is complete and we issue a final session token.
    """
    if session.get('auth_step') != 2:
        return jsonify({'error': 'complete step 2 first'}), 403

    data = request.get_json()
    if not data or 'otp' not in data:
        return jsonify({'error': 'missing otp'}), 400

    username = session.get('auth_user')
    submitted_otp = data['otp'].strip()

    if username not in pending_oobs:
        return jsonify({'error': 'no OTP was requested for this user'}), 400

    stored_otp, issued_at = pending_oobs[username]

    # OTPs expire after 2 minutes - short window to limit interception risk
    if time.time() - issued_at > 120:
        del pending_oobs[username]
        return jsonify({'error': 'OTP expired, request a new one'}), 401

    # use hmac.compare_digest instead of == to prevent timing attacks
    # (== short-circuits on first mismatch, leaking how many chars matched)
    import hmac
    if not hmac.compare_digest(submitted_otp, stored_otp):
        return jsonify({'error': 'wrong OTP'}), 401

    # all 3 factors passed - clean up and issue final token
    del pending_oobs[username]
    models.reset_attempts(username)
    session.clear()

    # generate the final access token
    ua = request.headers.get('User-Agent', '')
    ip = request.remote_addr
    access_token = jwt_utils.generate_device_token(username, ua, ip)

    return jsonify({
        'message': 'authentication complete - all 3 factors verified',
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': config.JWT_EXPIRY
    }), 200


def _send_oob_otp(username, otp):
    """
    send the OTP via out-of-band channel.
    tries telegram first, falls back to email, falls back to console print.
    returns True if delivery succeeded through any real channel.
    """
    print(f"\n[OOB DELIVERY] User: {username} | OTP: {otp}\n")

    # try telegram if configured
    bot_token = config.TELEGRAM_BOT_TOKEN
    chat_id   = config.TELEGRAM_CHAT_IDS.get(username)
    if bot_token and chat_id:
        ok = _send_telegram(bot_token, chat_id, otp)
        if ok:
            return True

    # try email if configured
    if config.SMTP_HOST and config.SMTP_USER:
        user_email = config.USER_EMAILS.get(username)
        if user_email:
            ok = _send_email(user_email, otp)
            if ok:
                return True

    # nothing configured - caller will expose otp in response for dev testing
    return False


def _send_telegram(bot_token, chat_id, otp):
    """send OTP via telegram bot"""
    import requests as req
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    msg = f"Your TripleAuth login code: *{otp}*\n\nExpires in 2 minutes."
    try:
        r = req.post(url, json={'chat_id': chat_id, 'text': msg, 'parse_mode': 'Markdown'}, timeout=5)
        if r.status_code == 200:
            print(f"[OOB] telegram delivery ok for chat {chat_id}")
            return True
        print(f"[OOB] telegram error: {r.text}")
        return False
    except Exception as e:
        print(f"[OOB] telegram exception: {e}")
        return False


def _send_email(to_address, otp):
    """send OTP via smtp email"""
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as s:
            s.starttls()
            s.login(config.SMTP_USER, config.SMTP_PASS)
            msg = (
                f"From: {config.SMTP_USER}\r\n"
                f"To: {to_address}\r\n"
                f"Subject: Your login code\r\n\r\n"
                f"Your TripleAuth login code is: {otp}\n"
                f"It expires in 2 minutes."
            )
            s.sendmail(config.SMTP_USER, to_address, msg)
        print(f"[OOB] email delivery ok to {to_address}")
        return True
    except Exception as e:
        print(f"[OOB] email exception: {e}")
        return False
