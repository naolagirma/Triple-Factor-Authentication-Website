from flask import Blueprint, request, jsonify, session
import time
import config
import models

totp_bp = Blueprint('totp', __name__)


# ---- login step 2: TOTP ----

@totp_bp.route('/login/step2', methods=['POST'])
def login_step2():
    """second factor - verify the TOTP code from authenticator app"""

    # make sure they actually completed step 1 first
    if session.get('auth_step') != 1:
        return jsonify({'error': 'complete step 1 first'}), 403

    # also check that step1 wasnt too long ago - 5 minutes max
    # dont want someone sitting on a completed step1 forever
    step1_time = session.get('step1_time', 0)
    if time.time() - step1_time > 300:
        session.clear()
        return jsonify({'error': 'session expired, start over'}), 401

    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({'error': 'missing totp code'}), 400

    username = session.get('auth_user')
    user = models.get_user(username)

    if user is None:
        # shouldnt happen but just in case
        session.clear()
        return jsonify({'error': 'something went wrong'}), 500

    code = data['code'].strip()

    # check if this exact code was already used recently (replay attack prevention)
    if _is_otp_used(code, username):
        return jsonify({'error': 'code already used'}), 401

    if not user.verify_totp(code):
        return jsonify({'error': 'invalid or expired code'}), 401

    # mark this code as used so it cant be replayed
    _mark_otp_used(code, username)

    # step 2 done - move to step 3
    session['auth_step'] = 2
    session['step2_time'] = time.time()

    return jsonify({
        'message': 'TOTP ok, proceed to device verification',
        'next_step': '/login/step3'
    }), 200


def _is_otp_used(code, username):
    """check if this otp code was already used in the valid window"""
    key = f"{username}:{code}"
    if key not in config.used_otps:
        return False
    used_at = config.used_otps[key]
    # codes are only valid for ~90 seconds (30s window * 3 with valid_window=1)
    # so we only need to remember them for that long
    if time.time() - used_at > 90:
        del config.used_otps[key]
        return False
    return True


def _mark_otp_used(code, username):
    """record that this otp was used"""
    key = f"{username}:{code}"
    config.used_otps[key] = time.time()
    # also clean up old entries while we're here
    # not the most efficient but fine for a small project
    _cleanup_used_otps()


def _cleanup_used_otps():
    """remove expired entries from the used otps store"""
    now = time.time()
    expired = [k for k, t in config.used_otps.items() if now - t > 90]
    for k in expired:
        del config.used_otps[k]
