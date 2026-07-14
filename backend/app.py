from flask import Flask, request, jsonify, session, render_template
import time
import qrcode
import io
import base64
import config
import models
from totp_routes import totp_bp
from device_routes import device_bp

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# register blueprints
app.register_blueprint(totp_bp)
app.register_blueprint(device_bp)


# ---- registration ----

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'missing username or password'}), 400

    username = data['username'].strip()
    password = data['password']

    # basic input validation - prevent silly long inputs
    if not username or len(username) > 64:
        return jsonify({'error': 'username must be 1-64 characters'}), 400
    if not username.isalnum() and '_' not in username:
        return jsonify({'error': 'username: letters, numbers and underscores only'}), 400
    if len(password) > 256:
        return jsonify({'error': 'password too long'}), 400

    ok, result = models.register_user(username, password)
    if not ok:
        return jsonify({'error': result}), 400

    user = result
    # return the QR code so the user can scan it with an authenticator app
    qr_uri = user.get_totp_uri()
    qr_img = _make_qr_base64(qr_uri)

    return jsonify({
        'message': 'registered successfully',
        'username': username,
        'totp_secret': user.totp_secret,  # also show raw secret as backup
        'qr_code': qr_img  # base64 png, frontend can display it directly
    }), 201


def _make_qr_base64(uri):
    """generate a qr code and return it as a base64 string"""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


# ---- login step 1: password ----

@app.route('/login/step1', methods=['POST'])
def login_step1():
    """first factor - just username and password"""
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'missing fields'}), 400

    username = data['username'].strip()
    password = data['password']

    # check lockout before doing anything else
    if models.is_locked_out(username):
        return jsonify({
            'error': 'account locked - too many failed attempts',
            'retry_after': config.LOCKOUT_TIME
        }), 429

    user = models.get_user(username)

    # important: we check password even if user doesnt exist to prevent timing attacks
    # (if we returned immediately for unknown users, attacker could tell users apart by response time)
    if user is None:
        # generate a real throwaway hash to compare against - same cost as a real check
        import bcrypt as _bcrypt
        _bcrypt.checkpw(password.encode(), _bcrypt.hashpw(b'dummy', _bcrypt.gensalt(rounds=4)))
        models.record_failed_attempt(username)
        return jsonify({'error': 'invalid credentials'}), 401

    if not user.check_password(password):
        models.record_failed_attempt(username)
        return jsonify({'error': 'invalid credentials'}), 401

    # password ok - save username in session and move to step 2
    session['auth_step'] = 1
    session['auth_user'] = username
    session['step1_time'] = time.time()

    return jsonify({
        'message': 'password ok, proceed to TOTP verification',
        'next_step': '/login/step2'
    }), 200


# ---- simple status endpoint for testing ----

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        'status': 'running',
        'registered_users': list(config.users.keys())
    })


@app.route('/reset', methods=['POST'])
def reset():
    """wipe all state - only for testing, would never exist in production"""
    config.users.clear()
    config.failed_attempts.clear()
    config.used_otps.clear()
    return jsonify({'message': 'state reset'})


@app.route('/qr/<username>', methods=['GET'])
def show_qr(username):
    """renders the qr code page for a registered user - just for setup convenience"""
    user = models.get_user(username)
    if user is None:
        return jsonify({'error': 'user not found'}), 404
    qr_code = _make_qr_base64(user.get_totp_uri())
    return render_template('qr.html',
        qr_code=qr_code,
        totp_secret=user.totp_secret,
        username=username
    )


if __name__ == '__main__':
    # debug=True is fine for development, would turn off in production
    # use_reloader=False so it works when started in background during testing
    app.run(debug=True, port=5000, use_reloader=False)


# ---- global error handlers ----
# without these flask returns html error pages which look weird for an api

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'method not allowed'}), 405

@app.errorhandler(500)
def internal_error(e):
    # dont leak exception details to the client
    return jsonify({'error': 'internal server error'}), 500
