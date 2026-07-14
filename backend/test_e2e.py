"""
end-to-end test for the triple factor auth system.
spins up the flask server internally, runs all scenarios, then shuts it down.
run with: python test_e2e.py
"""

import subprocess, time, requests, pyotp, base64, json
import jwt_utils

proc = subprocess.Popen(['python', '-c', '''
from app import app
app.run(debug=False, port=5000, use_reloader=False, threaded=True)
'''], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
time.sleep(2)

BASE = 'http://localhost:5000'
s    = requests.Session()
UN, PW = 'testuser_e2e', 'hunter22_secure'
passed = failed = 0

def ok(label, cond):
    global passed, failed
    print(f'  {"✓" if cond else "✗"} {label}')
    if cond: passed += 1
    else:    failed += 1

def sep(t): print(f'\n=== {t} ===')

# wipe state so tests are repeatable
requests.post(f'{BASE}/reset')


# ---- registration ----
sep('REGISTRATION')
r = s.post(f'{BASE}/register', json={'username': UN, 'password': PW})
ok(f'register 201 (got {r.status_code})', r.status_code == 201)
data = r.json()
totp_secret = data['totp_secret']
ok('has totp_secret', bool(totp_secret))
ok('has qr_code',     'qr_code' in data)


# ---- step 1: password ----
sep('STEP 1 - password (happy path)')
r = s.post(f'{BASE}/login/step1', json={'username': UN, 'password': PW})
ok(f'step1 200 (got {r.status_code})', r.status_code == 200)

r2 = requests.Session().post(f'{BASE}/login/step1', json={'username': UN, 'password': 'wrong'})
ok(f'wrong pw 401 (got {r2.status_code})', r2.status_code == 401)

sep('STEP 1 - brute force lockout')
sl = requests.Session()
requests.post(f'{BASE}/register', json={'username': UN+'_lk', 'password': PW})
for _ in range(6):
    sl.post(f'{BASE}/login/step1', json={'username': UN+'_lk', 'password': 'wrong'})
r = sl.post(f'{BASE}/login/step1', json={'username': UN+'_lk', 'password': PW})
ok(f'lockout 429 (got {r.status_code})', r.status_code == 429)


# ---- step 2: totp ----
sep('STEP 2 - TOTP (happy path)')
code = pyotp.TOTP(totp_secret).now()
r = s.post(f'{BASE}/login/step2', json={'code': code})
ok(f'step2 200 (got {r.status_code})', r.status_code == 200)

sep('STEP 2 - replay attack')
sr = requests.Session()
sr.post(f'{BASE}/login/step1', json={'username': UN, 'password': PW})
r = sr.post(f'{BASE}/login/step2', json={'code': code})  # reuse same code
ok(f'replay blocked 401 (got {r.status_code})', r.status_code == 401)

sw = requests.Session()
sw.post(f'{BASE}/login/step1', json={'username': UN, 'password': PW})
r = sw.post(f'{BASE}/login/step2', json={'code': '000000'})
ok(f'wrong code 401 (got {r.status_code})', r.status_code == 401)


# ---- step 3: device JWT + OOB OTP ----
sep('STEP 3 - device JWT + OOB OTP (happy path)')
device_token = jwt_utils.generate_device_token(UN, 'TestClient/1.0', '127.0.0.1')
r = s.post(f'{BASE}/login/step3/request', json={'device_token': device_token})
ok(f'step3/request 200 (got {r.status_code})', r.status_code == 200)
oob_otp = r.json().get('dev_otp')
ok('got dev_otp in response', bool(oob_otp))
print(f'  OTP delivered: {oob_otp}')

r = s.post(f'{BASE}/login/step3/verify', json={'otp': oob_otp})
ok(f'step3/verify 200 (got {r.status_code})', r.status_code == 200)
ok('has access_token', 'access_token' in r.json())
ok('token_type is Bearer', r.json().get('token_type') == 'Bearer')
print(f'  access token:  {r.json()["access_token"][:55]}...')

sep('STEP 3 - tampered JWT')
rt = requests.post(f'{BASE}/register', json={'username': UN+'_t', 'password': PW})
st = requests.Session()
st.post(f'{BASE}/login/step1', json={'username': UN+'_t', 'password': PW})
st.post(f'{BASE}/login/step2', json={'code': pyotp.TOTP(rt.json()['totp_secret']).now()})
r = st.post(f'{BASE}/login/step3/request', json={'device_token': device_token[:-8]+'XXXXXXXX'})
ok(f'tampered token 401 (got {r.status_code})', r.status_code == 401)

sep('STEP 3 - none algorithm attack')
rn = requests.post(f'{BASE}/register', json={'username': UN+'_n', 'password': PW})
sn = requests.Session()
sn.post(f'{BASE}/login/step1', json={'username': UN+'_n', 'password': PW})
sn.post(f'{BASE}/login/step2', json={'code': pyotp.TOTP(rn.json()['totp_secret']).now()})
h = base64.urlsafe_b64encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps({'sub': UN+'_n', 'exp': 9999999999}).encode()).rstrip(b'=')
forged = h.decode() + '.' + p.decode() + '.'
r = sn.post(f'{BASE}/login/step3/request', json={'device_token': forged})
ok(f'none-alg forged token 401 (got {r.status_code})', r.status_code == 401)


proc.terminate()
print(f'\n  {passed} passed  |  {failed} failed')
