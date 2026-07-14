/*
 * app.js - handles the login flow and attack simulator panel
 * talks to the flask backend through the nginx reverse proxy (/api/...)
 * attack simulations go through attack_proxy.php which uses curl server-side
 * so each attack gets its own independent session
 *
 * state is persisted to localStorage so a browser refresh doesnt wipe progress
 */

var API = '/api';
var state = loadState();


// =========================================================
//  STATE PERSISTENCE (fixes the refresh problem)
// =========================================================

function loadState() {
    try {
        var saved = localStorage.getItem('tripleauth_state');
        if (saved) return JSON.parse(saved);
    } catch(e) {}
    return { username: '', password: '', totpSecret: '', deviceToken: '', page: 'landing' };
}

function saveState() {
    try {
        localStorage.setItem('tripleauth_state', JSON.stringify(state));
    } catch(e) {}
}

function clearState() {
    state = { username: '', password: '', totpSecret: '', deviceToken: '', page: 'landing' };
    try { localStorage.removeItem('tripleauth_state'); } catch(e) {}
}


// =========================================================
//  UI helpers
// =========================================================

function showSection(id) {
    $('#section-landing, #section-register, #section-step1, #section-step2, #section-step3, #section-success').hide();
    $('#' + id).fadeIn(200);

    // show stepper only during login steps
    var isLoginStep = (id === 'section-step1' || id === 'section-step2' || id === 'section-step3');
    $('#stepper').toggle(isLoginStep);

    // track current page
    state.page = id;
    saveState();
}

function setStep(stepName) {
    var order = ['s1', 's2', 's3'];
    var hit = false;
    for (var i = 0; i < order.length; i++) {
        var el = $('#indicator-' + order[i]);
        if (order[i] === stepName) {
            el.removeClass('done').addClass('active');
            hit = true;
        } else if (!hit) {
            el.removeClass('active').addClass('done');
        } else {
            el.removeClass('active done');
        }
    }
}

function showToast(message, type) {
    // type: 'error', 'success', 'info'
    type = type || 'info';
    var toast = $('<div class="toast toast-' + type + '">' + escapeHtml(message) + '</div>');
    $('#toast-container').append(toast);
    setTimeout(function() { toast.addClass('show'); }, 10);
    setTimeout(function() {
        toast.removeClass('show');
        setTimeout(function() { toast.remove(); }, 300);
    }, 4000);
}

function setLoading(btn, loading) {
    if (loading) {
        btn.data('original-text', btn.text());
        btn.prop('disabled', true).text('Loading...');
    } else {
        btn.prop('disabled', false).text(btn.data('original-text') || btn.text());
    }
}

function logResponse(status, data, label) {
    var cls = 's2xx';
    if (status >= 400 && status < 500) cls = 's4xx';
    if (status >= 500) cls = 's5xx';
    var time = new Date().toLocaleTimeString();
    var body = typeof data === 'object' ? JSON.stringify(data, null, 2) : data;
    var prefix = label ? '<strong>' + label + '</strong> ' : '';

    var html = '<div class="log-entry">'
        + '<span class="log-status ' + cls + '">' + status + '</span>'
        + prefix
        + '<span class="log-time">' + time + '</span>'
        + '<div class="log-body">' + escapeHtml(body) + '</div>'
        + '</div>';
    $('#response-log').prepend(html);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}


// =========================================================
//  NAVIGATION (separate register / login)
// =========================================================

$('#btn-land-register, #nav-register').on('click', function(e) {
    e.preventDefault();
    showSection('section-register');
});

$('#btn-land-login, #nav-login, #link-to-login').on('click', function(e) {
    e.preventDefault();
    showSection('section-step1');
    setStep('s1');
    // prefill if we have saved credentials
    if (state.username) $('#login-user').val(state.username);
    if (state.password) $('#login-pass').val(state.password);
});

$('#link-to-register').on('click', function(e) {
    e.preventDefault();
    showSection('section-register');
});


// =========================================================
//  REGISTRATION
// =========================================================

$('#form-register').on('submit', function(e) {
    e.preventDefault();
    var btn = $('#btn-register');
    var username = $('#reg-user').val().trim();
    var password = $('#reg-pass').val();

    if (password.length < 8) {
        showToast('Password must be at least 8 characters', 'error');
        return;
    }

    setLoading(btn, true);

    $.ajax({
        url: API + '/register',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ username: username, password: password }),
        success: function(data, textStatus, xhr) {
            state.username = username;
            state.password = password;
            state.totpSecret = data.totp_secret;
            saveState();

            // show QR code
            $('#qr-image').attr('src', 'data:image/png;base64,' + data.qr_code);
            $('#totp-secret-text').text(data.totp_secret);
            $('#qr-result').slideDown(300);

            showToast('Account created. Scan the QR code with your authenticator app.', 'success');
            logResponse(xhr.status, data, 'POST /register');
            setLoading(btn, false);
        },
        error: function(xhr) {
            var msg = (xhr.responseJSON && xhr.responseJSON.error) || 'Registration failed';
            showToast(msg, 'error');
            logResponse(xhr.status, xhr.responseJSON, 'POST /register');
            setLoading(btn, false);
        }
    });
});

// go to login after registration
$('#btn-goto-login').on('click', function() {
    showSection('section-step1');
    setStep('s1');
    $('#login-user').val(state.username);
    $('#login-pass').val(state.password);
});


// =========================================================
//  STEP 1 - PASSWORD
// =========================================================

$('#form-step1').on('submit', function(e) {
    e.preventDefault();
    var btn = $('#btn-step1');
    var username = $('#login-user').val().trim();
    var password = $('#login-pass').val();

    if (!username || !password) {
        showToast('Enter both username and password', 'error');
        return;
    }

    state.username = username;
    state.password = password;
    saveState();
    setLoading(btn, true);

    $.ajax({
        url: API + '/login/step1',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ username: username, password: password }),
        success: function(data, textStatus, xhr) {
            logResponse(xhr.status, data, 'POST /login/step1');
            showToast('Password verified', 'success');
            showSection('section-step2');
            setStep('s2');
            setLoading(btn, false);
        },
        error: function(xhr) {
            var msg = (xhr.responseJSON && xhr.responseJSON.error) || 'Login failed';
            showToast(msg, 'error');
            logResponse(xhr.status, xhr.responseJSON, 'POST /login/step1');
            setLoading(btn, false);
        }
    });
});


// =========================================================
//  STEP 2 - TOTP
// =========================================================

$('#form-step2').on('submit', function(e) {
    e.preventDefault();
    var btn = $('#btn-step2');
    var code = $('#totp-code').val().trim();

    if (!/^\d{6}$/.test(code)) {
        showToast('Enter a 6-digit code', 'error');
        return;
    }

    setLoading(btn, true);

    $.ajax({
        url: API + '/login/step2',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ code: code }),
        success: function(data, textStatus, xhr) {
            logResponse(xhr.status, data, 'POST /login/step2');
            showToast('TOTP verified', 'success');
            showSection('section-step3');
            setStep('s3');
            setLoading(btn, false);
        },
        error: function(xhr) {
            var msg = (xhr.responseJSON && xhr.responseJSON.error) || 'TOTP verification failed';
            showToast(msg, 'error');
            logResponse(xhr.status, xhr.responseJSON, 'POST /login/step2');
            setLoading(btn, false);
        }
    });
});


// =========================================================
//  STEP 3 - DEVICE JWT + OOB OTP
// =========================================================

$('#btn-step3-request').on('click', function() {
    var btn = $(this);
    setLoading(btn, true);

    $.ajax({
        url: '/generate_token.php',
        method: 'POST',
        data: { username: state.username },
        dataType: 'json',
        success: function(tokenData) {
            state.deviceToken = tokenData.token;
            saveState();

            $.ajax({
                url: API + '/login/step3/request',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({ device_token: state.deviceToken }),
                success: function(data, textStatus, xhr) {
                    logResponse(xhr.status, data, 'POST /login/step3/request');
                    $('#step3-request').hide();
                    $('#step3-verify').show();

                    if (data.dev_otp) {
                        $('#otp-hint').html(
                            '<strong>Dev mode:</strong> No delivery channel configured.<br>'
                            + 'OTP: <code>' + data.dev_otp + '</code>'
                        ).show();
                        $('#oob-otp').val(data.dev_otp);
                    } else {
                        showToast('OTP sent to your Telegram / email', 'success');
                    }
                    setLoading(btn, false);
                },
                error: function(xhr) {
                    var msg = (xhr.responseJSON && xhr.responseJSON.error) || 'Device token rejected';
                    showToast(msg, 'error');
                    logResponse(xhr.status, xhr.responseJSON, 'POST /login/step3/request');
                    setLoading(btn, false);
                }
            });
        },
        error: function() {
            showToast('Failed to generate device token', 'error');
            setLoading(btn, false);
        }
    });
});

$('#form-step3').on('submit', function(e) {
    e.preventDefault();
    var btn = $('#btn-step3');
    var otp = $('#oob-otp').val().trim();

    if (!/^\d{6}$/.test(otp)) {
        showToast('Enter a 6-digit OTP', 'error');
        return;
    }

    setLoading(btn, true);

    $.ajax({
        url: API + '/login/step3/verify',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ otp: otp }),
        success: function(data, textStatus, xhr) {
            logResponse(xhr.status, data, 'POST /login/step3/verify');
            showToast('All 3 factors verified!', 'success');
            $('#access-token-text').text(data.access_token);
            $('#token-expiry').text(data.expires_in + ' seconds');
            showSection('section-success');
            state.page = 'section-success';
            saveState();
        },
        error: function(xhr) {
            var msg = (xhr.responseJSON && xhr.responseJSON.error) || 'OTP verification failed';
            showToast(msg, 'error');
            logResponse(xhr.status, xhr.responseJSON, 'POST /login/step3/verify');
            setLoading(btn, false);
        }
    });
});


// =========================================================
//  LOGOUT (just resets frontend, keeps backend users)
// =========================================================

$('#btn-logout').on('click', function() {
    clearState();
    $('form').trigger('reset');
    $('#qr-result').hide();
    $('#step3-request').show();
    $('#step3-verify').hide();
    $('#otp-hint').hide();
    showSection('section-landing');
    showToast('Logged out', 'info');
});


// =========================================================
//  RESET SERVER (wipes backend state too)
// =========================================================

$('#btn-reset').on('click', function() {
    if (!confirm('This will delete ALL registered users from the server. Continue?')) return;

    $.post(API + '/reset', function() {
        clearState();
        $('form').trigger('reset');
        $('#qr-result').hide();
        $('#step3-request').show();
        $('#step3-verify').hide();
        $('#otp-hint').hide();
        showSection('section-landing');
        showToast('Server state wiped. All users deleted.', 'info');
    });
});


// =========================================================
//  CLEAR LOG
// =========================================================

$('#btn-clear-log').on('click', function() {
    $('#response-log').empty();
});


// =========================================================
//  ATTACK PANEL TOGGLE
// =========================================================

$('#btn-toggle-attack').on('click', function() {
    $('#attack-panel').toggleClass('open');
    $(this).toggleClass('open');
});


// =========================================================
//  ATTACK SIMULATOR
// =========================================================

$('.btn-attack').on('click', function() {
    var btn = $(this);
    var attackType = btn.data('attack');
    var logEl = $('#log-' + attackType);

    btn.prop('disabled', true);
    logEl.html('<div class="atk-loading">&#9881; Running attack against live server...</div>');

    $.ajax({
        url: '/attack_proxy.php',
        method: 'POST',
        data: { attack: attackType },
        dataType: 'json',
        timeout: 30000,
        success: function(data) {
            renderAttackResults(logEl, data);
            btn.prop('disabled', false);
        },
        error: function(xhr) {
            var msg = xhr.responseText || 'Network error or timeout';
            logEl.html('<div class="atk-result failed">Error: ' + escapeHtml(msg) + '</div>');
            btn.prop('disabled', false);
        }
    });
});

function renderAttackResults(container, data) {
    var html = '';
    if (data.steps) {
        for (var i = 0; i < data.steps.length; i++) {
            var s = data.steps[i];
            var badgeClass = 'amber';
            if (s.status >= 200 && s.status < 300) badgeClass = 'green';
            if (s.status >= 400) badgeClass = 'red';
            html += '<div class="atk-step">';
            html += '<span class="status-badge ' + badgeClass + '">' + s.status + '</span> ';
            html += escapeHtml(s.label);
            if (s.detail) {
                html += ' <span style="color:#64748b;">&mdash; ' + escapeHtml(s.detail) + '</span>';
            }
            html += '</div>';
        }
    }
    if (data.blocked) {
        html += '<div class="atk-result blocked">&#10003; BLOCKED &mdash; ' + escapeHtml(data.summary) + '</div>';
    } else {
        html += '<div class="atk-result failed">&#10007; NOT BLOCKED &mdash; ' + escapeHtml(data.summary) + '</div>';
    }
    container.html(html);
}


// =========================================================
//  RESTORE STATE ON PAGE LOAD (fixes refresh problem)
// =========================================================

$(function() {
    var page = state.page || 'landing';

    // some pages need extra setup before they can be shown
    if (page === 'section-register') {
        showSection('section-register');
        // re-populate QR if we had one
        if (state.totpSecret) {
            $('#reg-user').val(state.username);
            // dont re-show QR since we dont store the image, but show the secret
            // user can just proceed to login
        }
    } else if (page === 'section-step1') {
        showSection('section-step1');
        setStep('s1');
        if (state.username) $('#login-user').val(state.username);
        if (state.password) $('#login-pass').val(state.password);
    } else if (page === 'section-step2') {
        // cant resume mid-step2 since the flask session is gone
        // drop back to step1 with a note
        showSection('section-step1');
        setStep('s1');
        if (state.username) $('#login-user').val(state.username);
        if (state.password) $('#login-pass').val(state.password);
        showToast('Session expired after refresh. Start login from step 1.', 'info');
    } else if (page === 'section-step3') {
        showSection('section-step1');
        setStep('s1');
        if (state.username) $('#login-user').val(state.username);
        if (state.password) $('#login-pass').val(state.password);
        showToast('Session expired after refresh. Start login from step 1.', 'info');
    } else if (page === 'section-success') {
        // show landing since the session is gone anyway
        showSection('section-landing');
    } else {
        showSection('section-landing');
    }
});
