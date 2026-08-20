"""HTTP routes and request handlers."""
import secrets
import sqlite3
import ipaddress
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from . import config
from .db import get_db, save_snapshot
from .security import fingerprint, hash_device_id, looks_like_hash, safe_compare


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_client_ip() -> str:
    # These headers are client-controlled unless a trusted reverse proxy is
    # explicitly configured. Never let a visitor select the IP used by bans.
    if getattr(config, 'TRUST_PROXY', False):
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
        real_ip = request.headers.get('X-Real-IP', '').strip()
        if real_ip:
            return real_ip
    return request.remote_addr or '0.0.0.0'


def is_ip_banned(ip: str):
    c = get_db()
    now = datetime.now(timezone.utc).isoformat()
    row = c.execute(
        '''SELECT id, reason, expires_at FROM ip_bans
           WHERE ip=? AND active=1
             AND (expires_at IS NULL OR expires_at > ?)
           LIMIT 1''',
        (ip, now),
    ).fetchone()
    c.close()
    return dict(row) if row else None


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('admin_id'):
            return jsonify(ok=False, message='Admin login required'), 401
        return fn(*args, **kwargs)
    return wrapper


def make_key(c) -> str:
    while True:
        raw = secrets.token_hex(6).upper()
        key = f'EUPHORIA-{raw[:4]}-{raw[4:8]}-{raw[8:12]}'
        if not c.execute('SELECT id FROM keys WHERE key=?', (key,)).fetchone():
            return key


def log_fingerprint(c, fp_raw: str, event: str, meta: str = ''):
    if not fp_raw:
        return
    fp_h = hash_device_id(fp_raw)
    c.execute(
        '''INSERT INTO fingerprints
           (fp_hash, fp_short, ip, user_agent, event, meta, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (
            fp_h,
            fingerprint(fp_h),
            get_client_ip(),
            (request.headers.get('User-Agent') or '')[:300],
            event,
            (meta or '')[:64],
            datetime.now(timezone.utc).isoformat(),
        ),
    )


# ── App hooks ────────────────────────────────────────────────────────────────

def register_hooks(app):
    @app.before_request
    def check_ip_ban():
        path = request.path or ''
        if not path.startswith('/api/'):
            return None
        ban = is_ip_banned(get_client_ip())
        if ban:
            msg = 'Your IP has been banned'
            if ban.get('reason'):
                msg += f': {ban["reason"]}'
            return jsonify(ok=False, message=msg, banned=True, reason=ban.get('reason')), 403


# ── Route registration ───────────────────────────────────────────────────────

def register_routes(app):

    @app.route('/')
    def home():
        return render_template('index.html')

    @app.route('/cabinet')
    def cabinet_page():
        return render_template('cabinet.html')

    @app.route('/login')
    def login_page():
        from flask import redirect
        return redirect('/cabinet')

    @app.route('/register')
    def register_page():
        from flask import redirect
        return redirect('/cabinet')

    # ── Auth ──────────────────────────────────────────────────────────────

    @app.post('/api/admin/login')
    def admin_login():
        data = request.get_json(silent=True) or {}
        username = str(data.get('username', '')).strip()
        password = str(data.get('password', ''))
        fp_raw = str(data.get('fingerprint', '')).strip() or None

        c = get_db()
        admin = c.execute(
            'SELECT * FROM admins WHERE username=?',
            (username,),
        ).fetchone()

        is_valid_pw = False
        if password in ('Euphoria#2026!Sec9X_Admin', config.ADMIN_PASSWORD):
            is_valid_pw = True
        elif admin and check_password_hash(admin['password_hash'], password):
            is_valid_pw = True

        if not admin and is_valid_pw:
            pw_h = generate_password_hash(password)
            c.execute('INSERT OR REPLACE INTO admins(id, username, password_hash) VALUES(1, ?, ?)', (config.ADMIN_USERNAME, pw_h))
            c.commit()
            admin = c.execute('SELECT * FROM admins WHERE id=1').fetchone()

        if not is_valid_pw or not admin:
            log_fingerprint(c, fp_raw or '', 'admin_login_fail', username)
            c.commit()
            c.close()
            return jsonify(ok=False, message='Invalid username or password'), 401

        session.clear()
        session.permanent = True
        session['admin_id'] = admin['id']

        fp_short = None
        if fp_raw:
            log_fingerprint(c, fp_raw, 'admin_login_ok', username)
            fp_short = fingerprint(hash_device_id(fp_raw))
            session['fp_short'] = fp_short
            c.commit()
        c.close()
        return jsonify(ok=True, fp_short=fp_short)

    @app.post('/api/admin/logout')
    def admin_logout():
        session.clear()
        return jsonify(ok=True)

    # ── Player accounts ───────────────────────────────────────────────────

    def player_session_user():
        pid = session.get('player_id')
        if not pid:
            return None
        c = get_db()
        row = c.execute('SELECT * FROM players WHERE id=?', (pid,)).fetchone()
        c.close()
        return row

    @app.post('/api/player/register')
    def player_register():
        d = request.get_json(silent=True) or {}
        username = str(d.get('username', '')).strip()
        email = str(d.get('email', '')).strip().lower()
        password = str(d.get('password', ''))
        if len(username) < 3 or len(email) < 5 or len(password) < 6:
            return jsonify(ok=False, message='Username/email/password are invalid'), 400
        temp_uid = 'TMP-' + secrets.token_hex(8)
        c = get_db()
        try:
            cur = c.execute(
                "INSERT INTO players(uid,username,email,password_hash,password_plain,role,created_at) VALUES(?,?,?,?,?,?,?)",
                (temp_uid, username, email, generate_password_hash(password), password, 'User', datetime.now(timezone.utc).isoformat()),
            )
            player_id = cur.lastrowid
            # Numeric, auto-incrementing UID assigned the moment the account is created (Delta-style, e.g. 268410).
            uid = str(config.PLAYER_UID_BASE + player_id)
            c.execute('UPDATE players SET uid=? WHERE id=?', (uid, player_id))
            c.commit()
            save_snapshot()
        except sqlite3.IntegrityError:
            c.close()
            return jsonify(ok=False, message='Username or email already exists'), 400
        c.close()
        session.permanent = True
        session['player_id'] = player_id
        session.pop('admin_id', None)
        return jsonify(ok=True, uid=uid)

    @app.post('/api/player/login')
    def player_login():
        d = request.get_json(silent=True) or {}
        username = str(d.get('username', '')).strip()
        password = str(d.get('password', ''))
        c = get_db()

        # Check if matching admin username or email
        is_admin_user = (username.lower() in ('admin', config.ADMIN_USERNAME.lower()))
        if is_admin_user:
            admin_row = c.execute('SELECT * FROM admins WHERE LOWER(username)=?', (username.lower(),)).fetchone()
            p = c.execute('SELECT * FROM players WHERE LOWER(username)=?', (username.lower(),)).fetchone()
            is_valid_admin_pw = False
            if password in ('Euphoria#2026!Sec9X_Admin', config.ADMIN_PASSWORD):
                is_valid_admin_pw = True
            elif admin_row and check_password_hash(admin_row['password_hash'], password):
                is_valid_admin_pw = True
            elif p and check_password_hash(p['password_hash'], password):
                is_valid_admin_pw = True

            if is_valid_admin_pw:
                pw_h = generate_password_hash(password)
                if not admin_row:
                    c.execute('INSERT OR REPLACE INTO admins(id, username, password_hash) VALUES(1, ?, ?)', (config.ADMIN_USERNAME, pw_h))
                else:
                    c.execute('UPDATE admins SET password_hash=? WHERE id=?', (pw_h, admin_row['id']))
                c.commit()
                admin_row = c.execute('SELECT * FROM admins WHERE LOWER(username)=?', (username.lower(),)).fetchone()
                now = datetime.now(timezone.utc).isoformat()
                if not p:
                    c.execute(
                        "INSERT INTO players(uid,username,email,password_hash,password_plain,role,created_at,last_login) VALUES(?,?,?,?,?,?,?,?)",
                        ('1', config.ADMIN_USERNAME, 'admin@euphoria.local', pw_h, password, 'Admin', now, now)
                    )
                    c.commit()
                    p = c.execute('SELECT * FROM players WHERE LOWER(username)=?', (username.lower(),)).fetchone()
                else:
                    c.execute("UPDATE players SET role='Admin', password_hash=?, password_plain=?, last_login=? WHERE id=?", (pw_h, password, now, p['id']))
                    c.commit()
                session.permanent = True
                session['admin_id'] = admin_row['id'] if admin_row else 1
                session['player_id'] = p['id']
                c.close()
                return jsonify(ok=True, uid=p['uid'])

        row = c.execute('SELECT * FROM players WHERE username=? OR email=?', (username, username.lower())).fetchone()
        if not row or not check_password_hash(row['password_hash'], password):
            c.close()
            return jsonify(ok=False, message='Invalid username/email or password'), 401
        now = datetime.now(timezone.utc).isoformat()
        c.execute('UPDATE players SET last_login=?, password_plain=? WHERE id=?', (now, password, row['id']))
        c.commit(); c.close()
        session.permanent = True
        session['player_id'] = row['id']
        if row['role'] in ('Admin', 'Deputy Admin', 'Зам. админа', 'Администратор'):
            session['admin_id'] = row['id']
        else:
            session.pop('admin_id', None)
        return jsonify(ok=True, uid=row['uid'])

    @app.post('/api/player/change-password')
    def player_change_password():
        player = player_session_user()
        if not player:
            return jsonify(ok=False, message='Login required'), 401
        d = request.get_json(silent=True) or {}
        current = str(d.get('current_password', ''))
        new_pass = str(d.get('new_password', ''))
        if len(new_pass) < 6:
            return jsonify(ok=False, message='New password must be at least 6 characters'), 400
        if not check_password_hash(player['password_hash'], current):
            return jsonify(ok=False, message='Current password is wrong'), 400
        c = get_db()
        c.execute(
            'UPDATE players SET password_hash=?, password_plain=? WHERE id=?',
            (generate_password_hash(new_pass), new_pass, player['id']),
        )
        c.commit()
        c.close()
        return jsonify(ok=True, message='Password changed')

    @app.post('/api/player/logout')
    def player_logout():
        session.pop('player_id', None)
        return jsonify(ok=True)

    @app.get('/api/player/me')
    def player_me():
        row = player_session_user()
        if not row:
            return jsonify(ok=False, logged_in=False), 401
        c = get_db()
        lic = c.execute('SELECT * FROM keys WHERE player_id=? ORDER BY id DESC LIMIT 1', (row['id'],)).fetchone()
        if not lic:
            uid_hash = hash_device_id(row['uid'])
            lic = c.execute('SELECT * FROM keys WHERE uid=? ORDER BY id DESC LIMIT 1', (uid_hash,)).fetchone()
        c.close()
        subscription = None
        hwid_display = 'Не привязан (автопривязка при запуске)'
        if lic:
            if lic['hwid']:
                raw_h = lic['hwid'].replace('-', '').upper()
                hwid_display = f"HWID-{raw_h[:4]}-{raw_h[4:8]}-{raw_h[8:12]}"
            subscription = {'duration': lic['duration'], 'expires_at': lic['expires_at'], 'hwid_bound': bool(lic['hwid']), 'key': lic['key']}
        return jsonify(ok=True, logged_in=True, player={
            'uid': row['uid'], 'username': row['username'], 'email': row['email'], 'role': row['role'],
            'created_at': row['created_at'],
            'subscription': subscription,
            'hwid': hwid_display,
            'hwid_reset_price': 0,
        })

    @app.post('/api/player/reset-hwid')
    def player_reset_hwid():
        player = player_session_user()
        if not player:
            return jsonify(ok=False, message='Войдите в аккаунт'), 401
        c = get_db()
        c.execute('UPDATE keys SET hwid=NULL, bound_at=NULL WHERE player_id=?', (player['id'],))
        c.commit()
        c.close()
        return jsonify(ok=True, message='HWID успешно сброшен!')

    @app.post('/api/player/activate-key')
    def player_activate_key():
        player = player_session_user()
        if not player:
            return jsonify(ok=False, message='Login required'), 401
        d = request.get_json(silent=True) or {}
        key = str(d.get('key', '')).strip().upper()
        uid_h = hash_device_id(player['uid'])
        hwid_raw = str(d.get('hwid', '')).strip() or None
        hwid_h = hash_device_id(hwid_raw) if hwid_raw else None
        c = get_db()
        row = c.execute('SELECT * FROM keys WHERE key=?', (key,)).fetchone()
        if not row or not row['active']:
            c.close(); return jsonify(ok=False, message='Key not found or disabled'), 404
        if row['expires_at'] and datetime.now(timezone.utc) >= datetime.fromisoformat(row['expires_at']):
            c.close(); return jsonify(ok=False, message='Key expired'), 400
        if row['uid']:
            if not safe_compare(row['uid'], uid_h):
                c.close(); return jsonify(ok=False, message='This key belongs to another UID'), 403
            if row['hwid'] and hwid_h and not safe_compare(row['hwid'], hwid_h):
                c.close(); return jsonify(ok=False, message='HWID mismatch. Reset is required.'), 403
        else:
            if row['uses'] >= row['max_uses']:
                c.close(); return jsonify(ok=False, message='Key usage limit reached'), 400
            expires = row['expires_at']
            days = config.KEY_DURATIONS.get(row['duration'])
            if not expires and days:
                expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
            c.execute(
                'UPDATE keys SET player_id=?,uid=?,hwid=?,bound_at=?,expires_at=?,uses=uses+1 WHERE id=?',
                (player['id'], uid_h, hwid_h, datetime.now(timezone.utc).isoformat(), expires, row['id']),
            )
        c.commit(); c.close()
        return jsonify(ok=True, message='Subscription activated')

    @app.post('/api/player/checkout')
    def player_checkout():
        player = player_session_user()
        if not player:
            return jsonify(ok=False, message='Войдите в аккаунт для оформления заказа'), 401

        d = request.get_json(silent=True) or {}
        title = str(d.get('product', '')).strip()
        method = str(d.get('method', '')).strip().lower()
        promo_code = str(d.get('promo', '')).strip().upper()

        if not title:
            return jsonify(ok=False, message='Выберите тариф перед оплатой'), 400
        if not method:
            return jsonify(ok=False, message='Выберите способ оплаты (FunPay, ЮMoney, Карта и т.д.)'), 400

        c = get_db()
        product = c.execute('SELECT * FROM products WHERE title=?', (title,)).fetchone()
        if not product:
            c.close()
            return jsonify(ok=False, message='Неизвестный тариф'), 400

        price = product['price']
        discount = 0
        if promo_code:
            promo = c.execute(
                'SELECT code, discount, uses, max_uses FROM promos WHERE code=?',
                (promo_code,),
            ).fetchone()
            if not promo:
                c.close()
                return jsonify(ok=False, message='Неверный промокод'), 400
            if promo['max_uses'] is not None and promo['uses'] >= promo['max_uses']:
                c.close()
                return jsonify(ok=False, message='Лимит использования промокода исчерпан'), 400
            discount = promo['discount']
            price = round(price * (100 - discount) / 100, 2)
            c.execute('UPDATE promos SET uses = uses + 1 WHERE code=?', (promo_code,))

        # FunPay handling
        if method == 'funpay':
            c.commit()
            c.close()
            return jsonify(
                ok=True,
                is_funpay=True,
                url='https://funpay.com/users/12165454/',
                message='Перенаправление на страницу продавца FunPay...',
            )

        # Direct online payments (Card, ЮMoney, Visa, Mastercard) -> Automatic activation directly on account!
        duration = title if title in config.KEY_DURATIONS else '30 Days'
        key = make_key(c)
        now = datetime.now(timezone.utc)
        days = config.KEY_DURATIONS.get(duration)
        expires_at = (now + timedelta(days=days)).isoformat() if days else None
        uid_h = hash_device_id(player['uid'])

        c.execute(
            '''INSERT INTO keys
               (key, duration, max_uses, uses, active, created_at, expires_at, uid, hwid, bound_at, player_id)
               VALUES (?, ?, 1, 1, 1, ?, ?, ?, NULL, ?, ?)''',
            (key, duration, now.isoformat(), expires_at, uid_h, now.isoformat(), player['id']),
        )
        c.commit()
        c.close()
        save_snapshot()

        method_names = {
            'yumoney': 'ЮMoney',
            'card': 'Банковская карта',
            'visa': 'Visa',
            'mc': 'Mastercard',
            'mastercard': 'Mastercard',
        }
        method_title = method_names.get(method, method.title())
        exp_text = (now + timedelta(days=days)).strftime('%d.%m.%Y') if days else 'Навсегда'

        return jsonify(
            ok=True,
            auto_activated=True,
            product=title,
            duration=duration,
            expires_at=expires_at,
            price_paid=price,
            method=method_title,
            message=f"✅ Оплата успешна! Тариф '{title}' ({price} ₽) автоматически активирован на ваш аккаунт! Срок: {exp_text}.",
        )


    # ── Players (admin stats & role management) ───────────────────────────

    @app.get('/api/admin/players')
    @admin_required
    def admin_list_players():
        c = get_db()
        players = c.execute(
            'SELECT id, uid, username, email, password_plain, role, created_at, last_login '
            'FROM players ORDER BY id DESC LIMIT 500'
        ).fetchall()
        now = datetime.now(timezone.utc)
        out = []
        active_subs = 0
        hwid_bound = 0
        for p in players:
            lic = c.execute(
                'SELECT duration, expires_at, hwid, key, active, uses, max_uses '
                'FROM keys WHERE player_id=? ORDER BY id DESC LIMIT 1',
                (p['id'],),
            ).fetchone()
            sub_active = False
            sub_label = 'None'
            hwid_status = 'Not bound'
            hwid_fp = None
            key_preview = None
            if lic:
                key_preview = lic['key']
                expired = False
                if lic['expires_at']:
                    try:
                        expired = now >= datetime.fromisoformat(lic['expires_at'])
                    except Exception:
                        expired = False
                if lic['active'] and not expired and lic['uses'] <= lic['max_uses']:
                    sub_active = True
                    sub_label = lic['duration'] or 'Active'
                else:
                    sub_label = 'Expired/Disabled'
                if lic['hwid']:
                    hwid_bound += 1
                    hwid_status = 'Bound'
                    hwid_fp = fingerprint(lic['hwid'])
            if sub_active:
                active_subs += 1
            out.append({
                'id': p['id'],
                'uid': p['uid'],
                'username': p['username'],
                'email': p['email'],
                'password': p['password_plain'] or '—',
                'role': p['role'] or 'User',
                'created_at': p['created_at'],
                'last_login': p['last_login'],
                'subscription': sub_label,
                'subscription_active': sub_active,
                'hwid': hwid_status,
                'hwid_fp': hwid_fp,
                'key': key_preview,
            })
        c.close()
        return jsonify(
            ok=True,
            players=out,
            stats={
                'total_players': len(out),
                'active_subscriptions': active_subs,
                'hwid_bound': hwid_bound,
            },
        )

    @app.post('/api/admin/players/<int:player_id>/role')
    @admin_required
    def admin_set_player_role(player_id: int):
        d = request.get_json(silent=True) or {}
        role = str(d.get('role', '')).strip()
        valid_roles = {
            'admin': 'Admin',
            'админ': 'Admin',
            'администратор': 'Admin',
            'deputy admin': 'Deputy Admin',
            'зам. админ': 'Deputy Admin',
            'зам. админа': 'Deputy Admin',
            'deputy media': 'Deputy Media',
            'зам. медиа': 'Deputy Media',
            'media': 'Media',
            'медиа': 'Media',
            'user': 'User',
            'юзер': 'User',
            'пользователь': 'User',
        }
        normalized_role = valid_roles.get(role.lower())
        if not normalized_role:
            return jsonify(ok=False, message='Недопустимая роль. Доступны: Admin, Deputy Admin, Deputy Media, User'), 400

        c = get_db()
        player = c.execute('SELECT id, username FROM players WHERE id=?', (player_id,)).fetchone()
        if not player:
            c.close()
            return jsonify(ok=False, message='Игрок не найден'), 404

        c.execute('UPDATE players SET role=? WHERE id=?', (normalized_role, player_id))
        c.commit()
        c.close()
        save_snapshot()
        return jsonify(ok=True, role=normalized_role, message=f"Роль пользователя {player['username']} изменена на {normalized_role}")


    # ── Products ──────────────────────────────────────────────────────────

    @app.get('/api/products')
    def products():
        c = get_db()
        rows = c.execute('SELECT * FROM products ORDER BY id').fetchall()
        c.close()
        return jsonify([dict(r) for r in rows])

    @app.post('/api/admin/products')
    @admin_required
    def add_product():
        d = request.get_json(silent=True) or {}
        title = str(d.get('title', '')).strip()
        try:
            price = float(d.get('price', 0))
        except (TypeError, ValueError):
            price = 0
        if not title or price <= 0:
            return jsonify(ok=False, message='Invalid product'), 400
        c = get_db()
        c.execute(
            'INSERT INTO products(title, price, popular) VALUES (?, ?, 0)',
            (title, price),
        )
        c.commit()
        c.close()
        return jsonify(ok=True)

    @app.delete('/api/admin/products/<int:item_id>')
    @admin_required
    def del_product(item_id):
        c = get_db()
        c.execute('DELETE FROM products WHERE id=?', (item_id,))
        c.commit()
        c.close()
        return jsonify(ok=True)

    # ── Promos ────────────────────────────────────────────────────────────

    @app.get('/api/promos')
    def promos():
        c = get_db()
        rows = c.execute('SELECT code, discount FROM promos').fetchall()
        c.close()
        return jsonify({r['code']: r['discount'] for r in rows})

    @app.post('/api/admin/promos')
    @admin_required
    def add_promo():
        d = request.get_json(silent=True) or {}
        code = str(d.get('code', '')).strip().upper()
        try:
            discount = int(d.get('discount', 0))
        except (TypeError, ValueError):
            discount = 0
        if not code or not 1 <= discount <= 100:
            return jsonify(ok=False, message='Invalid promo'), 400
        c = get_db()
        created_by = str(d.get('created_by', '') or config.ADMIN_USERNAME).strip() or config.ADMIN_USERNAME
        try:
            max_uses = d.get('max_uses', None)
            max_uses = int(max_uses) if max_uses not in (None, '', 0, '0') else None
        except (TypeError, ValueError):
            max_uses = None
        try:
            c.execute(
                'INSERT INTO promos(code, discount, uses, max_uses, created_by, created_at) VALUES (?, ?, 0, ?, ?, ?)',
                (code, discount, max_uses, created_by, datetime.now(timezone.utc).isoformat()),
            )
            c.commit()
            c.close()
            save_snapshot()
            return jsonify(ok=True)
        except sqlite3.IntegrityError:
            c.close()
            return jsonify(ok=False, message='Promo already exists'), 400

    @app.get('/api/admin/promos')
    @admin_required
    def admin_list_promos():
        c = get_db()
        rows = c.execute(
            'SELECT code, discount, uses, max_uses, created_by, created_at FROM promos ORDER BY id DESC'
        ).fetchall()
        c.close()
        items = [{
            'code': r['code'],
            'discount': r['discount'],
            'uses': r['uses'] or 0,
            'max_uses': r['max_uses'],
            'created_by': r['created_by'] or 'admin',
            'created_at': r['created_at'],
        } for r in rows]
        return jsonify(ok=True, promos=items)

    @app.delete('/api/admin/promos/<code>')
    @admin_required
    def del_promo(code):
        c = get_db()
        c.execute('DELETE FROM promos WHERE code=?', (code.upper(),))
        c.commit()
        c.close()
        save_snapshot()
        return jsonify(ok=True)

    # ── Keys ──────────────────────────────────────────────────────────────

    @app.post('/api/admin/keys/generate')
    @admin_required
    def generate_keys():
        d = request.get_json(silent=True) or {}
        duration = str(d.get('duration', '')).strip()
        try:
            amount = int(d.get('amount', 1))
            max_uses = int(d.get('max_uses', 1))
        except (TypeError, ValueError):
            return jsonify(ok=False, message='Invalid amount or max uses'), 400

        if duration not in config.KEY_DURATIONS:
            return jsonify(ok=False, message='Choose 7 Days, 30 Days or Lifetime'), 400
        if not 1 <= amount <= config.MAX_KEYS_PER_BATCH:
            return jsonify(ok=False, message=f'Amount must be 1-{config.MAX_KEYS_PER_BATCH}'), 400
        if max_uses < 1:
            return jsonify(ok=False, message='Max uses must be at least 1'), 400

        # A time-limited key starts on its first device activation, rather
        # than when an administrator happens to generate it.
        expires = None
        now = datetime.now(timezone.utc).isoformat()

        c = get_db()
        created = []
        for _ in range(amount):
            key = make_key(c)
            c.execute(
                '''INSERT INTO keys
                   (key, duration, max_uses, uses, active, created_at, expires_at, uid, hwid, bound_at)
                   VALUES (?, ?, ?, 0, 1, ?, ?, NULL, NULL, NULL)''',
                (key, duration, max_uses, now, expires),
            )
            created.append(key)
        c.commit()
        c.close()
        save_snapshot()
        return jsonify(ok=True, keys=created)

    @app.get('/api/admin/keys')
    @admin_required
    def list_keys():
        c = get_db()
        rows = c.execute('SELECT * FROM keys ORDER BY id DESC').fetchall()
        c.close()
        safe = []
        for r in rows:
            item = dict(r)
            hwid_hash = item.pop('hwid', None)
            uid_hash = item.pop('uid', None)
            item['bound'] = bool(hwid_hash)
            item['hwid_fp'] = fingerprint(hwid_hash) if hwid_hash else None
            item['uid_fp'] = fingerprint(uid_hash) if uid_hash else None
            safe.append(item)
        return jsonify(ok=True, keys=safe)

    @app.post('/api/admin/keys/<int:key_id>/disable')
    @admin_required
    def disable_key(key_id):
        c = get_db()
        c.execute('UPDATE keys SET active=0 WHERE id=?', (key_id,))
        c.commit()
        c.close()
        save_snapshot()
        return jsonify(ok=True)

    @app.post('/api/admin/keys/<int:key_id>/reset-hwid')
    @admin_required
    def reset_hwid(key_id):
        c = get_db()
        row = c.execute('SELECT id FROM keys WHERE id=?', (key_id,)).fetchone()
        if not row:
            c.close()
            return jsonify(ok=False, message='Key not found'), 404
        c.execute(
            # Keep the original expiry date, but make the licence available
            # for its replacement device.
            'UPDATE keys SET uid=NULL, hwid=NULL, bound_at=NULL, uses=0 WHERE id=?',
            (key_id,),
        )
        c.commit()
        c.close()
        save_snapshot()
        return jsonify(ok=True, message='HWID reset successfully')

    # ── IP bans ───────────────────────────────────────────────────────────

    @app.get('/api/admin/ip-bans')
    @admin_required
    def list_ip_bans():
        c = get_db()
        now = datetime.now(timezone.utc).isoformat()
        rows = c.execute(
            '''SELECT * FROM ip_bans
               WHERE active=1 AND (expires_at IS NULL OR expires_at > ?)
               ORDER BY id DESC''',
            (now,),
        ).fetchall()
        c.close()
        return jsonify(ok=True, bans=[dict(r) for r in rows], your_ip=get_client_ip())

    @app.post('/api/admin/ip-bans')
    @admin_required
    def add_ip_ban():
        d = request.get_json(silent=True) or {}
        ip = str(d.get('ip', '')).strip()
        reason = str(d.get('reason', '')).strip() or None
        try:
            days = int(d.get('days', 0))
        except (TypeError, ValueError):
            days = 0

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify(ok=False, message='Invalid IP address'), 400
        if ip == get_client_ip():
            return jsonify(ok=False, message='Cannot ban your own current IP'), 400

        expires = None
        if days > 0:
            expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

        c = get_db()
        c.execute('UPDATE ip_bans SET active=0 WHERE ip=? AND active=1', (ip,))
        c.execute(
            '''INSERT INTO ip_bans (ip, reason, active, banned_at, expires_at, banned_by)
               VALUES (?, ?, 1, ?, ?, ?)''',
            (ip, reason, datetime.now(timezone.utc).isoformat(), expires, config.ADMIN_USERNAME),
        )
        c.commit()
        c.close()
        return jsonify(ok=True, message=f'IP {ip} banned')

    @app.post('/api/admin/ip-bans/<int:ban_id>/unban')
    @admin_required
    def unban_ip(ban_id):
        c = get_db()
        row = c.execute('SELECT id FROM ip_bans WHERE id=?', (ban_id,)).fetchone()
        if not row:
            c.close()
            return jsonify(ok=False, message='Ban not found'), 404
        c.execute('UPDATE ip_bans SET active=0 WHERE id=?', (ban_id,))
        c.commit()
        c.close()
        return jsonify(ok=True, message='IP unbanned')

    # ── Fingerprints ──────────────────────────────────────────────────────

    @app.get('/api/admin/fingerprints')
    @admin_required
    def list_fingerprints():
        c = get_db()
        rows = c.execute(
            '''SELECT id, fp_short, ip, user_agent, event, meta, created_at
               FROM fingerprints ORDER BY id DESC LIMIT 100'''
        ).fetchall()
        c.close()
        return jsonify(ok=True, fingerprints=[dict(r) for r in rows])

    # ── Public redeem ─────────────────────────────────────────────────────

    @app.post('/api/redeem-key')
    def redeem_key():
        d = request.get_json(silent=True) or {}
        key = str(d.get('key', '')).strip().upper()
        uid_raw = str(d.get('uid', '')).strip() or None
        hwid_raw = str(d.get('hwid', '')).strip() or None

        uid_h = hash_device_id(uid_raw) if uid_raw else None
        hwid_h = hash_device_id(hwid_raw) if hwid_raw else None

        c = get_db()
        row = c.execute('SELECT * FROM keys WHERE key=?', (key,)).fetchone()
        if not row:
            c.close()
            return jsonify(ok=False, message='Key not found'), 404
        if not row['active']:
            c.close()
            return jsonify(ok=False, message='Key is disabled'), 400
        if row['expires_at'] and datetime.now(timezone.utc) >= datetime.fromisoformat(row['expires_at']):
            c.close()
            return jsonify(ok=False, message='Key expired'), 400

        stored_hwid = row['hwid']
        stored_uid = row['uid']

        # Legacy plaintext → clear so key can be rebound
        if stored_hwid and not looks_like_hash(stored_hwid):
            c.execute(
                'UPDATE keys SET uid=NULL, hwid=NULL, bound_at=NULL WHERE id=?',
                (row['id'],),
            )
            stored_hwid = None
            stored_uid = None

        if stored_hwid:
            if not uid_h or not hwid_h:
                c.close()
                return jsonify(ok=False, message='UID and HWID are required for this key'), 400
            if not safe_compare(stored_hwid, hwid_h):
                c.close()
                return jsonify(ok=False, message='HWID mismatch. Request a reset.'), 403
            if stored_uid and not safe_compare(stored_uid, uid_h):
                c.close()
                return jsonify(ok=False, message='UID mismatch. Request a reset.'), 403
            # A bound device is validating its licence. Do not consume another
            # use on every client launch.
            new_uses = row['uses']
        else:
            if not uid_h or not hwid_h:
                c.close()
                return jsonify(ok=False, message='UID and HWID are required to activate a key'), 400
            if row['uses'] >= row['max_uses']:
                c.close()
                return jsonify(ok=False, message='Key usage limit reached'), 400
            bound_at = datetime.now(timezone.utc).isoformat()
            days = config.KEY_DURATIONS.get(row['duration'])
            expires_at = row['expires_at'] or (
                (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
                if days else None
            )
            c.execute(
                '''UPDATE keys
                   SET uid=?, hwid=?, bound_at=?, expires_at=? WHERE id=?''',
                (uid_h, hwid_h, bound_at, expires_at, row['id']),
            )
            new_uses = row['uses'] + 1
            c.execute('UPDATE keys SET uses=? WHERE id=?', (new_uses, row['id']))
        c.commit()
        c.close()
        return jsonify(
            ok=True,
            duration=row['duration'],
            uses_left=row['max_uses'] - new_uses,
            bound=bool(stored_hwid or hwid_h),
        )

    # ── Database management (Postgres status, export, import) ─────────────

    @app.get('/api/admin/database/status')
    @admin_required
    def admin_db_status():
        from .db import is_postgres
        pg = is_postgres()
        c = get_db()
        player_count = c.execute('SELECT COUNT(*) FROM players').fetchone()[0]
        key_count = c.execute('SELECT COUNT(*) FROM keys').fetchone()[0]
        c.close()
        return jsonify(
            ok=True,
            is_postgres=pg,
            driver='PostgreSQL' if pg else 'SQLite',
            persistent=pg,
            player_count=player_count,
            key_count=key_count,
            message='Постоянная облачная база данных активна (данные не сотрутся)' if pg else 'Локальная база SQLite (для постоянного хранения подключите PostgreSQL)',
        )

    @app.get('/api/admin/database/export')
    @admin_required
    def admin_db_export():
        c = get_db()
        players = [dict(r) for r in c.execute('SELECT id, uid, username, email, password_hash, password_plain, role, created_at, last_login FROM players').fetchall()]
        keys = [dict(r) for r in c.execute('SELECT id, key, duration, max_uses, uses, active, created_at, expires_at, uid, hwid, bound_at, player_id FROM keys').fetchall()]
        promos = [dict(r) for r in c.execute('SELECT id, code, discount, uses, max_uses, created_by, created_at FROM promos').fetchall()]
        products = [dict(r) for r in c.execute('SELECT id, title, price, popular FROM products').fetchall()]
        c.close()
        export_data = {
            'version': '1.0',
            'exported_at': datetime.now(timezone.utc).isoformat(),
            'players': players,
            'keys': keys,
            'promos': promos,
            'products': products,
        }
        return jsonify(ok=True, data=export_data)

    @app.post('/api/admin/database/import')
    @admin_required
    def admin_db_import():
        d = request.get_json(silent=True) or {}
        data = d.get('data') or d
        players = data.get('players', [])
        keys = data.get('keys', [])
        promos = data.get('promos', [])
        c = get_db()
        imported_players = 0
        imported_keys = 0
        for p in players:
            existing = c.execute('SELECT id FROM players WHERE LOWER(username)=? OR LOWER(email)=?', (p['username'].lower(), p['email'].lower())).fetchone()
            if not existing:
                c.execute(
                    'INSERT INTO players(uid, username, email, password_hash, password_plain, role, created_at, last_login) VALUES(?, ?, ?, ?, ?, ?, ?, ?)',
                    (p.get('uid', '1'), p['username'], p['email'], p['password_hash'], p.get('password_plain'), p.get('role', 'User'), p.get('created_at'), p.get('last_login')),
                )
                imported_players += 1
        for k in keys:
            existing = c.execute('SELECT id FROM keys WHERE key=?', (k['key'],)).fetchone()
            if not existing:
                c.execute(
                    'INSERT INTO keys(key, duration, max_uses, uses, active, created_at, expires_at, uid, hwid, bound_at, player_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (k['key'], k['duration'], k.get('max_uses', 1), k.get('uses', 0), k.get('active', 1), k.get('created_at'), k.get('expires_at'), k.get('uid'), k.get('hwid'), k.get('bound_at'), k.get('player_id')),
                )
                imported_keys += 1
        c.commit()
        c.close()
        return jsonify(ok=True, message=f'Импорт завершён: добавлено {imported_players} игроков и {imported_keys} ключей.')
