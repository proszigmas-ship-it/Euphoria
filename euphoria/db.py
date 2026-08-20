"""Database connection and schema initialization."""
import sqlite3
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash

from . import config
from .security import looks_like_hash


def get_db():
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=30000')
    return conn


def init_db():
    c = get_db()

    c.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            duration TEXT NOT NULL,
            max_uses INTEGER NOT NULL DEFAULT 1,
            uses INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            uid TEXT,
            hwid TEXT,
            bound_at TEXT
        )
    ''')

    # Migrations for older databases
    cols = {row[1] for row in c.execute('PRAGMA table_info(keys)').fetchall()}
    if 'uid' not in cols:
        c.execute('ALTER TABLE keys ADD COLUMN uid TEXT')
    if 'hwid' not in cols:
        c.execute('ALTER TABLE keys ADD COLUMN hwid TEXT')
    if 'bound_at' not in cols:
        c.execute('ALTER TABLE keys ADD COLUMN bound_at TEXT')

    # Clear legacy plaintext HWID/UID left from pre-hash versions
    try:
        for row in c.execute('SELECT id, hwid FROM keys WHERE hwid IS NOT NULL').fetchall():
            if not looks_like_hash(row['hwid']):
                c.execute(
                    'UPDATE keys SET uid=NULL, hwid=NULL, bound_at=NULL WHERE id=?',
                    (row['id'],),
                )
    except Exception:
        pass

    c.execute('''
        CREATE TABLE IF NOT EXISTS promos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            discount INTEGER NOT NULL,
            uses INTEGER NOT NULL DEFAULT 0,
            max_uses INTEGER,
            created_by TEXT,
            created_at TEXT
        )
    ''')
    promo_cols = {row[1] for row in c.execute('PRAGMA table_info(promos)').fetchall()}
    if 'uses' not in promo_cols:
        c.execute('ALTER TABLE promos ADD COLUMN uses INTEGER NOT NULL DEFAULT 0')
    if 'max_uses' not in promo_cols:
        c.execute('ALTER TABLE promos ADD COLUMN max_uses INTEGER')
    if 'created_by' not in promo_cols:
        c.execute('ALTER TABLE promos ADD COLUMN created_by TEXT')
    if 'created_at' not in promo_cols:
        c.execute('ALTER TABLE promos ADD COLUMN created_at TEXT')


    c.execute("""
        CREATE TABLE IF NOT EXISTS players(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'User',
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)

    key_cols = {row[1] for row in c.execute('PRAGMA table_info(keys)').fetchall()}
    if 'player_id' not in key_cols:
        c.execute('ALTER TABLE keys ADD COLUMN player_id INTEGER')

    c.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            price REAL NOT NULL,
            popular INTEGER NOT NULL DEFAULT 0
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS ip_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            reason TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            banned_at TEXT NOT NULL,
            expires_at TEXT,
            banned_by TEXT
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bans_ip ON ip_bans(ip)')

    c.execute('''
        CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fp_hash TEXT NOT NULL,
            fp_short TEXT,
            ip TEXT,
            user_agent TEXT,
            event TEXT,
            meta TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_fp_hash ON fingerprints(fp_hash)')

    # Admin account — always sync password from env/config
    admin = c.execute(
        'SELECT id FROM admins WHERE username=?',
        (config.ADMIN_USERNAME,),
    ).fetchone()
    pw_hash = generate_password_hash(config.ADMIN_PASSWORD)
    if not admin:
        c.execute(
            'INSERT INTO admins(username, password_hash) VALUES(?, ?)',
            (config.ADMIN_USERNAME, pw_hash),
        )
    else:
        c.execute(
            'UPDATE admins SET password_hash=? WHERE username=?',
            (pw_hash, config.ADMIN_USERNAME),
        )

    # Seed products
    if c.execute('SELECT COUNT(*) FROM products').fetchone()[0] == 0:
        c.executemany(
            'INSERT INTO products(title, price, popular) VALUES(?, ?, ?)',
            config.DEFAULT_PRODUCTS,
        )
    else:
        # Keep the built-in plans in sync after an upgrade, while leaving any
        # administrator-created products untouched.
        for title, price, popular in config.DEFAULT_PRODUCTS:
            c.execute(
                'UPDATE products SET price=?, popular=? WHERE title=?',
                (price, popular, title),
            )
            if c.execute('SELECT changes()').fetchone()[0] == 0:
                c.execute(
                    'INSERT INTO products(title, price, popular) VALUES(?, ?, ?)',
                    (title, price, popular),
                )
        exists = c.execute(
            "SELECT id FROM products WHERE title=?",
            ('HWID Reset',),
        ).fetchone()
        if not exists:
            c.execute(
                'INSERT INTO products(title, price, popular) VALUES(?, ?, ?)',
                ('HWID Reset', 250, 0),
            )

    # Seed promo
    if c.execute('SELECT COUNT(*) FROM promos').fetchone()[0] == 0:
        c.execute(
            'INSERT INTO promos(code, discount) VALUES(?, ?)',
            config.DEFAULT_PROMO,
        )

    c.commit()
    c.close()
