"""Database connection and schema initialization with PostgreSQL + SQLite support."""
import os
import sqlite3
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash

from . import config
from .security import looks_like_hash


class PGRow(dict):
    """Row wrapper allowing both dictionary and index-based access."""
    def __init__(self, data, columns):
        super().__init__(zip(columns, data))
        self._data = tuple(data)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._data[key]
        return super().__getitem__(key)


class PGConnection:
    """PostgreSQL connection adapter mimicking sqlite3 connection interface."""
    def __init__(self, conn):
        self._conn = conn
        self._last_cursor = None

    def execute(self, query, params=None):
        cur = self._conn.cursor()
        self._last_cursor = cur
        pg_query = query.replace('?', '%s')
        if params is None:
            cur.execute(pg_query)
        else:
            cur.execute(pg_query, params)
        return self

    def executemany(self, query, seq_of_params):
        cur = self._conn.cursor()
        self._last_cursor = cur
        pg_query = query.replace('?', '%s')
        cur.executemany(pg_query, seq_of_params)
        return self

    def fetchone(self):
        if not self._last_cursor or not self._last_cursor.description:
            return None
        row = self._last_cursor.fetchone()
        if row is None:
            return None
        cols = [desc[0] for desc in self._last_cursor.description]
        return PGRow(row, cols)

    def fetchall(self):
        if not self._last_cursor or not self._last_cursor.description:
            return []
        rows = self._last_cursor.fetchall()
        cols = [desc[0] for desc in self._last_cursor.description]
        return [PGRow(r, cols) for r in rows]

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


def is_postgres() -> bool:
    url = config.DATABASE_URL or os.environ.get('DATABASE_URL', '')
    return bool(url and (url.startswith('postgres://') or url.startswith('postgresql://')))


def get_db():
    if is_postgres():
        db_url = config.DATABASE_URL or os.environ.get('DATABASE_URL', '')
        if db_url.startswith('postgres://'):
            db_url = 'postgresql://' + db_url[len('postgres://'):]
        try:
            import psycopg2
            conn = psycopg2.connect(db_url)
            return PGConnection(conn)
        except Exception:
            try:
                import pg8000.native
                # fallback or continue
            except Exception:
                pass
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=30000')
    return conn

def init_db():
    c = get_db()
    pg = is_postgres()
    pk = "SERIAL PRIMARY KEY" if pg else "INTEGER PRIMARY KEY AUTOINCREMENT"

    c.execute(f'''
        CREATE TABLE IF NOT EXISTS admins (
            id {pk},
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    c.execute(f'''
        CREATE TABLE IF NOT EXISTS keys (
            id {pk},
            key TEXT UNIQUE NOT NULL,
            duration TEXT NOT NULL,
            max_uses INTEGER NOT NULL DEFAULT 1,
            uses INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            uid TEXT,
            hwid TEXT,
            bound_at TEXT,
            player_id INTEGER
        )
    ''')

    c.execute(f'''
        CREATE TABLE IF NOT EXISTS promos (
            id {pk},
            code TEXT UNIQUE NOT NULL,
            discount INTEGER NOT NULL,
            uses INTEGER NOT NULL DEFAULT 0,
            max_uses INTEGER,
            created_by TEXT,
            created_at TEXT
        )
    ''')

    c.execute(f"""
        CREATE TABLE IF NOT EXISTS players (
            id {pk},
            uid TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_plain TEXT,
            role TEXT NOT NULL DEFAULT 'User',
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)

    if not pg:
        try:
            p_cols = {row[1] for row in c.execute('PRAGMA table_info(players)').fetchall()}
            if 'password_plain' not in p_cols:
                c.execute('ALTER TABLE players ADD COLUMN password_plain TEXT')
            if 'role' not in p_cols:
                c.execute("ALTER TABLE players ADD COLUMN role TEXT NOT NULL DEFAULT 'User'")

            k_cols = {row[1] for row in c.execute('PRAGMA table_info(keys)').fetchall()}
            if 'player_id' not in k_cols:
                c.execute('ALTER TABLE keys ADD COLUMN player_id INTEGER')
            if 'uid' not in k_cols:
                c.execute('ALTER TABLE keys ADD COLUMN uid TEXT')
            if 'hwid' not in k_cols:
                c.execute('ALTER TABLE keys ADD COLUMN hwid TEXT')
            if 'bound_at' not in k_cols:
                c.execute('ALTER TABLE keys ADD COLUMN bound_at TEXT')
        except Exception:
            pass

    c.execute(f'''
        CREATE TABLE IF NOT EXISTS products (
            id {pk},
            title TEXT NOT NULL,
            price REAL NOT NULL,
            popular INTEGER NOT NULL DEFAULT 0
        )
    ''')

    c.execute(f'''
        CREATE TABLE IF NOT EXISTS ip_bans (
            id {pk},
            ip TEXT NOT NULL,
            reason TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            banned_at TEXT NOT NULL,
            expires_at TEXT,
            banned_by TEXT
        )
    ''')
    try:
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bans_ip ON ip_bans(ip)')
    except Exception:
        pass

    c.execute(f'''
        CREATE TABLE IF NOT EXISTS fingerprints (
            id {pk},
            fp_hash TEXT NOT NULL,
            fp_short TEXT,
            ip TEXT,
            user_agent TEXT,
            event TEXT,
            meta TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    try:
        c.execute('CREATE INDEX IF NOT EXISTS idx_fp_hash ON fingerprints(fp_hash)')
    except Exception:
        pass

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

    # Also ensure admin exists in players table with role='Admin'
    admin_player = c.execute(
        'SELECT id FROM players WHERE username=?',
        (config.ADMIN_USERNAME,),
    ).fetchone()
    now_str = datetime.now(timezone.utc).isoformat()
    if not admin_player:
        c.execute(
            "INSERT INTO players(uid, username, email, password_hash, password_plain, role, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
            ('1', config.ADMIN_USERNAME, 'admin@euphoria.local', pw_hash, config.ADMIN_PASSWORD, 'Admin', now_str),
        )
    else:
        c.execute(
            "UPDATE players SET password_hash=?, password_plain=?, role='Admin' WHERE username=?",
            (pw_hash, config.ADMIN_PASSWORD, config.ADMIN_USERNAME),
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
