"""Application configuration."""
import os
from pathlib import Path

# Project root = folder that contains main.py, templates/, static/, euphoria/
# config.py lives at <root>/euphoria/config.py → parent.parent is root
_PACKAGE_DIR = Path(__file__).resolve().parent
BASE_DIR = _PACKAGE_DIR.parent

# Fallbacks if the package is nested oddly on Windows extracts
def _resolve_root() -> Path:
    candidates = [
        BASE_DIR,
        BASE_DIR.parent,
        Path.cwd(),
        Path.cwd().parent,
    ]
    for root in candidates:
        if (root / 'templates' / 'index.html').is_file():
            return root.resolve()
    # default: expected layout
    return BASE_DIR.resolve()

ROOT = _resolve_root()
TEMPLATES_DIR = ROOT / 'templates'
STATIC_DIR = ROOT / 'static'
DB_PATH = ROOT / 'euphoria.db'

DATABASE_URL = os.environ.get('DATABASE_URL', '')
SECRET_KEY = os.environ.get('EUPHORIA_SECRET', 'CHANGE_THIS_SECRET')
ADMIN_USERNAME = os.environ.get('EUPHORIA_ADMIN_USER', 'admin')
ADMIN_PASSWORD = os.environ.get('EUPHORIA_ADMIN_PASSWORD', 'Euphoria#2026!Sec9X_Admin')
CRYPTOBOT_API_TOKEN = os.environ.get('CRYPTOBOT_API_TOKEN', '624589:AAznMORRmPNjYNAUd9ad6uAjDF3tKgoJ3EV')
IS_TESTING = False

SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '465'))
SMTP_USER = os.environ.get('SMTP_USER', 'euphoria.auth@gmail.com')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', 'K9#vX2$mQ8!zL4@wR7*p')
SMTP_FROM = os.environ.get('SMTP_FROM', 'euphoria.auth@gmail.com')

DEFAULT_PRODUCTS = [
    ('30 Days', 159, 0),
    ('90 Days', 259, 0),
    ('365 Days', 459, 1),
    ('Lifetime', 699, 0),
    ('HWID Reset', 199, 0),
]

PLAYER_UID_BASE = 0
DEFAULT_PROMO = ('EUPHORIA20', 20)

KEY_DURATIONS = {
    '7 Days': 7,
    '30 Days': 30,
    '90 Days': 90,
    '365 Days': 365,
    'Lifetime': None,
}

MAX_KEYS_PER_BATCH = 500
