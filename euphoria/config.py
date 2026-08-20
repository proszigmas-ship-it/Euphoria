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

SECRET_KEY = os.environ.get('EUPHORIA_SECRET', 'CHANGE_THIS_SECRET')
ADMIN_USERNAME = os.environ.get('EUPHORIA_ADMIN_USER', 'admin')
ADMIN_PASSWORD = os.environ.get('EUPHORIA_ADMIN_PASSWORD', 'Euphoria#2026!Sec9X_Admin')

DEFAULT_PRODUCTS = [
    ('7 Days', 100, 0),
    ('30 Days', 320, 1),
    ('90 Days', 750, 0),
    ('Lifetime', 1200, 0),
    ('HWID Reset', 250, 0),
]

PLAYER_UID_BASE = 0
DEFAULT_PROMO = ('EUPHORIA20', 20)

KEY_DURATIONS = {
    '7 Days': 7,
    '30 Days': 30,
    '90 Days': 90,
    'Lifetime': None,
}

MAX_KEYS_PER_BATCH = 500
