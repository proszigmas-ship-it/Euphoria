EUPHORIA — Full Project (Clean Structure)

══════════════════════════════════════════════════════════════
 PROJECT LAYOUT
══════════════════════════════════════════════════════════════
main.py                 ← entry point (python main.py)
euphoria/
  __init__.py           ← create_app() factory
  config.py             ← settings, env vars, defaults
  db.py                 ← SQLite connection + schema
  security.py           ← HMAC hashing, fingerprints, compare
  routes.py             ← all HTTP routes
templates/
  index.html            ← frontend (RU/EN/KA/UK)
requirements.txt
README.txt

══════════════════════════════════════════════════════════════
 FEATURES
══════════════════════════════════════════════════════════════
• Multi-language: RU / EN / KA / UK
• Admin login (session)
• Products: 7 Days / 30 Days / Lifetime / HWID Reset 250₽
• Promo codes
• Key generator (up to 500, max uses)
• UID + HWID binding (HMAC-SHA256, never plaintext)
• HWID Reset in admin panel
• IP Ban system
• Browser fingerprinting (Canvas, WebGL, Audio, UA…)
• Payment UI: FunPay / ЮMoney / Card / Visa / Mastercard

══════════════════════════════════════════════════════════════
 HOW TO RUN
══════════════════════════════════════════════════════════════
EASIEST ON WINDOWS:
Double-click START_EUPHORIA.bat. It installs the required packages,
starts the site, and opens http://127.0.0.1:5000 in your browser.

MANUAL:
1) pip install -r requirements.txt
2) python main.py
3) Open http://127.0.0.1:5000

Admin:  admin / EuP!2026#Z7mQ@41x

══════════════════════════════════════════════════════════════
 PRODUCTION
══════════════════════════════════════════════════════════════
export EUPHORIA_SECRET="long-random-secret"
export EUPHORIA_ADMIN_PASSWORD="strong-password"
python main.py

chmod 600 euphoria.db
Use HTTPS behind nginx / Cloudflare.

══════════════════════════════════════════════════════════════
 API
══════════════════════════════════════════════════════════════
Public:
  GET  /api/products
  GET  /api/promos
  POST /api/redeem-key            { key, uid?, hwid? }

Admin:
  POST /api/admin/login           { username, password, fingerprint? }
  POST /api/admin/logout
  POST /api/admin/products
  DELETE /api/admin/products/<id>
  POST /api/admin/promos
  DELETE /api/admin/promos/<code>
  POST /api/admin/keys/generate   { duration, amount, max_uses }
  GET  /api/admin/keys
  POST /api/admin/keys/<id>/disable
  POST /api/admin/keys/<id>/reset-hwid
  GET  /api/admin/ip-bans
  POST /api/admin/ip-bans         { ip, reason?, days? }
  POST /api/admin/ip-bans/<id>/unban
  GET  /api/admin/fingerprints
