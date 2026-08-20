"""Euphoria Flask application factory."""
from pathlib import Path

from flask import Flask

from . import config
from .db import init_db
from .routes import register_hooks, register_routes


def create_app() -> Flask:
    templates = Path(config.TEMPLATES_DIR)
    static = Path(config.STATIC_DIR)

    if not (templates / 'index.html').is_file():
        raise FileNotFoundError(
            f'Cannot find templates/index.html.\n'
            f'Looked in: {templates}\n'
            f'Project root resolved to: {config.ROOT}\n'
            f'Make sure you extracted the FULL zip and run: python main.py\n'
            f'from the folder that contains templates/ and euphoria/'
        )

    from datetime import timedelta

    app = Flask(
        __name__,
        template_folder=str(templates.resolve()),
        static_folder=str(static.resolve()) if static.is_dir() else None,
        static_url_path='/static',
    )
    app.config.update(
        SECRET_KEY=config.SECRET_KEY,
        SESSION_COOKIE_NAME='euphoria_session',
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_PATH='/',
        PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    )
    app.root_path = str(config.ROOT)

    register_hooks(app)
    register_routes(app)
    init_db()

    return app
