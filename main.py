"""Euphoria — Flask entry point."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from euphoria import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "0.0.0.0"),
            port=int(os.environ.get("PORT", "5000")),
            debug=False)
