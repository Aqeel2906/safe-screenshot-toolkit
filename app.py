"""Run the Safe Screenshot Toolkit locally:  python app.py  ->  http://127.0.0.1:5000"""
import os

from toolkit import create_app

app = create_app()

if __name__ == "__main__":
    # Listens on this computer only. Debug mode is off unless you set FLASK_DEBUG=1.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG") == "1")
