"""Safe Screenshot Toolkit: Flask application factory."""
import importlib

from flask import Flask, jsonify, render_template, request

from .registry import MODULES, get_module, live_modules

MAX_REQUEST_BYTES = 1 * 1024 * 1024  # 1 MB is plenty for pasted text; images get their own limit later


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder="../static")
    app.config.update(MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES, JSON_SORT_KEYS=False)
    if test_config:
        app.config.update(test_config)

    # Register every live module's blueprint at /<slug>.
    for module in live_modules():
        package = importlib.import_module(module.import_path)
        app.register_blueprint(package.bp, url_prefix=f"/{module.slug}")

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.context_processor
    def inject_registry():
        return {
            "modules": MODULES,
            "live_count": len(live_modules()),
            "is_live": lambda slug: get_module(slug).live,
            "current_module": _current_module(),
        }

    @app.after_request
    def security_headers(response):
        # Strict Content Security Policy: no inline scripts, nothing loaded from other sites except fonts.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        # Pasted messages may be personal: never let a browser or proxy cache results.
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(413)
    def too_large(_error):
        message = "That's too much text. Paste up to 10,000 characters."
        if request.path.endswith("/api"):
            return jsonify(error=message), 413
        return render_template("error.html", message=message), 413

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", message="That page doesn't exist yet."), 404

    return app


def _current_module():
    """The registry entry for the page being shown, if it's a module page."""
    endpoint = request.endpoint or ""
    package = endpoint.split(".", 1)[0]
    return next((m for m in MODULES if m.package == package), None)
