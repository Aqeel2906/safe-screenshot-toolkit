"""Module 2: Link Inspector (routes)."""
from flask import Blueprint, jsonify, render_template, request

from .engine import MAX_INPUT_LENGTH, inspect_text

bp = Blueprint("link_inspector", __name__)

SAMPLES = (
    ("Brand in subdomain", "Your account is locked. Verify at https://paypal.com.account-verify.xyz/login"),
    ("@ trick", "Pay the £1.45 fee: https://www.royalmail.com@royalmail-redeliver.top/pay"),
    ("Look-alike letters", "Unusual sign-in detected. Review it at http://xn--pypal-4ve.com/signin"),
    ("Hidden redirect", "Secure message from HSBC: https://www.google.com/url?q=https://hsbc-secure-login.top/verify"),
    ("Defanged IOC", "Reported phish: hxxps://amaz0n-refunds[.]co/claim and hxxp://3232235777/"),
    ("Genuine link", "Track your parcel at https://www.royalmail.com/track-your-item"),
    ("Subdomain basics", "Log in at bank.example.com to see your statement."),
)


@bp.route("/", methods=["GET", "POST"])
def index():
    text, active = "", None
    if request.method == "POST":
        text = request.form.get("message", "")
    elif (sample := request.args.get("sample", type=int)) is not None and 0 <= sample < len(SAMPLES):
        text, active = SAMPLES[sample][1], sample

    result = inspect_text(text) if text.strip() else None
    return render_template(
        "modules/link_inspector.html",
        text=text,
        result=result,
        samples=SAMPLES,
        active_sample=active,
        max_length=MAX_INPUT_LENGTH,
    )


@bp.post("/api")
def api():
    """JSON endpoint for other modules and scripts: POST {"text": "..."}."""
    data = request.get_json(silent=True) or {}
    return jsonify(inspect_text(data.get("text", "")).to_dict())
