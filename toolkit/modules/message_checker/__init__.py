"""Module 1: Message Checker (routes)."""
from flask import Blueprint, jsonify, render_template, request

from .engine import MAX_INPUT_LENGTH, SEVERITY_RANK, analyse_message, highlight_segments

bp = Blueprint("message_checker", __name__)

SAMPLES = (
    ("OTP + pressure", "Send your OTP immediately or your account will close"),
    ("Parcel fee", "Royal Mail: Your parcel is on hold due to an unpaid £1.45 redelivery fee. "
                   "Pay within 24 hours at https://royalmail-redeliver.top or it will be returned to sender."),
    ('"Hi Mum"', "Hi Mum, it's me. I dropped my phone so this is my new number. Can you do a bank transfer "
                 "for £650 for my rent? I'll pay you back tomorrow. Don't tell dad x"),
    ("Fake fraud team", "This is the HSBC fraud team. Your account has been compromised. Please download AnyDesk "
                        "so we can move your funds to a safe account. Do not contact your branch, staff may be involved."),
    ("Genuine bank code", "Your HSBC verification code is 482913. Never share this code with anyone, not even HSBC."),
    ("Normal text", "Running a bit late, see you at the station around 6?"),
)


@bp.route("/", methods=["GET", "POST"])
def index():
    text, active = "", None
    if request.method == "POST":
        text = request.form.get("message", "")
    elif (sample := request.args.get("sample", type=int)) is not None and 0 <= sample < len(SAMPLES):
        text, active = SAMPLES[sample][1], sample

    report = analyse_message(text) if text.strip() else None
    findings = sorted(report.findings, key=lambda f: (-SEVERITY_RANK[f.severity], -f.points)) if report else []
    return render_template(
        "modules/message_checker.html",
        text=text,
        report=report,
        findings=findings,
        segments=highlight_segments(text, report) if report else [],
        samples=SAMPLES,
        active_sample=active,
        max_length=MAX_INPUT_LENGTH,
    )


@bp.post("/api")
def api():
    """JSON endpoint for other modules and scripts: POST {"text": "..."}."""
    data = request.get_json(silent=True) or {}
    return jsonify(analyse_message(data.get("text", "")).to_dict())
