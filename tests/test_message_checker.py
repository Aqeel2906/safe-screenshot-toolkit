import time

import pytest

from toolkit.modules.message_checker.engine import MAX_INPUT_LENGTH, analyse_message, highlight_segments


def ids(report):
    return sorted(f.id for f in report.findings)


def test_brief_example_otp_with_pressure():
    r = analyse_message("Send your OTP immediately or your account will close")
    assert ids(r) == ["credentials", "threat", "urgency"]
    assert r.level == "high"
    assert any("time pressure" in c["reason"] for c in r.combos)


@pytest.mark.parametrize("msg", [
    "Reply with your 0TP now",
    "Send the O T P code",
    "Send the O​TP code",
    "Enter ＯＴＰ",
])
def test_obfuscated_otp_is_still_detected(msg):
    assert "credentials" in ids(analyse_message(msg))


def test_highlights_point_at_original_text_after_zero_width_removal():
    msg = "Please send O​TP now"
    match = next(f for f in analyse_message(msg).findings if f.id == "credentials").matches[0]
    assert msg[match.start:match.end] == match.text
    assert "O​TP" in match.text


def test_royal_mail_parcel_fee_smishing():
    r = analyse_message(
        "Royal Mail: Your parcel is on hold due to an unpaid £1.45 redelivery fee. "
        "Pay within 24 hours at https://royalmail-redeliver.top or it will be returned."
    )
    assert ids(r) == ["brand", "link", "payment", "threat", "urgency"]
    assert r.level == "high"


def test_hi_mum_scam():
    r = analyse_message("Hi mum it's me, I lost my phone so this is my new number. "
                        "Can you do a bank transfer for me? Don't tell dad")
    assert {"family_impersonation", "payment", "secrecy"} <= set(ids(r))
    assert any("new number" in c["reason"].lower() for c in r.combos)
    assert r.level == "high"


def test_safe_account_remote_access_scam():
    r = analyse_message("This is Barclays fraud team. Install AnyDesk so we can move your money "
                        "to a safe account. Do not contact your bank branch.")
    assert {"remote_access", "payment"} <= set(ids(r))
    assert r.level == "high"


@pytest.mark.parametrize("msg", [
    "Hey, are we still on for football at 6?",
    "I'm fine thanks, see you tomorrow",
    "Can you pick up some milk on the way home?",
    "",
])
def test_ordinary_messages_have_no_findings(msg):
    r = analyse_message(msg)
    assert r.level == "none" and r.score == 0


def test_brand_alone_is_low():
    r = analyse_message("Your Amazon order has been dispatched.")
    assert ids(r) == ["brand"] and r.level == "low"


def test_single_high_severity_tactic_is_at_least_medium():
    assert analyse_message("What is your password?").level == "medium"


@pytest.mark.parametrize("msg", [
    "Your Barclays OTP is 482913. Never share this code with anyone, not even us.",
    "Do not share your OTP with anyone. We will never ask for it.",
    "Don't share your verification code with anyone.",
])
def test_genuine_never_share_text_is_not_a_request(msg):
    r = analyse_message(msg)
    assert "credentials" not in ids(r)
    assert r.level != "high"


def test_casual_password_mention_is_low():
    r = analyse_message("I need to reset my password lol, forgot it again")
    assert ids(r) == ["credential_mention"] and r.level == "low"


def test_score_is_capped_at_100():
    r = analyse_message(
        "URGENT final notice from HMRC: send your OTP and card number immediately, pay the release fee with "
        "gift cards or bitcoin within 2 hours or face arrest. Do not tell anyone. Install AnyDesk. "
        "Claim your refund at http://x.top"
    )
    assert r.score == 100


def test_long_input_is_truncated_not_rejected():
    r = analyse_message("a" * (MAX_INPUT_LENGTH + 500) + " OTP")
    assert r.truncated and r.findings == []


@pytest.mark.parametrize("value", [None, 123, ["OTP"]])
def test_non_string_input_is_safe(value):
    assert analyse_message(value).level == "none"


def test_highlight_segments_rebuild_the_text_and_never_overlap():
    msg = "Send your one-time passcode now or your account will be suspended today"
    segments = highlight_segments(msg, analyse_message(msg))
    assert "".join(s["text"] for s in segments) == msg
    assert any(s["severity"] == "high" for s in segments)


def test_regexes_finish_quickly_on_adversarial_input():
    start = time.perf_counter()
    analyse_message("a." * 4000 + "!")
    analyse_message("send " + "x " * 4000 + "code")
    assert time.perf_counter() - start < 1.0
