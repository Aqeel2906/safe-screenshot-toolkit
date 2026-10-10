"""Tests for the Flask app: dashboard, module registry wiring, security headers."""
import importlib
from pathlib import Path

import pytest

from toolkit import create_app
from toolkit.registry import MODULES

TEMPLATES = Path(__file__).resolve().parent.parent / "toolkit" / "templates"


@pytest.fixture
def client():
    return create_app({"TESTING": True}).test_client()


# ------------------------------------------------------------ registry

def test_module_numbers_are_in_order_and_slugs_unique():
    assert [m.number for m in MODULES] == list(range(1, len(MODULES) + 1))
    assert len({m.slug for m in MODULES}) == len(MODULES)


@pytest.mark.parametrize("module", [m for m in MODULES if m.live], ids=lambda m: m.slug)
def test_every_live_module_is_fully_wired_up(module, client):
    package = importlib.import_module(module.import_path)
    assert hasattr(package, "bp"), f"{module.import_path} needs a Blueprint called bp"
    assert (TEMPLATES / module.template).exists(), f"missing template {module.template}"
    assert client.get(f"/{module.slug}/").status_code == 200


@pytest.mark.parametrize("module", [m for m in MODULES if not m.live], ids=lambda m: m.slug)
def test_planned_modules_are_not_reachable(module, client):
    assert client.get(f"/{module.slug}/").status_code == 404


# ------------------------------------------------------------ dashboard

def test_dashboard_lists_every_module_and_progress(client):
    html = client.get("/").get_data(as_text=True)
    for m in MODULES:
        assert m.name.replace("&", "&amp;") in html
    live = sum(m.live for m in MODULES)
    assert f"{live} of {len(MODULES)} modules ready" in html
    for m in MODULES:
        assert (f'href="/{m.slug}/"' in html) == m.live


# ------------------------------------------------------------ module pages

def test_message_checker_post_shows_verdict(client):
    html = client.post("/message-checker/", data={"message": "Send your OTP immediately"}).get_data(as_text=True)
    assert "This looks like a scam" in html or "Be careful" in html


def test_message_checker_hands_links_to_link_inspector(client):
    html = client.post("/message-checker/", data={"message": "Pay at https://x.top now"}).get_data(as_text=True)
    assert 'action="/link-inspector/"' in html


def test_link_inspector_shows_registered_domain(client):
    html = client.post("/link-inspector/", data={"message": "bank.example.com"}).get_data(as_text=True)
    assert '<span class="host-reg">example.com</span>' in html


@pytest.mark.parametrize("path", ["/message-checker/", "/link-inspector/"])
def test_samples_load(client, path):
    assert client.get(f"{path}?sample=0").status_code == 200
    assert client.get(f"{path}?sample=999").status_code == 200  # out of range is ignored


@pytest.mark.parametrize("path", ["/message-checker/", "/link-inspector/"])
def test_pasted_html_is_escaped_not_executed(client, path):
    payload = '<script>alert(1)</script> https://evil.top/"><img src=x onerror=alert(1)>'
    html = client.post(path, data={"message": payload}).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.parametrize("path", ["/message-checker/api", "/link-inspector/api"])
def test_json_api(client, path):
    response = client.post(path, json={"text": "Send your OTP to https://paypal.com.evil.top"})
    assert response.status_code == 200
    assert response.is_json


# ------------------------------------------------------------ security

def test_security_headers(client):
    headers = client.get("/").headers
    csp = headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cache-Control"] == "no-store"


def test_oversized_request_is_rejected(client):
    response = client.post("/message-checker/", data={"message": "a" * (2 * 1024 * 1024)})
    assert response.status_code == 413


def test_unknown_page_is_friendly_404(client):
    response = client.get("/nope")
    assert response.status_code == 404
    assert "exist yet" in response.get_data(as_text=True)
