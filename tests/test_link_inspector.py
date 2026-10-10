import socket
import time

import pytest

from toolkit.modules.link_inspector.engine import extract_links, inspect_text, inspect_url, refang


def ids(report):
    return {f.id for f in report.findings}


# ------------------------------------------------------------ extraction

def test_extracts_scheme_www_and_bare_links_in_order():
    text = "Go to https://a.example.com/x, then www.b.example.org or c.example.co.uk."
    assert extract_links(text) == ["https://a.example.com/x", "www.b.example.org", "c.example.co.uk"]


def test_ignores_emails_filenames_and_versions():
    assert extract_links("Email bob@example.com about report.txt, v2.0 and e.g. this") == []


def test_keeps_balanced_brackets_and_trims_punctuation():
    links = extract_links("(see https://en.wikipedia.org/wiki/Phishing_(disambiguation)).")
    assert links == ["https://en.wikipedia.org/wiki/Phishing_(disambiguation)"]


def test_duplicates_are_removed():
    assert len(extract_links("bit.ly/abc and again bit.ly/abc")) == 1


def test_refangs_defanged_links():
    assert refang("hxxps://evil[.]example(.)com[/]x") == "https://evil.example.com/x"
    result = inspect_text("hxxps://amaz0n-refunds[.]co/claim")
    assert result.defanged and result.links[0].registered_domain == "amaz0n-refunds.co"


# ------------------------------------------------------------ the brief's example

def test_brief_example_registered_domain_is_explained():
    r = inspect_url("bank.example.com")
    assert r.registered_domain == "example.com"
    assert r.subdomain == "bank"
    assert r.host_prefix == "bank."
    assert "subdomain" in ids(r)


# ------------------------------------------------------------ phishing tricks

def test_brand_in_subdomain():
    r = inspect_url("https://paypal.com.account-verify.xyz/login")
    assert r.registered_domain == "account-verify.xyz"
    assert {"brand_in_subdomain", "cheap_tld"} <= ids(r)
    assert r.level == "high"


def test_userinfo_at_sign_trick():
    r = inspect_url("https://www.royalmail.com@royalmail-redeliver.top/pay")
    assert r.host == "royalmail-redeliver.top"
    assert r.userinfo == "www.royalmail.com"
    assert {"userinfo_trick", "brand_in_domain"} <= ids(r)


@pytest.mark.parametrize("link,brand", [("paypa1.com", "PayPal"), ("amaz0n-refunds.co", "Amazon"),
                                        ("rnicrosoft.com", "Microsoft"), ("barc1ays.co.uk", "Barclays")])
def test_typo_and_leet_lookalikes(link, brand):
    r = inspect_url(link)
    assert "brand_lookalike" in ids(r)
    assert brand in next(f.label for f in r.findings if f.id == "brand_lookalike")


def test_punycode_homograph():
    r = inspect_url("http://xn--pypal-4ve.com/signin")
    assert r.host_unicode == "pаypal.com"  # Cyrillic а
    assert "homograph" in ids(r)
    assert "brand_lookalike" not in ids(r)  # not double-counted
    assert r.level == "high"


def test_raw_and_disguised_ip_addresses():
    assert "ip_address" in ids(inspect_url("http://192.168.4.20:8080/login"))
    assert "odd_port" in ids(inspect_url("http://192.168.4.20:8080/login"))
    assert "encoded_ip" in ids(inspect_url("http://3232235777/"))
    assert "encoded_ip" in ids(inspect_url("http://0xc0a80101/"))


def test_hidden_redirect_inside_genuine_domain():
    r = inspect_url("https://www.google.com/url?q=https://hsbc-secure-login.top/verify")
    assert r.owner == "Google"
    assert r.redirect_target == "https://hsbc-secure-login.top/verify"
    assert {"hidden_redirect", "redirect_suspicious"} <= ids(r)
    assert r.level == "high"


def test_free_hosting_and_shortener():
    assert "free_hosting" in ids(inspect_url("https://hmrc-tax-refund.github.io/claim"))
    assert "shortener" in ids(inspect_url("https://bit.ly/3xYz9Q"))


def test_dangerous_schemes():
    r = inspect_url("javascript:alert(document.cookie)")
    assert "dangerous_scheme" in ids(r) and r.level == "high"
    assert inspect_text("click data:text/html;base64,PHNjcmlwdD4=").links[0].level == "high"


def test_brand_name_with_wrong_ending_is_medium():
    r = inspect_url("https://paypal.co/")
    assert "brand_wrong_ending" in ids(r) and r.level == "medium"


# ------------------------------------------------------------ genuine links

@pytest.mark.parametrize("link,owner", [
    ("https://www.royalmail.com/track-your-item", "Royal Mail"),
    ("https://www.gov.uk/check-tax", "the UK Government (GOV.UK)"),
    ("WWW.NATWEST.COM", "NatWest"),
    ("https://www.nhs.uk/conditions", "the NHS"),
])
def test_official_domains_are_recognised(link, owner):
    r = inspect_url(link)
    assert r.owner == owner
    assert r.level == "none"


def test_ordinary_site_has_no_warnings():
    assert inspect_url("https://www.bbc.co.uk/news").level == "none"


# ------------------------------------------------------------ safety

def test_never_touches_the_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Link Inspector tried to open a network connection")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    inspect_text("https://paypal.com.account-verify.xyz/login https://bit.ly/x http://xn--pypal-4ve.com")


def test_link_count_is_capped():
    text = " ".join(f"site{i}.example.com" for i in range(100))
    assert len(inspect_text(text).links) == 25


@pytest.mark.parametrize("value", [None, 42, ""])
def test_bad_input_is_safe(value):
    assert inspect_text(value).links == []


def test_extraction_is_fast_on_adversarial_input():
    start = time.perf_counter()
    inspect_text("a." * 4000 + "!")
    inspect_text("a-" * 4000 + ".com")
    assert time.perf_counter() - start < 1.0
