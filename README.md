# Safe Screenshot Toolkit

A privacy-focused Flask app that helps people spot scam messages and share screenshots safely. Links are never opened, and nothing you paste is stored or logged.

| # | Module | Status |
|---|--------|--------|
| 1 | Message Checker | ✅ Live |
| 2 | Link Inspector | ✅ Live |
| 3 | Screenshot Text Reader (OCR) | Planned |
| 4 | Privacy Detector | Planned |
| 5 | Redaction & Export | Planned |
| 6 | Combined Workspace | Planned |

## Run it

Needs Python 3.10 or newer.

```bash
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt

python app.py          # open http://127.0.0.1:5000
pytest                 # run the test suite
```

## Module 1: Message Checker

Paste a message and it flags common scam tactics, highlights the exact words, and explains each one with advice.

| Category | Severity | Examples |
|---|---|---|
| Credential request | High | "send your OTP", "confirm your card number" |
| Remote access | High | AnyDesk, TeamViewer, "install this app" |
| Payment demand | High | gift cards, crypto, "safe account", "£1.45 redelivery fee" |
| Threat | Medium | "account will be suspended", arrest, bailiffs |
| Urgency | Medium | "immediately", "within 24 hours", "final notice" |
| Secrecy | Medium | "don't tell anyone", "do not contact your bank" |
| Family impersonation | Medium | "Hi Mum… this is my new number" |
| Prize / refund bait | Medium | "you've won", "tax refund" |
| Credential mention | Low | code mentioned but not requested ("never share this code") |
| Impersonated brand | Low | HMRC, Royal Mail, PayPal, UK banks |
| Link present | Info | hands off to the Link Inspector |

- **Evasion-resistant:** Unicode NFKC folding (`ＯＴＰ`), zero-width character stripping, leetspeak decoding (`0TP`) and spaced letters (`O T P`). An index map keeps highlights on the original text.
- **Context-aware:** "Send your OTP" is high; "Never share this code" is not treated as a request.
- **Explainable scoring:** fixed weights per category, a capped bonus for repeats, and extra points for dangerous combinations (code request + urgency).

## Module 2: Link Inspector

Paste a message or link. It extracts every address and shows the **registered domain**, the part that really decides where a link goes, without ever visiting it.

| Check | Severity | Example |
|---|---|---|
| Script / data URL | High | `javascript:…`, `data:text/html…` |
| `@` userinfo trick | High | `https://royalmail.com@evil.top` goes to evil.top |
| Brand in subdomain | High | `paypal.com.account-verify.xyz` |
| Brand in someone else's domain | High | `royalmail-redeliver.top` |
| Typo / leetspeak look-alike | High | `paypa1.com`, `rnicrosoft.com` |
| Homograph (punycode) | High | `xn--pypal-4ve.com` displays as `pаypal.com` (Cyrillic а) |
| Raw or disguised IP | High | `192.168.4.20`, `3232235777`, `0xc0a80101` |
| Hidden redirect | Medium/High | `google.com/url?q=https://evil.top`, and the hidden target is checked too |
| Free hosting | Medium | `hmrc-refund.github.io` |
| Link shortener | Medium | `bit.ly/…` |
| Cheap TLD / odd port | Medium | `.top`, `.xyz`, `:8080` |
| No HTTPS, lure words, deep subdomains | Low | `http://`, "verify", "login" |
| Official domain | Info | `royalmail.com`, anything under `gov.uk` |

- Registered domains come from the **Public Suffix List** (via `tldextract`'s bundled snapshot), so `www.gov.uk`, `example.co.uk` and `user.github.io` are split correctly. No download happens at runtime.
- Accepts **defanged** IOCs (`hxxps://evil[.]com`) as used in threat-intel reports.
- A test blocks all socket connections to prove the inspector never touches the network.

## Security

- **No XSS:** user text is rendered by Jinja2 with auto-escaping. Tests post `<script>` payloads to every page.
- **Strict CSP:** `script-src 'self'`, no inline scripts or styles, `frame-ancestors 'none'`, `form-action 'self'`.
- **Other headers:** `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, `Cache-Control: no-store` (results aren't cached).
- **Limits:** 1 MB request cap (413), 10,000 characters analysed, 25 links per check.
- **ReDoS-safe:** patterns are anchored so matching stays linear; tests time adversarial input.
- **No JavaScript at all:** every page is server-rendered and works with scripts disabled.

## Architecture

```
app.py                          Entry point (python app.py)
toolkit/
  __init__.py                   create_app(): registers live modules, security headers, errors
  registry.py                   MODULES list: the single source of truth for the dashboard
  modules/
    message_checker/
      __init__.py               Blueprint: page + /api route
      engine.py                 analyse_message() (pure, no Flask)
      rules.py                  Categories, weights, explanations, combos
      normalise.py              Unicode / leetspeak / zero-width normalisation
    link_inspector/
      __init__.py               Blueprint: page + /api route
      engine.py                 extract_links(), inspect_url(), inspect_text() (pure, no Flask)
      brands.py                 Brands and official domains, shorteners, TLDs, confusables
  templates/
    base.html                   Top bar with live-module navigation
    dashboard.html              Homepage built from the registry
    modules/<package>.html      One page per module
    partials/                   Shared input panel, risk meter, footer
static/css/styles.css           Light and dark theme
tests/                          pytest: engines, app wiring, security
```

Each module's engine is plain Python with no Flask code, so Module 6 can import and chain them directly. Each module also has a JSON API, for example `POST /link-inspector/api` with `{"text": "..."}`.

## Adding a module

1. Copy `toolkit/modules/link_inspector/` to `toolkit/modules/<new_package>/` and replace the engine and routes.
2. Create `toolkit/templates/modules/<new_package>.html` (copy `link_inspector.html`).
3. In `toolkit/registry.py`, change the module's `status` from `"planned"` to `"live"`.
4. Run `pytest`. It fails if a live module is missing its blueprint, template or page.
5. Commit and push.

The app registers the blueprint, and the dashboard card, progress bar and top-bar navigation update automatically.

## Limitations

Rule-based checks catch common, known tactics. They can miss new wording, other languages, and genuine websites that have been hacked. "No warnings" doesn't mean a message or link is safe.

## Licence

MIT
