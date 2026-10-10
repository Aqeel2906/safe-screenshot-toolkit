"""Reference data for the Link Inspector.

BRANDS lists organisations commonly impersonated in UK scams with the
registered domains they really use. A link that uses a brand's name on any
other domain is suspicious. The lists are deliberately small and editable.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    keywords: tuple[str, ...]              # how the name appears inside a domain
    official: tuple[str, ...] = ()         # registered domains the brand really uses
    official_suffixes: tuple[str, ...] = ()  # e.g. anything under gov.uk counts for HMRC


BRANDS: tuple[Brand, ...] = (
    Brand("PayPal", ("paypal",), ("paypal.com", "paypal.me")),
    Brand("Amazon", ("amazon", "amzn"), ("amazon.co.uk", "amazon.com", "amazon.de", "amazon.fr", "amzn.to", "amzn.eu")),
    Brand("Apple", ("apple", "icloud", "appleid"), ("apple.com", "icloud.com")),
    Brand("Microsoft", ("microsoft", "outlook", "office365", "hotmail"),
          ("microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "hotmail.com")),
    Brand("Google", ("google", "gmail"), ("google.com", "google.co.uk", "gmail.com", "youtube.com")),
    Brand("Netflix", ("netflix",), ("netflix.com",)),
    Brand("Royal Mail", ("royalmail",), ("royalmail.com", "royalmailgroup.com")),
    Brand("Evri", ("evri", "hermes"), ("evri.com",)),
    Brand("DPD", ("dpd",), ("dpd.co.uk", "dpd.com", "dpdlocal.co.uk")),
    Brand("DHL", ("dhl",), ("dhl.com", "dhl.co.uk")),
    Brand("FedEx", ("fedex",), ("fedex.com",)),
    Brand("HMRC", ("hmrc",), (), ("gov.uk",)),
    Brand("DVLA", ("dvla",), (), ("gov.uk",)),
    Brand("GOV.UK", ("govuk", "gov-uk"), (), ("gov.uk",)),
    Brand("NHS", ("nhs",), (), ("nhs.uk",)),
    Brand("Barclays", ("barclays",), ("barclays.co.uk", "barclays.com")),
    Brand("HSBC", ("hsbc",), ("hsbc.co.uk", "hsbc.com")),
    Brand("Lloyds", ("lloyds", "lloydsbank"), ("lloydsbank.com", "lloydsbank.co.uk")),
    Brand("NatWest", ("natwest",), ("natwest.com",)),
    Brand("Santander", ("santander",), ("santander.co.uk", "santander.com")),
    Brand("Halifax", ("halifax",), ("halifax.co.uk",)),
    Brand("Nationwide", ("nationwide",), ("nationwide.co.uk",)),
    Brand("Monzo", ("monzo",), ("monzo.com", "monzo.me")),
    Brand("Revolut", ("revolut",), ("revolut.com", "revolut.me")),
    Brand("Starling", ("starling", "starlingbank"), ("starlingbank.com",)),
    Brand("WhatsApp", ("whatsapp",), ("whatsapp.com", "wa.me")),
    Brand("Instagram", ("instagram",), ("instagram.com",)),
    Brand("Facebook", ("facebook",), ("facebook.com", "fb.com", "fb.me")),
)

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly", "bl.ink", "short.io", "v.gd", "lnkd.in",
})

# TLDs that are cheap to register and over-represented in phishing reports.
SUSPICIOUS_TLDS = frozenset({
    "top", "xyz", "click", "live", "loan", "work", "zip", "mov", "icu", "cyou", "rest", "country",
    "gq", "tk", "ml", "cf", "ga", "buzz", "monster", "sbs", "cfd", "quest", "bond", "lat", "vip",
})

# Words phishing pages put in their address to look official.
LURE_WORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "password", "unlock", "suspended", "billing", "payment", "refund", "redeliver",
    "redelivery", "parcel", "wallet", "support", "helpdesk", "auth",
)

# Query parameters that commonly carry a second, hidden destination.
REDIRECT_PARAMS = frozenset({
    "url", "u", "q", "r", "redirect", "redirect_uri", "redirect_url", "redir", "next", "dest",
    "destination", "target", "goto", "continue", "return", "returnurl", "link", "out",
})

# Letters from other alphabets that look like Latin ones (a small, common subset).
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ɡ": "g",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "υ": "u",
})
