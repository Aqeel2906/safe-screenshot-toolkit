"""Link Inspector engine.

Finds links in text and explains where each one really goes. It never opens a
link or makes any network request: everything is worked out from the text of
the address alone. The public suffix list used to find the registered domain
is the snapshot bundled with tldextract, so even that needs no download.

Pure functions with no Flask imports, so they can be tested directly and
reused by the Combined Workspace (Module 6).
"""
import ipaddress
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

import tldextract

from .brands import (BRANDS, CONFUSABLES, LURE_WORDS, REDIRECT_PARAMS, SUSPICIOUS_TLDS,
                     URL_SHORTENERS, Brand)

MAX_INPUT_LENGTH = 10_000
MAX_LINKS = 25
SEVERITY_POINTS = {"high": 40, "medium": 20, "low": 8, "info": 0}

# suffix_list_urls=() -> use the bundled snapshot, never fetch. cache_dir=None -> write nothing to disk.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

# ---------------------------------------------------------------- extraction

# Security teams "defang" links (hxxp, [.]) so they can't be clicked. Turn them back so they can be inspected.
_DEFANG = (
    (re.compile(r"\bhxxp", re.I), "http"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.I), "."),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
)

_STOP = r"[^\s<>\"'`]"
_LINK_PATTERNS = (
    # Script and data URLs run code instead of opening a page.
    re.compile(rf"\bjavascript:{_STOP}+|\bdata:[a-z]+/[a-z0-9.+-]+[;,]{_STOP}*", re.I),
    re.compile(rf"\b(?:https?|ftp)://{_STOP}+", re.I),
    re.compile(rf"\bwww\.{_STOP}+", re.I),
    re.compile(rf"(?<![\w.])\d{{1,3}}(?:\.\d{{1,3}}){{3}}(?::\d{{2,5}})?(?:/{_STOP}*)?"),
    # Bare domains, including non-Latin letters. The lookbehind stops a match starting part-way
    # through a name or inside an email address, which also keeps matching linear (no ReDoS).
    re.compile(rf"(?<![\w.@/-])(?:[^\W_](?:[\w-]{{0,61}}[^\W_])?\.)+[^\W\d_]{{2,63}}(?::\d{{2,5}})?(?:/{_STOP}*)?"),
)
_TRAILING = ".,;:!?'\")]}>*"


def refang(text: str) -> str:
    for pattern, replacement in _DEFANG:
        text = pattern.sub(replacement, text)
    return text


def extract_links(text: str) -> list[str]:
    """Return links in the order they appear, without duplicates."""
    spans: list[tuple[int, int]] = []
    for pattern in _LINK_PATTERNS:
        for m in pattern.finditer(text):
            if any(m.start() < e and s < m.end() for s, e in spans):
                continue  # already covered by a more specific pattern
            spans.append((m.start(), m.end()))

    links, seen = [], set()
    for s, e in sorted(spans):
        link = _trim(text[s:e])
        if not _looks_like_link(link):
            continue
        key = link.lower()
        if key not in seen:
            seen.add(key)
            links.append(link)
        if len(links) >= MAX_LINKS:
            break
    return links


def _trim(link: str) -> str:
    while link and link[-1] in _TRAILING:
        if link[-1] == ")" and link.count("(") >= link.count(")"):
            break  # keep balanced brackets, e.g. Wikipedia links
        link = link[:-1]
    return link


def _looks_like_link(link: str) -> bool:
    if re.match(r"(?:javascript|data):", link, re.I):
        return True
    if re.match(r"[a-z][a-z0-9+.-]*://", link, re.I):
        return True
    host = urlsplit("http://" + link).hostname or ""
    if _parse_ip(host)[0]:
        return True
    parts = _extract(host)
    return bool(parts.domain and parts.suffix)


# ---------------------------------------------------------------- reports

@dataclass
class LinkFinding:
    id: str
    label: str
    severity: str  # high | medium | low | info
    explain: str


@dataclass
class LinkReport:
    original: str
    scheme: str = ""
    userinfo: str = ""
    host: str = ""
    host_unicode: str = ""
    port: int | None = None
    path: str = ""
    query: str = ""
    subdomain: str = ""
    registered_domain: str = ""
    suffix: str = ""
    is_ip: bool = False
    owner: str | None = None
    redirect_target: str | None = None
    findings: list[LinkFinding] = field(default_factory=list)
    score: int = 0
    level: str = "none"  # none | low | medium | high

    @property
    def host_prefix(self) -> str:
        """The part of the host before the registered domain (shown greyed out)."""
        host = self.host_unicode or self.host
        if self.registered_domain and host.endswith(self.registered_domain):
            return host[: -len(self.registered_domain)]
        return ""

    def add(self, id: str, label: str, severity: str, explain: str) -> None:
        self.findings.append(LinkFinding(id, label, severity, explain))

    def to_dict(self) -> dict:
        return asdict(self) | {"host_prefix": self.host_prefix}


@dataclass
class InspectResult:
    links: list[LinkReport]
    defanged: bool
    truncated: bool

    @property
    def worst_level(self) -> str:
        order = ["none", "low", "medium", "high"]
        return max((r.level for r in self.links), key=order.index, default="none")

    def to_dict(self) -> dict:
        return {"links": [r.to_dict() for r in self.links], "defanged": self.defanged,
                "truncated": self.truncated, "worst_level": self.worst_level}


def inspect_text(text: str | None) -> InspectResult:
    raw = text if isinstance(text, str) else ""
    truncated = len(raw) > MAX_INPUT_LENGTH
    raw = raw[:MAX_INPUT_LENGTH]
    clean = refang(raw)
    reports = [inspect_url(link) for link in extract_links(clean)]
    return InspectResult(links=reports, defanged=clean != raw, truncated=truncated)


def inspect_url(link: str) -> LinkReport:
    """Explain where one link really goes and what looks suspicious about it."""
    r = LinkReport(original=link)

    scheme_match = re.match(r"([a-z][a-z0-9+.-]*):", link, re.I)
    if scheme_match and scheme_match.group(1).lower() in ("javascript", "data", "vbscript"):
        r.scheme = scheme_match.group(1).lower()
        r.add("dangerous_scheme", "Runs code instead of opening a web page", "high",
              f"A {r.scheme}: link doesn't go to a website at all. It runs code or loads hidden content in your browser. "
              "Legitimate messages never send these.")
        return _score(r)

    has_scheme = bool(re.match(r"[a-z][a-z0-9+.-]*://", link, re.I))
    parts = urlsplit(link if has_scheme else "http://" + link)
    r.scheme = parts.scheme.lower() if has_scheme else ""
    r.host = (parts.hostname or "").rstrip(".")
    r.path, r.query = parts.path, parts.query
    if "@" in parts.netloc:
        r.userinfo = unquote(parts.netloc.rpartition("@")[0])
    try:
        r.port = parts.port
    except ValueError:
        r.port = None
    if not r.host:
        r.add("no_host", "Not a complete web address", "low", "There's no website name in this link, so it can't be checked.")
        return _score(r)

    r.host_unicode = _to_unicode(r.host)
    is_ip, encoded_ip = _parse_ip(r.host)
    r.is_ip = is_ip

    if not is_ip:
        ext = _extract(r.host_unicode)
        r.suffix = ext.suffix
        r.subdomain = ext.subdomain
        r.registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else r.host_unicode
        r.owner = _official_owner(r.registered_domain, r.suffix)
        _check_name(r, ext)
    else:
        r.registered_domain = r.host

    _check_structure(r, is_ip, encoded_ip)
    return _score(r)


# ---------------------------------------------------------------- checks

def _check_name(r: LinkReport, ext) -> None:
    """Checks about the website name itself: brands, look-alikes, odd characters."""
    domain_tokens = _tokens(ext.domain)
    sub_tokens = _tokens(ext.subdomain)

    if r.host_unicode != r.host or not r.host.isascii():
        skeleton = r.host_unicode.translate(CONFUSABLES)
        copied = _brand_for_tokens(_tokens(_extract(skeleton).domain))
        scripts = _scripts(r.host_unicode)
        ascii_host = _to_ascii(r.host)
        if copied and copied[1] in ("exact", "contains", "lookalike"):
            r.add("homograph", f"Uses look-alike letters to copy {copied[0].name}", "high",
                  f"This address is written with letters from another alphabet ({', '.join(sorted(scripts - {'LATIN'})) or 'non-Latin'}) "
                  f"that look identical to normal ones. It reads like {copied[0].name}, but the real address is {ascii_host}.")
        else:
            r.add("idn", "Uses non-Latin characters in the address", "medium",
                  f"The address contains characters outside the normal A to Z. Browsers may show it as “{r.host_unicode}”, "
                  f"but its real form is {ascii_host}. Mixed alphabets are a common trick to copy real names.")

    if r.owner:
        r.add("official", f"Registered domain belongs to {r.owner}", "info",
              f"{r.registered_domain} is a domain {r.owner} really uses. That's a good sign, but scammers can still "
              "hide a second destination inside a genuine link, so check the other notes too.")
        return

    if ext.subdomain and ext.subdomain != "www":
        r.add("subdomain", f"The real website is {r.registered_domain}", "info",
              f"The registered domain is the name just before the ending (.{r.suffix}). It decides where the link goes. "
              f"“{ext.subdomain}.” in front of it is a subdomain, and whoever owns {r.registered_domain} can make it say anything.")

    sub_brand = _brand_for_tokens(sub_tokens)
    if sub_brand:
        r.add("brand_in_subdomain", f"“{sub_brand[0].name}” is only in the subdomain", "high",
              f"The address starts with {sub_brand[0].name}'s name, but the website is really {r.registered_domain}, "
              f"which {sub_brand[0].name} doesn't own. Putting a brand at the front is a classic phishing trick "
              f"because people read links from the left.")

    dom_brand = _brand_for_tokens(domain_tokens)
    already_homograph = any(f.id == "homograph" for f in r.findings)
    if dom_brand and not already_homograph:
        brand, kind = dom_brand
        official = _official_list(brand)
        if kind == "lookalike":
            r.add("brand_lookalike", f"Misspells {brand.name} to look genuine", "high",
                  f"“{ext.domain}” is one or two characters away from “{brand.keywords[0]}”. "
                  f"{brand.name}'s real addresses are {official}.")
        elif kind == "exact" and len(domain_tokens) == 1:
            r.add("brand_wrong_ending", f"Uses {brand.name}'s name with an unusual ending", "medium",
                  f"{r.registered_domain} isn't one of the domains {brand.name} uses ({official}). "
                  "Scammers register the same name under a different ending.")
        else:
            r.add("brand_in_domain", f"Uses {brand.name}'s name in a domain it doesn't own", "high",
                  f"{r.registered_domain} adds extra words to {brand.name}'s name, but it isn't {brand.name}'s website. "
                  f"{brand.name}'s real addresses are {official}.")

    if not sub_brand and not dom_brand:
        path_brand = _brand_for_tokens(_tokens(unquote(r.path)), allow_lookalike=False)
        if path_brand:
            r.add("brand_in_path", f"Mentions {path_brand[0].name} after the website name", "medium",
                  f"{path_brand[0].name} appears in the page path, but the website itself is {r.registered_domain}. "
                  "Anyone can put any words after the slash.")

    if ext.is_private:
        r.add("free_hosting", f"Hosted on {r.suffix}, where anyone can make a site", "medium",
              f"{r.suffix} is a hosting service that gives out free addresses. The site at {r.registered_domain} "
              "belongs to whoever signed up, not the hosting company.")

    if r.registered_domain in URL_SHORTENERS:
        r.add("shortener", "Short link that hides the real destination", "medium",
              f"{r.registered_domain} is a link shortener. The text tells you nothing about where it ends up, "
              "which is why scammers like them.")

    tld = r.suffix.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        r.add("cheap_tld", f"Ends in .{tld}, common in scam sites", "medium",
              f".{tld} addresses are cheap to register and appear often in phishing reports. "
              "Many are legitimate, but it's rare for a bank or delivery company to use one.")

    if len(ext.subdomain.split(".")) >= 3:
        r.add("deep_subdomains", "Unusually many parts before the real name", "low",
              "Long chains of subdomains push the real website name out of view, especially on a phone screen.")
    if ext.domain.count("-") >= 3 or len(r.host) > 50:
        r.add("long_name", "Long or heavily hyphenated name", "low",
              "Genuine organisations use short, memorable addresses. Long hyphenated names are cheap throwaway registrations.")

    words_found = sorted({w for w in LURE_WORDS if w in (r.host + " " + r.path.lower())})
    if words_found:
        r.add("lure_words", "Uses words designed to look official", "low",
              f"The address contains {', '.join(f'“{w}”' for w in words_found[:5])}. "
              "Phishing pages add these to look like a real sign-in or payment page.")


def _check_structure(r: LinkReport, is_ip: bool, encoded_ip: bool) -> None:
    """Checks about how the address is put together."""
    if r.userinfo:
        r.add("userinfo_trick", "Hides the real address behind an @", "high",
              f"Browsers ignore everything before the @. This link shows “{r.userinfo}” first, "
              f"but it actually goes to {r.host}.")

    if encoded_ip:
        r.add("encoded_ip", "Uses a disguised number instead of a website name", "high",
              f"“{r.host}” is an IP address written in an unusual form so it doesn't look like one. "
              "There's no innocent reason for this in a message.")
    elif is_ip:
        r.add("ip_address", "Uses a bare IP address instead of a website name", "high",
              f"{r.host} is a raw server address. Real companies link to their name, not a number, "
              "and an IP address can't be traced to an organisation by reading it.")

    if r.port not in (None, 80, 443):
        r.add("odd_port", f"Uses an unusual port ({r.port})", "medium",
              "Normal websites don't put a port number in their links. It often means a home-made or compromised server.")

    if r.scheme == "http":
        r.add("no_https", "Not encrypted (http, not https)", "low",
              "Anything typed into this page can be read in transit. Real login and payment pages always use https.")

    for name, value in parse_qsl(r.query, keep_blank_values=False):
        value = value.strip()
        if name.lower() in REDIRECT_PARAMS and re.match(r"(?:https?:)?//", value, re.I):
            r.redirect_target = value
            target = inspect_url(value if value.startswith("http") else "https:" + value)
            r.add("hidden_redirect", f"Forwards you on to {target.registered_domain or 'another site'}", "medium",
                  f"The link contains a second address in its “{name}=” setting. Opening it may send you straight on to "
                  f"{target.registered_domain or value}, so the first website name isn't where you end up.")
            if target.level == "high":
                r.add("redirect_suspicious", "The hidden destination looks dangerous", "high",
                      f"Checking {target.registered_domain} on its own finds: "
                      f"{'; '.join(f.label for f in target.findings if f.severity == 'high')}.")
            break

    if len(re.findall(r"%[0-9a-f]{2}", r.path + r.query, re.I)) >= 6:
        r.add("encoded", "Heavily encoded address", "low",
              "Lots of %-codes hide readable text in the address. It's sometimes used to sneak a second link or brand name past filters.")


def _score(r: LinkReport) -> LinkReport:
    # Most serious first; the stable sort keeps check order within a severity.
    r.findings.sort(key=lambda f: -SEVERITY_POINTS[f.severity])
    r.score = min(100, sum(SEVERITY_POINTS[f.severity] for f in r.findings))
    r.level = "high" if r.score >= 40 else "medium" if r.score >= 20 else "low" if r.score > 0 else "none"
    return r


# ---------------------------------------------------------------- helpers

def _tokens(text: str) -> list[str]:
    """Split a name into words, plus the whole name joined up ("royal-mail" also gives "royalmail")."""
    words = [t for t in re.split(r"[^\w]+|_", text.lower()) if t]
    joined = re.sub(r"[^\w]", "", text.lower())
    return words + ([joined] if joined and joined not in words else [])


def _skeletons(token: str) -> set[str]:
    base = token.translate(CONFUSABLES).replace("rn", "m").replace("vv", "w")
    return {
        base.translate(str.maketrans("013457", "oleast")),  # paypa1 -> paypal
        base.translate(str.maketrans("013457", "oieast")),  # m1crosoft -> microsoft
    }


def _brand_for_tokens(tokens: list[str], allow_lookalike: bool = True) -> tuple[Brand, str] | None:
    """Return (brand, how) where how is exact | contains | lookalike."""
    best = None
    for token in tokens:
        for brand in BRANDS:
            for kw in brand.keywords:
                if token == kw:
                    return brand, "exact"
                if len(kw) >= 5 and kw in token:
                    best = best or (brand, "contains")
                elif allow_lookalike and len(token) >= 4 and len(kw) >= 4:
                    skels = _skeletons(token)
                    if kw in skels or (len(kw) >= 5 and any(_distance(s, kw) == 1 for s in skels)):
                        best = best or (brand, "lookalike")
    return best


def _distance(a: str, b: str) -> int:
    """Levenshtein edit distance (small strings only)."""
    if abs(len(a) - len(b)) > 1:
        return 2
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _official_owner(registered: str, suffix: str) -> str | None:
    for brand in BRANDS:
        if registered in brand.official:
            return brand.name
    for brand in BRANDS:
        if suffix in brand.official_suffixes:
            return {"gov.uk": "the UK Government (GOV.UK)", "nhs.uk": "the NHS"}.get(suffix, brand.name)
    return None


def _official_list(brand: Brand) -> str:
    items = list(brand.official) + [f"addresses ending .{s}" for s in brand.official_suffixes]
    return ", ".join(items[:4])


def _to_unicode(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def _to_ascii(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def _scripts(text: str) -> set[str]:
    """Names of the alphabets used, e.g. {"LATIN", "CYRILLIC"}."""
    out = set()
    for ch in text:
        if ch.isalpha():
            out.add(unicodedata.name(ch, "UNKNOWN").split(" ")[0])
    return out


_ENCODED_IP = re.compile(r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$", re.I)


def _parse_ip(host: str) -> tuple[bool, bool]:
    """Return (is_ip, is_disguised). Browsers accept 3232235777 or 0xc0a80101 for 192.168.1.1."""
    try:
        ipaddress.ip_address(host)
        return True, False
    except ValueError:
        pass
    if _ENCODED_IP.match(host) and not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return True, True
    return False, False
