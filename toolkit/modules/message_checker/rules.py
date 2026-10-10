"""Detection rules for the Message Checker.

Each category groups regex patterns that point to one scam tactic. Patterns run
against the normalised (lower-case) text. `leet=True` also runs them against the
leetspeak-decoded copy, which catches "0TP" or "p@ssw0rd".

Weights feed the risk score in engine.py. They are deliberately simple and
documented so the scoring can be explained, not a black box.
"""
from dataclasses import dataclass

from .normalise import spaced


def words(*options: str) -> str:
    """Match any option as a whole word or phrase."""
    return r"\b(?:" + "|".join(options) + r")\b"


@dataclass(frozen=True)
class Category:
    id: str
    label: str
    severity: str  # high | medium | low | info
    weight: int
    explain: str
    advice: str
    patterns: tuple[str, ...]
    leet: bool = False
    suppressed_by: str | None = None   # skip if this stronger category already fired
    skip_if_negated: bool = False      # ignore matches preceded by "never" / "do not"


# Sensitive things a scammer wants. Shared by the two credential rules.
SECRET = "|".join([
    spaced("otp"), r"one[\s-]?time\s(?:pass(?:code|word)|code|pin)", r"verification\scode",
    r"security\scode", r"authenticat(?:ion|or)\scode", r"2fa\scode", r"confirmation\scode",
    r"(?:6|six)[\s-]?digit\scode",
    r"passwords?", r"passcodes?", r"pin(?:\snumber)?", r"login\sdetails", r"log[\s-]?in\scredentials",
    r"memorable\s(?:word|information)", r"security\squestions?",
    r"card\s(?:number|details)", r"cvv", r"cvc", r"expiry\sdate", r"sort\scode",
    r"account\snumber", r"bank\sdetails", r"online\sbanking\sdetails",
])

# A request verb, then up to five words, then a secret ("send us the 6 digit code").
REQUEST = (
    r"\b(?:send|share|give|provide|enter|confirm|verify|update|submit|type|text|forward|read\sout|"
    r"reply\swith|tell\s(?:us|me)|what'?s|what\sis|need(?=\s(?:your|the)\b))\b"
)

CATEGORIES: tuple[Category, ...] = (
    Category(
        id="credentials",
        label="Asks for passwords, codes or card details",
        severity="high", weight=35, leet=True, skip_if_negated=True,
        patterns=(
            rf"{REQUEST}(?:\s+\S+){{0,5}}?\s+(?:{SECRET})\b",
            rf"\b(?:{SECRET})\s(?:needed|required|asap|now|please)\b",
        ),
        explain=("Real banks and services never ask you to send a password, PIN or one-time code by message. "
                 "A one-time code is the final key to your account: whoever has it can log in or approve a payment."),
        advice="Never share codes or passwords. If unsure, contact the company using the number on its official website or your card.",
    ),
    Category(
        id="credential_mention",
        label="Mentions passwords, codes or card details",
        severity="low", weight=8, leet=True, suppressed_by="credentials",
        patterns=(rf"\b(?:{SECRET})\b",),
        explain=("The message mentions a password, code or card details but doesn't clearly ask for them. "
                 'Genuine security texts often say "never share this code", which is fine. Be wary if someone then asks you for it.'),
        advice="Never read out or forward a code you receive, even to someone claiming to be from the company.",
    ),
    Category(
        id="remote_access",
        label="Asks you to install software or give remote access",
        severity="high", weight=30,
        patterns=(
            words("anydesk", "teamviewer", r"quick\s?support", "rustdesk", "ultraviewer", "supremo"),
            words(r"remote\s(?:access|control|support|desktop)", r"screen\s?shar(?:e|ing)",
                  r"(?:download|install)\s(?:this|the|our)\s(?:app|application|software)"),
        ),
        explain=("Remote-access apps let someone else control your device, including your banking app. "
                 "Scammers posing as support staff use them to take money while you watch."),
        advice="Don't install apps at the request of someone who contacted you unexpectedly.",
    ),
    Category(
        id="payment",
        label="Demands payment or unusual payment methods",
        severity="high", weight=25,
        patterns=(
            words(r"gift\s?cards?", r"itunes\scards?", r"google\splay\scards?", r"steam\scards?", r"amazon\svouchers?",
                  "bitcoin", "btc", r"crypto(?:currency)?", "usdt", r"western\sunion", "moneygram"),
            words(r"safe\saccount", r"secure\saccount", r"holding\saccount"),
            words(r"(?:delivery|redelivery|customs|release|processing|admin(?:istration)?|unlock)\sfee",
                  r"outstanding\s(?:payment|balance|amount)", r"unpaid\s(?:bill|invoice|toll|fine|tax)",
                  r"pay\s(?:now|immediately|the\sfee|a\ssmall\sfee)", r"make\sa\spayment",
                  r"(?:bank|wire)\stransfer", r"transfer\s(?:the\s)?(?:money|funds)"),
            r"[£$€]\s?\d+(?:[.,]\d{2})?(?=[^.!?\n]{0,40}\b(?:fee|pay|charge|owe|due)\b)",
        ),
        explain=("Pressure to pay, especially by gift card, crypto or bank transfer to a \"safe account\", is a hallmark of fraud. "
                 "These methods are hard to trace and almost impossible to reverse."),
        advice="Check any bill by logging in to the official app or website yourself, not through a link in the message.",
    ),
    Category(
        id="threat",
        label="Threatens consequences",
        severity="medium", weight=20,
        patterns=(
            r"\b(?:account|card|service|access|parcel|package)\s(?:\w+\s){0,3}(?:will\sbe\s|has\sbeen\s|is\s)?"
            r"(?:clos|suspend|lock|block|terminat|deactivat|froz|freez|restrict|disabl|cancell?|return)\w*\b",
            r"\bor\s(?:\w+\s){0,3}will\sbe\s(?:closed|suspended|locked|blocked|terminated|deactivated|frozen|deleted|"
            r"cancell?ed|returned(?:\sto\ssender)?|destroyed)\b",
            words(r"legal\saction", r"court\saction", r"arrest(?:ed)?", "warrant", "police", r"prosecut(?:e|ed|ion)",
                  "bailiffs?", r"debt\scollect(?:ors?|ion)", r"penalty(?:\scharge)?", "fined", r"(?:a|the)\sfine",
                  r"criminal\sproceedings"),
        ),
        explain=("Threats of account closure, fines or arrest are designed to make you panic so you act before thinking. "
                 "Genuine organisations follow formal processes and don't threaten you by text."),
        advice="Pause. Contact the organisation directly using contact details you already trust.",
    ),
    Category(
        id="urgency",
        label="Creates urgency or time pressure",
        severity="medium", weight=15,
        patterns=(
            words("immediately", r"urgent(?:ly)?", r"act\snow", r"right\snow", "asap", r"as\ssoon\sas\spossible",
                  r"without\sdelay", r"don'?t\sdelay", r"last\schance", r"final\s(?:notice|warning|reminder|attempt)",
                  r"expires?\s(?:today|tonight|soon)", r"today\sonly", r"time\s(?:is\s)?running\sout"),
            r"\bwithin\s(?:the\snext\s)?(?:\d+|one|two|twenty[\s-]four)\s?(?:h(?:ou)?rs?|minutes?|mins?|days?)\b",
            r"\b(?:by|before)\s(?:midnight|end\sof\s(?:the\s)?day|today|tonight)\b",
        ),
        explain="Short deadlines stop you checking whether a message is genuine. Scammers rely on that rush.",
        advice="Any real deadline will survive a few minutes of checking. Slow down.",
    ),
    Category(
        id="secrecy",
        label="Asks you to keep it secret",
        severity="medium", weight=15,
        patterns=(
            r"\b(?:don'?t|do\snot|never)\s(?:tell|inform|contact|call|speak\sto)\s(?:anyone|anybody|your\sbank|the\sbank|"
            r"family|staff|mum|mom|dad|your\s(?:mum|mom|dad|parents|partner|husband|wife|family|branch|bank\sbranch))\b",
            words(r"keep\s(?:this|it)\s(?:secret|private|confidential|between\sus)", r"strictly\sconfidential"),
        ),
        explain="Being told not to talk to your bank or family is a strong warning sign. It stops anyone spotting the scam.",
        advice="Talk to someone you trust before acting on this message.",
    ),
    Category(
        id="family_impersonation",
        label="Claims to be a family member on a new number",
        severity="medium", weight=20,
        patterns=(
            r"\b(?:hi|hey|hello)\s(?:mum|mom|mummy|dad|daddy|mam|grandma|nan|nana)\b",
            words(r"(?:this\sis\smy|it'?s\smy|i\shave\sa|got\sa)\snew\s(?:number|phone)",
                  r"(?:lost|broke|dropped|smashed)\smy\sphone", r"old\sphone\s(?:is\s)?(?:broken|lost)",
                  r"can'?t\s(?:access|log\sinto)\smy\s(?:bank|banking|account)"),
        ),
        explain='The "Hi Mum/Dad" scam: someone claims to be your child on a new number, then asks for urgent money.',
        advice="Call your family member on their known, old number before sending anything.",
    ),
    Category(
        id="reward",
        label="Promises prizes, refunds or money",
        severity="medium", weight=15,
        patterns=(
            words(r"(?:you'?ve|you\shave)\s(?:won|been\sselected|been\schosen)", "winner", "prize", "lottery", "jackpot",
                  r"claim\s(?:your|now)", r"free\s(?:gift|iphone|money)", r"(?:tax\s)?refund", "rebate",
                  "compensation", "cashback", r"eligible\sfor"),
        ),
        explain=('Unexpected prizes and refunds are bait. They usually lead to a form asking for card details '
                 'or a small "release fee".'),
        advice="You can't win a competition you didn't enter. Check refunds through the official website.",
    ),
    Category(
        id="brand",
        label="Mentions an organisation scammers often copy",
        severity="low", weight=10,
        patterns=(
            words("hmrc", "dvla", "nhs", r"royal\smail", "evri", "hermes", "dpd", "dhl", "fedex", "parcelforce",
                  "paypal", "amazon", "netflix", r"apple\sid", "icloud", "microsoft", "whatsapp", "instagram",
                  "barclays", "hsbc", "lloyds", "natwest", "santander", "halifax", "nationwide", "monzo", "revolut",
                  "starling", "tsb", r"your\sbank", r"tv\slicen[cs]e", "ee", "vodafone", "o2", r"virgin\smedia"),
        ),
        explain=("Scammers borrow trusted names to look official. A brand name alone proves nothing. "
                 "It only matters alongside other warning signs."),
        advice="Don't trust the sender name or logo. Check through the organisation's own app or website.",
    ),
    Category(
        id="link",
        label="Contains a link",
        severity="info", weight=5,
        patterns=(
            r"\bhttps?://[^\s<>\"']+",
            r"\bwww\.[^\s<>\"']+",
            # Bare domains. The lookbehind means a match can only start at the beginning of a
            # dotted name, never part-way through one, which keeps this linear on input like
            # "a.a.a.a..." instead of quadratic (ReDoS).
            r"(?<![a-z0-9.\-])(?:[a-z0-9-]+\.)+"
            r"(?:com|co\.uk|uk|org|net|info|xyz|top|live|online|site|app|link|click|ly|io|me|cc|ru|cn)\b"
            r"(?:/[^\s<>\"']*)?",
        ),
        explain=("The message contains a link. Links are how most phishing messages steal details, "
                 "and the visible text often hides the real destination."),
        advice="Don't tap it. Use the Link Inspector to see the real domain without opening it.",
    ),
)


@dataclass(frozen=True)
class Combo:
    ids: tuple[str, ...]
    bonus: int
    reason: str


# Extra points when tactics appear together. Combinations are far more telling than single words.
COMBOS: tuple[Combo, ...] = (
    Combo(("credentials", "urgency"), 15, "Asks for a code or password under time pressure"),
    Combo(("credentials", "brand"), 10, "Uses a trusted name to ask for credentials"),
    Combo(("payment", "threat"), 15, "Demands payment with a threat attached"),
    Combo(("payment", "link"), 10, "Asks for payment through a link"),
    Combo(("family_impersonation", "payment"), 20, '"New number" contact asking for money'),
    Combo(("secrecy", "payment"), 15, "Asks for payment and secrecy"),
    Combo(("reward", "link"), 10, "Prize or refund offered through a link"),
    Combo(("remote_access", "brand"), 10, "Claims to be a company and asks for remote access"),
    Combo(("remote_access", "payment"), 15, "Wants remote access and a payment or transfer"),
)
