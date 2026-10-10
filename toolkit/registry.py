"""Module registry: the single source of truth for the dashboard.

To add a module:
  1. Create its package in toolkit/modules/<package_name>/ with a Flask Blueprint called `bp`
     (copy toolkit/modules/link_inspector/ as a starting point).
  2. Create its page template in toolkit/templates/modules/<package_name>.html.
  3. Change its `status` below from "planned" to "live".

The app registers live modules automatically, and the dashboard cards, progress bar
and navigation update on their own. `pytest` checks every live module is wired up.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Module:
    number: int
    slug: str          # URL path, e.g. /link-inspector
    name: str
    summary: str
    example: str
    status: str = "planned"  # "planned" or "live"

    @property
    def package(self) -> str:
        """Python package name, e.g. link_inspector."""
        return self.slug.replace("-", "_")

    @property
    def import_path(self) -> str:
        return f"toolkit.modules.{self.package}"

    @property
    def endpoint(self) -> str:
        """Flask endpoint for the module's main page."""
        return f"{self.package}.index"

    @property
    def template(self) -> str:
        return f"modules/{self.package}.html"

    @property
    def live(self) -> bool:
        return self.status == "live"


MODULES: tuple[Module, ...] = (
    Module(
        1, "message-checker", "Message Checker",
        "Checks pasted text for urgency, payment demands, threats and requests for passwords or OTPs. "
        "Explains each finding.",
        "“Send your OTP immediately or your account will close” → flags the OTP request and the pressure to act.",
        status="live",
    ),
    Module(
        2, "link-inspector", "Link Inspector",
        "Extracts links and shows the real domain. Flags suspicious structures, such as a brand name placed "
        "in a subdomain. Never opens the link.",
        "bank.example.com → explains that the registered domain is example.com.",
        status="live",
    ),
    Module(
        3, "screenshot-reader", "Screenshot Text Reader",
        "Uses OCR to extract text from an image. Lets you correct recognition errors before checking it.",
        "Upload a text-message screenshot → extract its message and links.",
    ),
    Module(
        4, "privacy-detector", "Privacy Detector",
        "Finds email addresses and phone numbers in images, checks for GPS metadata, and lets you mark "
        "other text to hide.",
        "Highlights an email address visible in a delivery screenshot.",
    ),
    Module(
        5, "redaction-export", "Redaction & Export",
        "Select detected details or draw extra boxes. Permanently replaces those pixels and exports an "
        "image with no copied metadata.",
        "Download a screenshot with the phone number covered by a solid box.",
    ),
    Module(
        6, "workspace", "Combined Workspace",
        "Connects every module into one screenshot workflow.",
        "Upload → review extracted text → check warnings → redact → download.",
    ),
)


def get_module(slug: str) -> Module:
    return next(m for m in MODULES if m.slug == slug)


def live_modules() -> list[Module]:
    return [m for m in MODULES if m.live]
