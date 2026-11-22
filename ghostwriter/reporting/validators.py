"""This contains custom validators for the Reporting application."""

# Standard Libraries
import re

# Django Imports
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator

EVIDENCE_ALLOWED_EXTENSIONS = ["txt", "md", "log", "jpg", "jpeg", "png"]

DOCX_ALLOWED_EXTENSIONS = ["docx", "doc", "docm", "dotx", "dotm"]
PPTX_ALLOWED_EXTENSIONS = ["pptx", "ppt", "pptm", "potx", "potm", "ppsx", "ppsm"]
TEMPLATE_ALLOWED_EXTENSIONS = DOCX_ALLOWED_EXTENSIONS + PPTX_ALLOWED_EXTENSIONS


def validate_evidence_extension(value):
    """
    Enforce a limited allowlist for filetypes. Allowed filetypes are limited to
    text and image files that will work for report documents.
    """
    return FileExtensionValidator(allowed_extensions=EVIDENCE_ALLOWED_EXTENSIONS)(value)


# CVE identifiers: the year, then a sequence number of at least four digits (CVE-2021-44228)
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
CVE_ID_SEARCH = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
CVE_ID_SEPARATORS = re.compile(r"[\s,;]+")


def _cve_sort_key(cve_id):
    _, year, number = cve_id.split("-")
    return int(year), int(number)


def normalize_cves(value):
    """
    Return CVE identifiers as a sorted list of unique, upper-case strings.

    Accepts a list of identifiers or a string with identifiers separated by commas,
    semicolons, or whitespace. Raises ``ValueError`` naming the first entry that is not
    a CVE identifier.
    """
    if value in (None, ""):
        return []
    if isinstance(value, str):
        items = CVE_ID_SEPARATORS.split(value)
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        raise ValueError("CVE identifiers must be a list of strings")
    cves = set()
    for item in items:
        if not isinstance(item, str):
            raise ValueError(f"{item!r} is not a CVE identifier")
        cve_id = item.strip().upper()
        if not cve_id:
            continue
        if not CVE_ID_PATTERN.match(cve_id):
            raise ValueError(f"{item.strip()} is not a CVE identifier, such as CVE-2021-44228")
        cves.add(cve_id)
    return sorted(cves, key=_cve_sort_key)


def clean_cves(value):
    """
    Return the valid CVE identifiers in ``value``, normalized, ignoring anything else.

    Used where data may have been written without validation, such as through the
    GraphQL API, so a stray entry never breaks a report.
    """
    if isinstance(value, str):
        value = CVE_ID_SEPARATORS.split(value)
    if not isinstance(value, (list, tuple)):
        return []
    valid = {
        item.strip().upper() for item in value if isinstance(item, str) and CVE_ID_PATTERN.match(item.strip().upper())
    }
    return sorted(valid, key=_cve_sort_key)


def find_cves(text):
    """Return the CVE identifiers mentioned in ``text``, normalized."""
    return clean_cves(CVE_ID_SEARCH.findall(text or ""))


def validate_cve_list(value):
    """Validate a list of CVE identifiers for the ``cves`` field of findings."""
    try:
        normalize_cves(value)
    except ValueError as exception:
        raise ValidationError(str(exception), code="invalid_cve") from exception
