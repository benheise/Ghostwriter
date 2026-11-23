"""Download and parse the CISA KEV catalog and FIRST EPSS scores."""

# Standard Libraries
import csv
import gzip
import io
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation

# 3rd Party Libraries
import requests

# Ghostwriter Libraries
from ghostwriter.reporting.validators import CVE_ID_PATTERN

# A real catalog has well over a thousand entries and a real scores file has hundreds of thousands
# of rows, so anything much smaller is a truncated download or a changed format, not real data.
MIN_KEV_ENTRIES = 1000
MIN_EPSS_ROWS = 100000

GZIP_MAGIC = b"\x1f\x8b"
USER_AGENT = "Ghostwriter vulnerability intelligence (+https://github.com/benheise/Ghostwriter)"
EPSS_HEADER = re.compile(r"model_version:(?P<model>[^,\s]+).*?score_date:(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})")


class FeedError(Exception):
    """A feed could not be downloaded or did not look like real data."""


@dataclass
class KevCatalog:
    version: str
    released_at: datetime | None
    entries: list[dict] = field(default_factory=list)
    skipped: int = 0


@dataclass
class EpssScores:
    model_version: str
    score_date: date
    total_rows: int
    scores: dict[str, tuple[float, float]] = field(default_factory=dict)


def download(url, timeout, max_bytes):
    """
    Return the body of ``url`` as bytes.

    TLS certificates are verified and the proxy settings in the environment are honoured. Raises
    ``FeedError`` if the request fails, a redirect leaves HTTPS, or the body is larger than ``max_bytes``.
    """
    try:
        with requests.get(url, timeout=timeout, stream=True, headers={"User-Agent": USER_AGENT}) as response:
            if not response.url.lower().startswith("https://"):
                raise FeedError(f"{url} redirected to a non-HTTPS address")
            response.raise_for_status()
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise FeedError(f"{url} is larger than the {max_bytes // (1024 * 1024)} MB limit")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise FeedError(f"{url} is larger than the {max_bytes // (1024 * 1024)} MB limit")
            return bytes(body)
    except requests.RequestException as exception:
        raise FeedError(f"Could not download {url}: {exception}") from exception


def _parse_date(value):
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _parse_datetime(value):
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    # Python wants at most six digits of fractional seconds
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_kev(data):
    """Parse CISA's KEV catalog (JSON) and return a ``KevCatalog``. Raises ``FeedError`` if it looks wrong."""
    try:
        document = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exception:
        raise FeedError(f"The KEV catalog is not valid JSON: {exception}") from exception
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise FeedError("The KEV catalog has no list of vulnerabilities")

    catalog = KevCatalog(
        version=str(document.get("catalogVersion") or "")[:64],
        released_at=_parse_datetime(document.get("dateReleased")),
    )
    seen = set()
    for item in document["vulnerabilities"]:
        cve_id = str(item.get("cveID", "")).strip().upper() if isinstance(item, dict) else ""
        if not CVE_ID_PATTERN.match(cve_id) or cve_id in seen:
            catalog.skipped += 1
            continue
        seen.add(cve_id)
        cwes = item.get("cwes")
        catalog.entries.append(
            {
                "cve_id": cve_id,
                "vendor": str(item.get("vendorProject") or "")[:255],
                "product": str(item.get("product") or "")[:255],
                "name": str(item.get("vulnerabilityName") or "")[:500],
                "date_added": _parse_date(item.get("dateAdded")),
                "due_date": _parse_date(item.get("dueDate")),
                "known_ransomware": str(item.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
                "short_description": str(item.get("shortDescription") or ""),
                "required_action": str(item.get("requiredAction") or ""),
                "notes": str(item.get("notes") or ""),
                "cwes": [str(cwe) for cwe in cwes] if isinstance(cwes, list) else [],
            }
        )

    if len(catalog.entries) < MIN_KEV_ENTRIES:
        raise FeedError(
            f"The KEV catalog has only {len(catalog.entries)} usable entries; "
            f"expected at least {MIN_KEV_ENTRIES}, so it is probably truncated"
        )
    return catalog


def _score(value):
    """Return a score between 0 and 1 rounded to five places, as FIRST publishes them, or None."""
    try:
        number = Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        return None
    if not number.is_finite() or number < 0 or number > 1:
        return None
    return float(number.quantize(Decimal("0.00001")))


def parse_epss(data, wanted=None, max_bytes=None):
    """
    Parse FIRST's daily EPSS file (CSV, optionally gzipped) and return an ``EpssScores``.

    Only the CVE IDs in ``wanted`` are kept, when it is given; every row still counts towards the
    sanity check. ``max_bytes`` limits the decompressed size. Raises ``FeedError`` if it looks wrong.
    """
    if data[:2] == GZIP_MAGIC:
        stream = gzip.GzipFile(fileobj=io.BytesIO(data))
    else:
        stream = io.BytesIO(data)
    text = io.TextIOWrapper(stream, encoding="utf-8", errors="replace", newline="")

    read = 0

    def lines():
        nonlocal read
        try:
            for line in text:
                read += len(line)
                if max_bytes and read > max_bytes:
                    raise FeedError(
                        f"The decompressed EPSS file is larger than the {max_bytes // (1024 * 1024)} MB limit"
                    )
                yield line
        except (OSError, EOFError) as exception:
            raise FeedError(f"The EPSS file could not be decompressed: {exception}") from exception

    rows = lines()
    first = next(rows, "")
    match = EPSS_HEADER.search(first) if first.startswith("#") else None
    if not match:
        raise FeedError("The EPSS file does not start with its model version and score date")
    header = next(rows, "").strip().lower()
    if header.replace(" ", "") != "cve,epss,percentile":
        raise FeedError("The EPSS file does not have the columns cve, epss and percentile")

    result = EpssScores(
        model_version=match.group("model")[:64],
        score_date=date.fromisoformat(match.group("date")),
        total_rows=0,
    )
    for record in csv.reader(rows):
        if len(record) < 3:
            continue
        result.total_rows += 1
        cve_id = record[0].strip().upper()
        if wanted is not None and cve_id not in wanted:
            continue
        epss, percentile = _score(record[1]), _score(record[2])
        if CVE_ID_PATTERN.match(cve_id) and epss is not None and percentile is not None:
            result.scores[cve_id] = (epss, percentile)

    if result.total_rows < MIN_EPSS_ROWS:
        raise FeedError(
            f"The EPSS file has only {result.total_rows} rows; "
            f"expected at least {MIN_EPSS_ROWS}, so it is probably truncated"
        )
    return result


def parse_epss_api(data):
    """
    Parse a response from FIRST's EPSS API and return ``{cve_id: (epss, percentile, score_date)}``.
    Raises ``FeedError`` if the response is not a successful API answer.
    """
    try:
        document = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exception:
        raise FeedError(f"The EPSS API answer is not valid JSON: {exception}") from exception
    if not isinstance(document, dict) or str(document.get("status", "")).upper() != "OK":
        raise FeedError("The EPSS API did not answer OK")
    scores = {}
    for item in document.get("data") or []:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cve", "")).strip().upper()
        epss, percentile = _score(item.get("epss")), _score(item.get("percentile"))
        score_date = _parse_date(item.get("date"))
        if CVE_ID_PATTERN.match(cve_id) and epss is not None and percentile is not None and score_date:
            scores[cve_id] = (epss, percentile, score_date)
    return scores
