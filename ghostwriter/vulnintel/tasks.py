"""Background jobs that keep the local KEV catalog and EPSS scores current."""

# Standard Libraries
import logging
from urllib.parse import urlencode

# Django Imports
from django.db import transaction
from django.utils import timezone

# Ghostwriter Libraries
from ghostwriter.reporting.models import Finding, ReportFindingLink
from ghostwriter.reporting.validators import clean_cves
from ghostwriter.vulnintel.feeds import FeedError, download, parse_epss, parse_epss_api, parse_kev
from ghostwriter.vulnintel.models import EpssScore, KnownExploitedVulnerability, VulnIntelConfiguration

logger = logging.getLogger(__name__)

REFRESH_TASK = "ghostwriter.vulnintel.tasks.refresh_vulnerability_intel"
LOOKUP_TASK = "ghostwriter.vulnintel.tasks.lookup_epss_scores"

# FIRST's API takes a comma-separated list of CVE IDs; keep each request well under its URL limits
EPSS_API_BATCH = 100
# One lookup never asks for more than this many CVE IDs; the next refresh covers the rest
EPSS_LOOKUP_LIMIT = 1000

KEV_FIELDS = [
    "vendor",
    "product",
    "name",
    "date_added",
    "due_date",
    "known_ransomware",
    "short_description",
    "required_action",
    "notes",
    "cwes",
    "removed_on",
    "updated_at",
]
EPSS_FIELDS = ["epss", "percentile", "score_date", "model_version", "updated_at"]


def _save_status(config, **fields):
    """Write run status fields only, so a refresh never overwrites settings saved meanwhile."""
    for name, value in fields.items():
        setattr(config, name, value)
    config.save(update_fields=list(fields))


def referenced_cves():
    """Return the set of valid CVE IDs on any library or report finding."""
    cves = set()
    for model in (Finding, ReportFindingLink):
        for value in model.objects.exclude(cves=[]).values_list("cves", flat=True).iterator():
            cves.update(clean_cves(value))
    return cves


def apply_kev(catalog, config):
    """Store a parsed KEV catalog, mark entries CISA dropped, and record the run. Returns a summary."""
    if config.kev_released_at and catalog.released_at and catalog.released_at < config.kev_released_at:
        raise FeedError(
            f"The KEV catalog ({catalog.released_at:%Y-%m-%d %H:%M} UTC) is older than the stored copy "
            f"({config.kev_released_at:%Y-%m-%d %H:%M} UTC)"
        )
    now = timezone.now()
    feed_ids = {entry["cve_id"] for entry in catalog.entries}
    with transaction.atomic():
        before = set(KnownExploitedVulnerability.objects.values_list("cve_id", flat=True))
        KnownExploitedVulnerability.objects.bulk_create(
            [KnownExploitedVulnerability(removed_on=None, updated_at=now, **entry) for entry in catalog.entries],
            update_conflicts=True,
            unique_fields=["cve_id"],
            update_fields=KEV_FIELDS,
            batch_size=500,
        )
        removed = (
            KnownExploitedVulnerability.objects.filter(removed_on__isnull=True)
            .exclude(cve_id__in=feed_ids)
            .update(removed_on=now.date(), updated_at=now)
        )
    added = len(feed_ids - before)
    _save_status(
        config,
        kev_synced_at=now,
        kev_catalog_version=catalog.version,
        kev_released_at=catalog.released_at,
        kev_count=len(feed_ids),
    )
    return f"KEV {catalog.version or 'catalog'}: {len(feed_ids)} entries, {added} new, {removed} removed"


def apply_epss(scores, config, wanted):
    """
    Store parsed EPSS scores for the CVE IDs in ``wanted``, drop scores no finding references any more,
    and record the run. Returns a summary.
    """
    if config.epss_score_date and scores.score_date < config.epss_score_date:
        raise FeedError(
            f"The EPSS scores ({scores.score_date}) are older than the stored ones ({config.epss_score_date})"
        )
    now = timezone.now()
    with transaction.atomic():
        EpssScore.objects.bulk_create(
            [
                EpssScore(
                    cve_id=cve_id,
                    epss=epss,
                    percentile=percentile,
                    score_date=scores.score_date,
                    model_version=scores.model_version,
                    updated_at=now,
                )
                for cve_id, (epss, percentile) in scores.scores.items()
            ],
            update_conflicts=True,
            unique_fields=["cve_id"],
            update_fields=EPSS_FIELDS,
            batch_size=500,
        )
        pruned, _ = EpssScore.objects.exclude(cve_id__in=wanted).delete()
        stored = EpssScore.objects.count()
    _save_status(
        config,
        epss_synced_at=now,
        epss_score_date=scores.score_date,
        epss_model_version=scores.model_version,
        epss_count=stored,
    )
    missing = len(wanted) - len(scores.scores)
    summary = f"EPSS {scores.score_date} ({scores.model_version}): {len(scores.scores)} scores stored"
    if missing:
        summary += f", {missing} CVE IDs not in the file"
    if pruned:
        summary += f", {pruned} no longer referenced"
    return summary


def refresh_kev(config, data=None):
    """Download (unless ``data`` is given), check, and store the KEV catalog."""
    if data is None:
        data = download(config.kev_feed_url, config.request_timeout, config.max_download_bytes)
    return apply_kev(parse_kev(data), config)


def refresh_epss(config, data=None):
    """Download (unless ``data`` is given), check, and store EPSS scores for the CVE IDs findings reference."""
    wanted = referenced_cves()
    if not wanted and data is None:
        EpssScore.objects.all().delete()
        _save_status(config, epss_count=0)
        return "EPSS: no findings reference CVE IDs, so nothing was downloaded"
    if data is None:
        data = download(config.epss_feed_url, config.request_timeout, config.max_download_bytes)
    scores = parse_epss(data, wanted=wanted, max_bytes=config.max_download_bytes)
    return apply_epss(scores, config, wanted)


def refresh_vulnerability_intel():
    """
    Refresh every enabled source. A failure in one source does not stop the other, and a failed or
    suspicious download never replaces stored data. Returns a summary for the task result.
    """
    config = VulnIntelConfiguration.get_solo()
    if not config.any_source_enabled:
        return "Nothing to refresh: the KEV and EPSS sources are both disabled"

    results, errors = [], []
    for enabled, label, refresh in (
        (config.enable_kev, "KEV", refresh_kev),
        (config.enable_epss, "EPSS", refresh_epss),
    ):
        if not enabled:
            continue
        try:
            results.append(refresh(config))
        except FeedError as exception:
            logger.warning("Vulnerability intelligence refresh failed for %s: %s", label, exception)
            errors.append(f"{label}: {exception}")
        except Exception as exception:  # pylint: disable=broad-exception-caught
            logger.exception("Vulnerability intelligence refresh failed for %s", label)
            errors.append(f"{label}: unexpected error ({exception.__class__.__name__}: {exception})")

    _save_status(config, last_run_at=timezone.now(), last_error="\n".join(errors))
    summary = "; ".join(results + errors)
    if errors and not results:
        raise RuntimeError(summary)
    return summary


def lookup_epss_scores(cve_ids):
    """
    Fetch EPSS scores from FIRST's API for CVE IDs that have none stored yet, so findings show a score
    without waiting for the next refresh. Returns a summary for the task result.
    """
    config = VulnIntelConfiguration.get_solo()
    if not config.enable_epss:
        return "EPSS is disabled"
    wanted = clean_cves(cve_ids)
    known = set(EpssScore.objects.filter(cve_id__in=wanted).values_list("cve_id", flat=True))
    missing = [cve_id for cve_id in wanted if cve_id not in known][:EPSS_LOOKUP_LIMIT]
    if not missing:
        return "Every CVE ID already has a score"

    found = {}
    for start in range(0, len(missing), EPSS_API_BATCH):
        batch = missing[start : start + EPSS_API_BATCH]
        url = f"{config.epss_api_url}?{urlencode({'cve': ','.join(batch)})}"
        found.update(parse_epss_api(download(url, config.request_timeout, config.max_download_bytes)))

    now = timezone.now()
    # ``ignore_conflicts`` keeps a score a concurrent refresh stored from the daily file
    EpssScore.objects.bulk_create(
        [
            EpssScore(
                cve_id=cve_id,
                epss=epss,
                percentile=percentile,
                score_date=score_date,
                model_version=config.epss_model_version,
                updated_at=now,
            )
            for cve_id, (epss, percentile, score_date) in found.items()
        ],
        ignore_conflicts=True,
    )
    _save_status(config, epss_count=EpssScore.objects.count())
    return f"EPSS lookup: {len(found)} of {len(missing)} CVE IDs scored"
