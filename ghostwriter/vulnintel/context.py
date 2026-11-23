"""KEV and EPSS data for findings, for report templates, the Excel export, and pages."""

# Django Imports
from django.conf import settings
from django.utils import dateformat

# Ghostwriter Libraries
from ghostwriter.reporting.validators import clean_cves
from ghostwriter.vulnintel.models import EpssScore, KnownExploitedVulnerability, VulnIntelConfiguration


def format_date(value):
    """Format a date or datetime the way the rest of the report data does, or return an empty string."""
    return dateformat.format(value, settings.DATE_FORMAT) if value else ""


class VulnIntelLookup:
    """The stored KEV entries and EPSS scores for a set of CVE IDs, fetched with two queries."""

    def __init__(self, cve_ids, threshold=None):
        cve_ids = set(cve_ids)
        self.cve_ids = cve_ids
        # Entries CISA removed from the catalog no longer count as known exploited
        self.kev = {
            entry.cve_id: entry
            for entry in KnownExploitedVulnerability.objects.filter(cve_id__in=cve_ids, removed_on__isnull=True)
        }
        self.epss = {score.cve_id: score for score in EpssScore.objects.filter(cve_id__in=cve_ids)}
        self.threshold = VulnIntelConfiguration.get_solo().epss_threshold if threshold is None else threshold
        self._dates = {}

    def date_text(self, value):
        """``format_date``, cached: long tables show the same few dates many times."""
        if value not in self._dates:
            self._dates[value] = format_date(value)
        return self._dates[value]

    @classmethod
    def for_findings(cls, findings, threshold=None):
        """Build a lookup for every CVE ID on an iterable of finding or report finding objects."""
        cve_ids = set()
        for finding in findings:
            cve_ids.update(clean_cves(finding.cves))
        return cls(cve_ids, threshold=threshold)

    def summary(self, cves):
        """Return the KEV and EPSS facts for a finding with these CVE IDs (see ``finding_context``)."""
        kev_entries = [self.kev[cve_id] for cve_id in cves if cve_id in self.kev]
        scores = [self.epss[cve_id] for cve_id in cves if cve_id in self.epss]
        top = max(scores, key=lambda score: (score.epss, score.cve_id), default=None)
        due_dates = [entry.due_date for entry in kev_entries if entry.due_date]
        return {
            "kev_entries": kev_entries,
            "scores": scores,
            "top": top,
            "earliest_due": min(due_dates, default=None),
            "over_threshold": bool(top and top.epss >= self.threshold),
        }

    def finding_context(self, cves):
        """Return the keys added to each finding in the report data."""
        facts = self.summary(cves)
        top = facts["top"]
        return {
            "vuln_intel": [
                {
                    "cve": cve_id,
                    "kev": kev_context(self.kev.get(cve_id)),
                    "epss": epss_context(self.epss.get(cve_id)),
                }
                for cve_id in cves
            ],
            "kev": bool(facts["kev_entries"]),
            "kev_cves": [entry.cve_id for entry in facts["kev_entries"]],
            "kev_ransomware": any(entry.known_ransomware for entry in facts["kev_entries"]),
            "kev_due_date": format_date(facts["earliest_due"]),
            "epss_max": top.epss if top else None,
            "epss_max_percentile": top.percentile if top else None,
            "epss_max_cve": top.cve_id if top else "",
            "epss_over_threshold": facts["over_threshold"],
        }


def kev_context(entry):
    if entry is None:
        return None
    return {
        "vendor": entry.vendor,
        "product": entry.product,
        "name": entry.name,
        "date_added": format_date(entry.date_added),
        "due_date": format_date(entry.due_date),
        "known_ransomware": entry.known_ransomware,
        "short_description": entry.short_description,
        "required_action": entry.required_action,
        "notes": entry.notes,
        "cwes": list(entry.cwes or []),
    }


def epss_context(score):
    if score is None:
        return None
    return {
        "score": score.epss,
        "percentile": score.percentile,
        "score_date": format_date(score.score_date),
        "model_version": score.model_version,
    }


def add_report_vuln_intel(rep):
    """
    Add KEV and EPSS data to serialized report data: keys on each finding, a report-level
    ``vuln_intel`` with the dates and versions of the stored data, and counts in ``totals``.
    """
    config = VulnIntelConfiguration.get_solo()
    findings = rep.get("findings") or []
    cve_ids = set()
    for finding in findings:
        cve_ids.update(finding.get("cves") or [])
    lookup = VulnIntelLookup(cve_ids, threshold=config.epss_threshold)

    findings_kev = findings_ransomware = findings_epss_over = 0
    for finding in findings:
        finding.update(lookup.finding_context(finding.get("cves") or []))
        findings_kev += finding["kev"]
        findings_ransomware += finding["kev_ransomware"]
        findings_epss_over += finding["epss_over_threshold"]

    rep["vuln_intel"] = {
        "cves": sorted(cve_ids),
        "kev_cves": sorted(lookup.kev),
        "kev_catalog_version": config.kev_catalog_version,
        "kev_released": format_date(config.kev_released_at),
        "kev_updated": format_date(config.kev_synced_at),
        "epss_score_date": format_date(config.epss_score_date),
        "epss_model_version": config.epss_model_version,
        "epss_threshold": config.epss_threshold,
    }
    totals = rep.setdefault("totals", {})
    totals["findings_kev"] = findings_kev
    totals["findings_kev_ransomware"] = findings_ransomware
    totals["findings_epss_over"] = findings_epss_over
    return rep
