"""Template tags that show KEV and EPSS data next to findings' CVE IDs."""

# Django Imports
from django import template
from django.utils.html import format_html
from django.utils.safestring import mark_safe

# Ghostwriter Libraries
from ghostwriter.vulnintel.context import VulnIntelLookup

register = template.Library()


@register.simple_tag
def vuln_intel_for(findings):
    """
    Return a lookup of KEV entries and EPSS scores for every CVE ID on ``findings``, an iterable of
    library or report findings, so each row can show its badges without more queries.
    """
    return VulnIntelLookup.for_findings(findings)


@register.simple_tag
def finding_cve_lookup(finding):
    """Return a lookup for one finding's CVE IDs."""
    return VulnIntelLookup.for_findings([finding])


@register.filter
def percent(value, digits=1):
    """Format a 0 to 1 score as a percentage, such as 0.97352 as ``97.4%``."""
    try:
        return f"{float(value) * 100:.{int(digits)}f}%"
    except (TypeError, ValueError):
        return ""


def _kev_title(entry, lookup):
    parts = [
        (
            f"In CISA's KEV catalog since {lookup.date_text(entry.date_added)}"
            if entry.date_added
            else "In CISA's KEV catalog"
        )
    ]
    if entry.due_date:
        parts.append(f"remediation due {lookup.date_text(entry.due_date)}")
    if entry.known_ransomware:
        parts.append("known ransomware use")
    return "; ".join(parts)


def _epss_title(score, lookup):
    return (
        f"EPSS {score.epss:.5f} ({percent(score.percentile)} percentile) on {lookup.date_text(score.score_date)}. "
        "EPSS by FIRST.org"
    )


@register.inclusion_tag("vulnintel/snippets/cve_badges.html")
def cve_intel_badges(cves, lookup):
    """Show each CVE ID with its KEV and EPSS badges, for a finding's page."""
    rows = []
    for cve_id in cves:
        entry, score = lookup.kev.get(cve_id), lookup.epss.get(cve_id)
        rows.append(
            {
                "cve": cve_id,
                "kev": entry,
                "kev_title": _kev_title(entry, lookup) if entry else "",
                "epss": score,
                "epss_title": _epss_title(score, lookup) if score else "",
                "epss_high": bool(score and score.epss >= lookup.threshold),
            }
        )
    return {"rows": rows}


@register.simple_tag
def finding_intel_summary(cves, lookup):
    """
    Show one KEV badge and the highest EPSS score for a finding, for compact table rows. Built in
    Python rather than with an included template, because long tables call it once per row. The
    details are in each badge's tooltip.
    """
    facts = lookup.summary(cves)
    kev_entries, top = facts["kev_entries"], facts["top"]
    if not kev_entries and not top:
        return ""
    badges = []
    if kev_entries:
        ransomware = any(entry.known_ransomware for entry in kev_entries)
        title = f"In CISA's KEV catalog: {', '.join(entry.cve_id for entry in kev_entries)}"
        if facts["earliest_due"]:
            title += f"; earliest remediation due {lookup.date_text(facts['earliest_due'])}"
        if ransomware:
            title += "; known ransomware use"
        badges.append(
            format_html(
                '<span class="library-tag library-tag-warning finding-kev-badge" data-bs-toggle="tooltip" '
                'title="{}"><i class="fas fa-exclamation-triangle" aria-hidden="true"></i> <span>{}</span></span>',
                title,
                "KEV · Ransomware" if ransomware else "KEV",
            )
        )
    if top:
        title = f"Highest score among this finding's CVE IDs ({top.cve_id}). {_epss_title(top, lookup)}"
        badges.append(
            format_html(
                '<span class="library-tag {} finding-epss-badge" data-bs-toggle="tooltip" title="{}">'
                "<span>EPSS {}</span></span>",
                "library-tag-warning" if facts["over_threshold"] else "library-tag-neutral",
                title,
                percent(top.epss),
            )
        )
    return format_html('<span class="finding-intel-summary">{}</span>', mark_safe(" ".join(badges)))
