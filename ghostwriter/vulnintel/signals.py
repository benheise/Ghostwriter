"""This contains all the signals used by the Vulnerability Intelligence application."""

# Standard Libraries
import logging

# Django Imports
from django.core.cache import cache
from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

# 3rd Party Libraries
from django_q.tasks import async_task

# Ghostwriter Libraries
from ghostwriter.reporting.models import Finding, ReportFindingLink
from ghostwriter.reporting.validators import clean_cves
from ghostwriter.vulnintel.models import EpssScore, VulnIntelConfiguration
from ghostwriter.vulnintel.schedule import sync_schedule
from ghostwriter.vulnintel.tasks import LOOKUP_TASK

logger = logging.getLogger(__name__)

# Saving a finding several times (as the collaborative editor does) queues one lookup per CVE ID
LOOKUP_CACHE_PREFIX = "vulnintel:epss-lookup:"
LOOKUP_DEDUP_SECONDS = 600


@receiver(post_save, sender=VulnIntelConfiguration)
def sync_refresh_schedule(sender, instance, raw=False, update_fields=None, **kwargs):
    """Match the refresh schedule to the saved settings; run status updates leave it alone."""
    if raw or (update_fields and set(update_fields) <= VulnIntelConfiguration.STATUS_FIELDS):
        return
    sync_schedule(instance)


def queue_epss_lookup(instance):
    """Queue an EPSS API lookup for CVE IDs on a saved finding that have no stored score yet."""
    cves = clean_cves(instance.cves)
    if not cves:
        return
    config = VulnIntelConfiguration.get_solo()
    if not config.enable_epss:
        return
    known = set(EpssScore.objects.filter(cve_id__in=cves).values_list("cve_id", flat=True))
    missing = [cve_id for cve_id in cves if cve_id not in known]
    if not missing:
        return

    def enqueue():
        fresh = [
            cve_id for cve_id in missing if cache.add(f"{LOOKUP_CACHE_PREFIX}{cve_id}", True, LOOKUP_DEDUP_SECONDS)
        ]
        if not fresh:
            return
        try:
            async_task(LOOKUP_TASK, fresh)
        except Exception:  # pylint: disable=broad-exception-caught
            # The next scheduled refresh covers these CVE IDs; never fail the finding's save
            cache.delete_many([f"{LOOKUP_CACHE_PREFIX}{cve_id}" for cve_id in fresh])
            logger.exception("Could not queue an EPSS lookup for %s", ", ".join(fresh))

    transaction.on_commit(enqueue)


@receiver(post_save, sender=Finding)
def lookup_finding_cves(sender, instance, raw=False, **kwargs):
    if not raw:
        queue_epss_lookup(instance)


@receiver(post_save, sender=ReportFindingLink)
def lookup_report_finding_cves(sender, instance, raw=False, **kwargs):
    if not raw:
        queue_epss_lookup(instance)
