"""This contains all the database models for the Vulnerability Intelligence application."""

# Standard Libraries
from datetime import time

# Django Imports
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

# Ghostwriter Libraries
from ghostwriter.singleton.models import SingletonModel

DEFAULT_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_EPSS_FEED_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
DEFAULT_EPSS_API_URL = "https://api.first.org/data/v1/epss"


def validate_https_url(value):
    """Require feed URLs to use HTTPS, so downloads are always encrypted and verified."""
    if not str(value).lower().startswith("https://"):
        raise ValidationError("Use an https:// URL", code="insecure_url")


class VulnIntelConfiguration(SingletonModel):
    """Settings and run status for downloading the CISA KEV catalog and FIRST EPSS scores."""

    FREQUENCY_DISABLED = "disabled"
    FREQUENCY_6_HOURS = "6h"
    FREQUENCY_12_HOURS = "12h"
    FREQUENCY_DAILY = "daily"
    FREQUENCY_WEEKLY = "weekly"
    FREQUENCY_CHOICES = [
        (FREQUENCY_DISABLED, "Disabled (refresh manually)"),
        (FREQUENCY_6_HOURS, "Every 6 hours"),
        (FREQUENCY_12_HOURS, "Every 12 hours"),
        (FREQUENCY_DAILY, "Daily"),
        (FREQUENCY_WEEKLY, "Weekly"),
    ]

    # Fields the refresh job writes; saving only these does not touch the schedule
    STATUS_FIELDS = frozenset(
        {
            "last_run_at",
            "last_error",
            "kev_synced_at",
            "kev_catalog_version",
            "kev_released_at",
            "kev_count",
            "epss_synced_at",
            "epss_score_date",
            "epss_model_version",
            "epss_count",
        }
    )

    enable_kev = models.BooleanField(
        "Download the CISA KEV Catalog",
        default=False,
        help_text="Keep a local copy of CISA's Known Exploited Vulnerabilities catalog",
    )
    enable_epss = models.BooleanField(
        "Download EPSS Scores",
        default=False,
        help_text="Keep FIRST's EPSS scores for the CVE IDs your findings reference",
    )
    update_frequency = models.CharField(
        "Update Frequency",
        max_length=16,
        choices=FREQUENCY_CHOICES,
        default=FREQUENCY_DAILY,
        help_text="How often to refresh the enabled sources. EPSS publishes new scores once a day",
    )
    run_at = models.TimeField(
        "Run Time (UTC)",
        default=time(14, 0),
        help_text=(
            "Time of day, in UTC, for daily and weekly refreshes, and the starting point for 6- and 12-hour "
            "refreshes. FIRST publishes each day's EPSS scores at about 13:30 UTC"
        ),
    )
    kev_feed_url = models.URLField(
        "KEV Feed URL",
        max_length=500,
        default=DEFAULT_KEV_FEED_URL,
        validators=[validate_https_url],
        help_text="CISA's KEV catalog in JSON, or an internal mirror of it",
    )
    epss_feed_url = models.URLField(
        "EPSS Feed URL",
        max_length=500,
        default=DEFAULT_EPSS_FEED_URL,
        validators=[validate_https_url],
        help_text="FIRST's daily EPSS scores file (CSV, optionally gzipped), or an internal mirror of it",
    )
    epss_api_url = models.URLField(
        "EPSS API URL",
        max_length=500,
        default=DEFAULT_EPSS_API_URL,
        validators=[validate_https_url],
        help_text="FIRST's EPSS API, used only to look up scores for CVE IDs newly added to findings",
    )
    request_timeout = models.PositiveIntegerField(
        "Request Timeout (Seconds)",
        default=60,
        validators=[MinValueValidator(5), MaxValueValidator(600)],
        help_text="Give up on a download that takes longer than this",
    )
    max_download_mb = models.PositiveIntegerField(
        "Maximum Download Size (MB)",
        default=100,
        validators=[MinValueValidator(1), MaxValueValidator(1024)],
        help_text="Refuse a download, or a decompressed file, larger than this",
    )

    last_run_at = models.DateTimeField("Last Run", null=True, blank=True, editable=False)
    last_error = models.TextField("Last Errors", blank=True, default="", editable=False)
    kev_synced_at = models.DateTimeField("KEV Last Updated", null=True, blank=True, editable=False)
    kev_catalog_version = models.CharField("KEV Catalog Version", max_length=64, blank=True, default="", editable=False)
    kev_released_at = models.DateTimeField("KEV Catalog Released", null=True, blank=True, editable=False)
    kev_count = models.PositiveIntegerField("KEV Entries", default=0, editable=False)
    epss_synced_at = models.DateTimeField("EPSS Last Updated", null=True, blank=True, editable=False)
    epss_score_date = models.DateField("EPSS Score Date", null=True, blank=True, editable=False)
    epss_model_version = models.CharField("EPSS Model Version", max_length=64, blank=True, default="", editable=False)
    epss_count = models.PositiveIntegerField("EPSS Scores Stored", default=0, editable=False)

    def __str__(self):
        return "Vulnerability Intelligence Configuration"

    class Meta:
        verbose_name = "Vulnerability Intelligence Configuration"

    @property
    def any_source_enabled(self):
        return self.enable_kev or self.enable_epss

    @property
    def max_download_bytes(self):
        return self.max_download_mb * 1024 * 1024


class KnownExploitedVulnerability(models.Model):
    """An entry in CISA's Known Exploited Vulnerabilities catalog."""

    cve_id = models.CharField("CVE ID", max_length=32, unique=True)
    vendor = models.CharField("Vendor or Project", max_length=255, blank=True, default="")
    product = models.CharField(max_length=255, blank=True, default="")
    name = models.CharField("Vulnerability Name", max_length=500, blank=True, default="")
    date_added = models.DateField("Date Added", null=True, blank=True)
    due_date = models.DateField("Due Date", null=True, blank=True)
    known_ransomware = models.BooleanField(
        "Known Ransomware Use",
        default=False,
        help_text="CISA knows of this vulnerability being used in ransomware campaigns",
    )
    short_description = models.TextField("Short Description", blank=True, default="")
    required_action = models.TextField("Required Action", blank=True, default="")
    notes = models.TextField(blank=True, default="")
    cwes = models.JSONField("CWEs", default=list, blank=True)
    removed_on = models.DateField(
        "Removed On",
        null=True,
        blank=True,
        help_text="The date this entry was no longer in CISA's catalog, which can happen when CISA corrects it",
    )
    updated_at = models.DateTimeField("Updated", auto_now=True)

    class Meta:
        ordering = ["-date_added", "cve_id"]
        verbose_name = "Known exploited vulnerability"
        verbose_name_plural = "Known exploited vulnerabilities"

    def __str__(self):
        return self.cve_id


class EpssScore(models.Model):
    """FIRST's Exploit Prediction Scoring System score for one CVE."""

    cve_id = models.CharField("CVE ID", max_length=32, unique=True)
    epss = models.FloatField(
        "EPSS Score",
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text="Probability of exploitation activity in the next 30 days, from 0 to 1",
    )
    percentile = models.FloatField(
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text="Share of all scored CVEs with an equal or lower score, from 0 to 1",
    )
    score_date = models.DateField("Score Date")
    model_version = models.CharField("Model Version", max_length=64, blank=True, default="")
    updated_at = models.DateTimeField("Updated", auto_now=True)

    class Meta:
        ordering = ["-epss", "cve_id"]
        verbose_name = "EPSS score"
        verbose_name_plural = "EPSS scores"

    def __str__(self):
        return f"{self.cve_id}: {self.epss}"
