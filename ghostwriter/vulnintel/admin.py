"""This contains customizations for displaying the Vulnerability Intelligence models in the admin panel."""

# Django Imports
from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseNotAllowed, HttpResponseRedirect
from django.urls import re_path, reverse

# 3rd Party Libraries
from django_q.tasks import async_task

# Ghostwriter Libraries
from ghostwriter.singleton.admin import SingletonModelAdmin
from ghostwriter.vulnintel.models import EpssScore, KnownExploitedVulnerability, VulnIntelConfiguration
from ghostwriter.vulnintel.schedule import get_refresh_schedule
from ghostwriter.vulnintel.tasks import REFRESH_TASK

STATUS_FIELDS = (
    "schedule_status",
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
)


@admin.register(VulnIntelConfiguration)
class VulnIntelConfigurationAdmin(SingletonModelAdmin):
    change_form_template = "vulnintel/admin_change_form.html"
    readonly_fields = STATUS_FIELDS
    fieldsets = (
        (
            "Sources",
            {
                "description": (
                    "Ghostwriter makes no requests to these sources until you enable one. KEV data comes "
                    "from CISA. EPSS scores come from FIRST (first.org/epss); credit FIRST wherever you "
                    "show them."
                ),
                "fields": ("enable_kev", "enable_epss"),
            },
        ),
        (
            "Schedule",
            {
                "description": (
                    "Saving this page sets the refresh schedule. Edits made to that schedule in the "
                    "Django Q admin are replaced the next time this page is saved."
                ),
                "fields": ("update_frequency", "run_at", "schedule_status"),
            },
        ),
        (
            "Feeds and Limits",
            {
                "description": "Change the URLs only to point at an internal mirror of the same data.",
                "classes": ("collapse",),
                "fields": ("kev_feed_url", "epss_feed_url", "epss_api_url", "request_timeout", "max_download_mb"),
            },
        ),
        (
            "Status",
            {
                "fields": (
                    "last_run_at",
                    "last_error",
                    ("kev_synced_at", "kev_catalog_version", "kev_released_at", "kev_count"),
                    ("epss_synced_at", "epss_score_date", "epss_model_version", "epss_count"),
                )
            },
        ),
    )

    @admin.display(description="Next Refresh")
    def schedule_status(self, obj):
        schedule = get_refresh_schedule()
        if schedule is None:
            if obj.any_source_enabled and obj.update_frequency != VulnIntelConfiguration.FREQUENCY_DISABLED:
                return "No schedule found. Save this page to restore it."
            return "Not scheduled"
        if schedule.next_run is None:
            return "Scheduled, with no next run set"
        return f"{schedule.next_run:%Y-%m-%d %H:%M} UTC"

    def get_urls(self):
        info = (self.model._meta.app_label, self.model._meta.model_name)
        return [
            re_path(
                r"^refresh/$",
                self.admin_site.admin_view(self.refresh_view),
                name="%s_%s_refresh" % info,
            ),
        ] + super().get_urls()

    def refresh_view(self, request):
        """Queue a refresh of the enabled sources now."""
        if request.method != "POST":
            return HttpResponseNotAllowed(["POST"])
        if not self.has_change_permission(request):
            raise PermissionDenied
        change_url = reverse("admin:vulnintel_vulnintelconfiguration_change")
        config = VulnIntelConfiguration.get_solo()
        if not config.any_source_enabled:
            self.message_user(request, "Enable at least one source before refreshing.", messages.WARNING)
            return HttpResponseRedirect(change_url)
        try:
            async_task(REFRESH_TASK)
        except Exception as exception:  # pylint: disable=broad-exception-caught
            self.message_user(request, f"Could not queue the refresh: {exception}", messages.ERROR)
        else:
            self.message_user(
                request,
                "Refresh queued. Reload this page in a minute to see the result under Status.",
                messages.SUCCESS,
            )
        return HttpResponseRedirect(change_url)


class ReadOnlyAdmin(admin.ModelAdmin):
    """The refresh job owns these tables, so the admin only shows them."""

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(KnownExploitedVulnerability)
class KnownExploitedVulnerabilityAdmin(ReadOnlyAdmin):
    list_display = ("cve_id", "vendor", "product", "date_added", "due_date", "known_ransomware", "removed_on")
    list_filter = ("known_ransomware", ("removed_on", admin.EmptyFieldListFilter), "date_added")
    search_fields = ("cve_id", "vendor", "product", "name")
    date_hierarchy = "date_added"


@admin.register(EpssScore)
class EpssScoreAdmin(ReadOnlyAdmin):
    list_display = ("cve_id", "epss", "percentile", "score_date", "model_version")
    list_filter = ("score_date",)
    search_fields = ("cve_id",)
