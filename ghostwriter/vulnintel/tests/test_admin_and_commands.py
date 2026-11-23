"""Tests for the configuration page, the read-only lists, and the management commands."""

# Standard Libraries
import tempfile
from datetime import date
from io import StringIO
from pathlib import Path
from unittest import mock

# Django Imports
from django.core.management import CommandError, call_command
from django.test import TestCase
from django.urls import reverse

# Ghostwriter Libraries
from ghostwriter.factories import AdminFactory, FindingFactory, MgrFactory
from ghostwriter.vulnintel import feeds
from ghostwriter.vulnintel.models import EpssScore, KnownExploitedVulnerability, VulnIntelConfiguration
from ghostwriter.vulnintel.tasks import REFRESH_TASK
from ghostwriter.vulnintel.tests.fixtures import epss_document, kev_document, kev_entry

PASSWORD = "SuperNaturalReporting!"


class ConfigurationAdminTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin_user = AdminFactory(password=PASSWORD)
        cls.manager = MgrFactory(password=PASSWORD)
        cls.change_url = reverse("admin:vulnintel_vulnintelconfiguration_change")
        cls.refresh_url = reverse("admin:vulnintel_vulnintelconfiguration_refresh")

    def setUp(self):
        self.client.login(username=self.admin_user.username, password=PASSWORD)

    def test_page_shows_settings_status_and_refresh_button(self):
        response = self.client.get(self.change_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Download the CISA KEV Catalog")
        self.assertContains(response, "Next Refresh")
        self.assertContains(response, "Not scheduled")
        self.assertContains(response, self.refresh_url)

    def test_saving_settings_schedules_the_refresh(self):
        response = self.client.post(
            self.change_url,
            {
                "enable_kev": "on",
                "update_frequency": VulnIntelConfiguration.FREQUENCY_12_HOURS,
                "run_at": "14:00:00",
                "kev_feed_url": "https://mirror.example.com/kev.json",
                "epss_feed_url": "https://mirror.example.com/epss.csv.gz",
                "epss_api_url": "https://api.first.org/data/v1/epss",
                "request_timeout": 60,
                "max_download_mb": 100,
            },
        )
        self.assertEqual(response.status_code, 302)
        response = self.client.get(self.change_url)
        self.assertContains(response, " UTC")
        self.assertNotContains(response, "Not scheduled")

    def test_rejects_plain_http_feeds(self):
        response = self.client.post(
            self.change_url,
            {
                "update_frequency": VulnIntelConfiguration.FREQUENCY_DAILY,
                "run_at": "14:00:00",
                "kev_feed_url": "http://mirror.example.com/kev.json",
                "epss_feed_url": "https://mirror.example.com/epss.csv.gz",
                "epss_api_url": "https://api.first.org/data/v1/epss",
                "request_timeout": 60,
                "max_download_mb": 100,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Use an https:// URL")

    @mock.patch("ghostwriter.vulnintel.admin.async_task")
    def test_refresh_queues_the_task(self, async_task):
        config = VulnIntelConfiguration.get_solo()
        config.enable_epss = True
        config.save()
        response = self.client.post(self.refresh_url, follow=True)
        async_task.assert_called_once_with(REFRESH_TASK)
        self.assertContains(response, "Refresh queued")

    @mock.patch("ghostwriter.vulnintel.admin.async_task")
    def test_refresh_needs_an_enabled_source_and_a_post(self, async_task):
        response = self.client.post(self.refresh_url, follow=True)
        self.assertContains(response, "Enable at least one source")
        self.assertEqual(self.client.get(self.refresh_url).status_code, 405)
        async_task.assert_not_called()

    @mock.patch("ghostwriter.vulnintel.admin.async_task")
    def test_refresh_is_admin_only(self, async_task):
        self.client.logout()
        self.client.login(username=self.manager.username, password=PASSWORD)
        response = self.client.post(self.refresh_url)
        self.assertNotEqual(response.status_code, 200)
        async_task.assert_not_called()

    def test_kev_and_epss_lists_are_read_only(self):
        KnownExploitedVulnerability.objects.create(cve_id="CVE-2021-44228", vendor="Apache", product="Log4j")
        EpssScore.objects.create(cve_id="CVE-2021-44228", epss="0.9", percentile="0.9", score_date=date(2026, 11, 1))
        for name in ("knownexploitedvulnerability", "epssscore"):
            response = self.client.get(reverse(f"admin:vulnintel_{name}_changelist"))
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, "CVE-2021-44228")
            self.assertEqual(self.client.get(reverse(f"admin:vulnintel_{name}_add")).status_code, 403)


@mock.patch.object(feeds, "MIN_KEV_ENTRIES", 2)
@mock.patch.object(feeds, "MIN_EPSS_ROWS", 1)
class CommandTests(TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def write(self, name, data):
        path = Path(self.directory.name) / name
        path.write_bytes(data)
        return str(path)

    def test_import_kev(self):
        path = self.write("kev.json", kev_document([kev_entry("CVE-2021-44228"), kev_entry("CVE-2014-0160")]))
        out = StringIO()
        call_command("import_kev", path, stdout=out)
        self.assertIn("2 entries, 2 new", out.getvalue())
        self.assertEqual(KnownExploitedVulnerability.objects.count(), 2)

    def test_import_kev_rejects_bad_files(self):
        with self.assertRaisesMessage(CommandError, "probably truncated"):
            call_command("import_kev", self.write("kev.json", kev_document([kev_entry("CVE-2021-44228")])))
        with self.assertRaisesMessage(CommandError, "Could not read"):
            call_command("import_kev", str(Path(self.directory.name) / "missing.json"))

    def test_import_epss(self):
        FindingFactory(cves=["CVE-2021-44228"])
        path = self.write(
            "epss.csv.gz", epss_document([("CVE-2021-44228", "0.9", "0.99"), ("CVE-2014-0160", "0.5", "0.9")])
        )
        out = StringIO()
        call_command("import_epss", path, stdout=out)
        self.assertIn("1 scores stored", out.getvalue())
        self.assertEqual(list(EpssScore.objects.values_list("cve_id", flat=True)), ["CVE-2021-44228"])

    def test_import_respects_the_size_limit(self):
        config = VulnIntelConfiguration.get_solo()
        config.max_download_mb = 1
        config.save()
        path = self.write("kev.json", b" " * (1024 * 1024 + 10))
        with self.assertRaisesMessage(CommandError, "larger than the 1 MB limit"):
            call_command("import_kev", path)

    def test_refresh_command(self):
        out = StringIO()
        call_command("refresh_vuln_intel", stdout=out)
        self.assertIn("both disabled", out.getvalue())
        config = VulnIntelConfiguration.get_solo()
        config.enable_kev = True
        config.save()
        with mock.patch("ghostwriter.vulnintel.tasks.download", side_effect=feeds.FeedError("unreachable")):
            with self.assertRaisesMessage(CommandError, "KEV: unreachable"):
                call_command("refresh_vuln_intel")
