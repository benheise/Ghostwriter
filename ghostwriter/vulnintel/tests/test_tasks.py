"""Tests for the jobs that refresh the KEV catalog and EPSS scores."""

# Standard Libraries
from datetime import date, datetime, timezone
from unittest import mock

# Django Imports
from django.test import TestCase

# Ghostwriter Libraries
from ghostwriter.factories import FindingFactory, ReportFindingLinkFactory
from ghostwriter.vulnintel import feeds
from ghostwriter.vulnintel.feeds import FeedError
from ghostwriter.vulnintel.models import EpssScore, KnownExploitedVulnerability, VulnIntelConfiguration
from ghostwriter.vulnintel.tasks import (
    lookup_epss_scores,
    referenced_cves,
    refresh_epss,
    refresh_kev,
    refresh_vulnerability_intel,
)
from ghostwriter.vulnintel.tests.fixtures import epss_api_document, epss_document, kev_document, kev_entry

DOWNLOAD = "ghostwriter.vulnintel.tasks.download"


def configure(**fields):
    config = VulnIntelConfiguration.get_solo()
    for name, value in fields.items():
        setattr(config, name, value)
    config.save()
    return config


@mock.patch.object(feeds, "MIN_KEV_ENTRIES", 2)
class RefreshKevTests(TestCase):
    def test_stores_catalog_and_status(self):
        config = configure(enable_kev=True)
        summary = refresh_kev(
            config,
            kev_document([kev_entry("CVE-2021-44228", knownRansomwareCampaignUse="Known"), kev_entry("CVE-2014-0160")]),
        )
        self.assertIn("2 entries, 2 new, 0 removed", summary)
        log4shell = KnownExploitedVulnerability.objects.get(cve_id="CVE-2021-44228")
        self.assertTrue(log4shell.known_ransomware)
        self.assertEqual(log4shell.due_date, date(2026, 11, 22))
        config.refresh_from_db()
        self.assertEqual(config.kev_catalog_version, "2026.11.20")
        self.assertEqual(config.kev_count, 2)
        self.assertIsNotNone(config.kev_synced_at)

    def test_updates_entries_and_marks_removed_ones(self):
        config = configure(enable_kev=True)
        refresh_kev(config, kev_document([kev_entry("CVE-2021-44228"), kev_entry("CVE-2014-0160")]))
        summary = refresh_kev(
            config,
            kev_document(
                [kev_entry("CVE-2021-44228", dueDate="2026-12-01"), kev_entry("CVE-2023-4966")],
                version="2026.11.21",
                released="2026-11-21T10:00:00Z",
            ),
        )
        self.assertIn("2 entries, 1 new, 1 removed", summary)
        self.assertEqual(KnownExploitedVulnerability.objects.get(cve_id="CVE-2021-44228").due_date, date(2026, 12, 1))
        removed = KnownExploitedVulnerability.objects.get(cve_id="CVE-2014-0160")
        self.assertIsNotNone(removed.removed_on)

        # An entry CISA restores loses its removal date
        refresh_kev(
            config,
            kev_document(
                [kev_entry("CVE-2021-44228"), kev_entry("CVE-2014-0160")],
                version="2026.11.22",
                released="2026-11-22T10:00:00Z",
            ),
        )
        removed.refresh_from_db()
        self.assertIsNone(removed.removed_on)

    def test_refuses_older_catalog(self):
        config = configure(enable_kev=True)
        refresh_kev(config, kev_document([kev_entry("CVE-2021-44228"), kev_entry("CVE-2014-0160")]))
        with self.assertRaisesMessage(FeedError, "older than the stored copy"):
            refresh_kev(
                config,
                kev_document([kev_entry("CVE-2023-4966"), kev_entry("CVE-2014-0160")], released="2026-01-01T00:00:00Z"),
            )
        self.assertFalse(KnownExploitedVulnerability.objects.filter(cve_id="CVE-2023-4966").exists())

    def test_bad_download_keeps_stored_data(self):
        config = configure(enable_kev=True)
        refresh_kev(config, kev_document([kev_entry("CVE-2021-44228"), kev_entry("CVE-2014-0160")]))
        with self.assertRaises(FeedError):
            refresh_kev(config, kev_document([kev_entry("CVE-2023-4966")]))
        self.assertEqual(KnownExploitedVulnerability.objects.filter(removed_on__isnull=True).count(), 2)

    @mock.patch(DOWNLOAD)
    def test_downloads_from_configured_feed(self, download):
        download.return_value = kev_document([kev_entry("CVE-2021-44228"), kev_entry("CVE-2014-0160")])
        config = configure(enable_kev=True, kev_feed_url="https://mirror.example.com/kev.json", request_timeout=30)
        refresh_kev(config)
        download.assert_called_once_with("https://mirror.example.com/kev.json", 30, config.max_download_bytes)


@mock.patch.object(feeds, "MIN_EPSS_ROWS", 3)
class RefreshEpssTests(TestCase):
    rows = [
        ("CVE-1999-0001", "0.04753", "0.92097"),
        ("CVE-2014-0160", "0.99999", "0.99997"),
        ("CVE-2021-44228", "0.99999", "1.00000"),
    ]

    def setUp(self):
        FindingFactory(cves=["CVE-2021-44228", "CVE-2099-0001"])
        ReportFindingLinkFactory(cves=["CVE-2014-0160"])

    def test_referenced_cves(self):
        self.assertEqual(referenced_cves(), {"CVE-2021-44228", "CVE-2099-0001", "CVE-2014-0160"})

    def test_stores_scores_for_referenced_cves_only(self):
        config = configure(enable_epss=True)
        summary = refresh_epss(config, epss_document(self.rows))
        self.assertIn("2 scores stored, 1 CVE IDs not in the file", summary)
        self.assertEqual(set(EpssScore.objects.values_list("cve_id", flat=True)), {"CVE-2021-44228", "CVE-2014-0160"})
        score = EpssScore.objects.get(cve_id="CVE-2021-44228")
        self.assertEqual(score.epss, 0.99999)
        self.assertEqual(score.score_date, date(2026, 11, 22))
        self.assertEqual(score.model_version, "v2026.06.15")
        config.refresh_from_db()
        self.assertEqual(config.epss_score_date, date(2026, 11, 22))
        self.assertEqual(config.epss_count, 2)

    def test_drops_scores_no_finding_references(self):
        config = configure(enable_epss=True)
        EpssScore.objects.create(cve_id="CVE-2010-0001", epss="0.1", percentile="0.5", score_date=date(2026, 11, 1))
        summary = refresh_epss(config, epss_document(self.rows))
        self.assertIn("1 no longer referenced", summary)
        self.assertFalse(EpssScore.objects.filter(cve_id="CVE-2010-0001").exists())

    def test_refuses_older_scores(self):
        config = configure(enable_epss=True)
        refresh_epss(config, epss_document(self.rows, score_date="2026-11-22"))
        with self.assertRaisesMessage(FeedError, "older than the stored ones"):
            refresh_epss(config, epss_document([(c, "0.1", "0.1") for c, _, _ in self.rows], score_date="2026-11-01"))
        self.assertEqual(EpssScore.objects.get(cve_id="CVE-2021-44228").epss, 0.99999)

    @mock.patch(DOWNLOAD)
    def test_skips_download_when_no_cves_are_referenced(self, download):
        from ghostwriter.reporting.models import Finding, ReportFindingLink

        Finding.objects.update(cves=[])
        ReportFindingLink.objects.update(cves=[])
        config = configure(enable_epss=True)
        self.assertIn("nothing was downloaded", refresh_epss(config))
        download.assert_not_called()


@mock.patch.object(feeds, "MIN_KEV_ENTRIES", 2)
@mock.patch.object(feeds, "MIN_EPSS_ROWS", 1)
class RefreshVulnerabilityIntelTests(TestCase):
    def setUp(self):
        FindingFactory(cves=["CVE-2021-44228"])

    @mock.patch(DOWNLOAD)
    def test_does_nothing_when_disabled(self, download):
        configure(enable_kev=False, enable_epss=False)
        self.assertIn("both disabled", refresh_vulnerability_intel())
        download.assert_not_called()

    @mock.patch(DOWNLOAD)
    def test_refreshes_enabled_sources(self, download):
        kev = kev_document([kev_entry("CVE-2021-44228"), kev_entry("CVE-2014-0160")])
        epss = epss_document([("CVE-2021-44228", "0.9", "0.99")])
        download.side_effect = lambda url, *args: kev if "known_exploited" in url else epss
        configure(enable_kev=True, enable_epss=True)
        summary = refresh_vulnerability_intel()
        self.assertIn("KEV 2026.11.20", summary)
        self.assertIn("EPSS 2026-11-22", summary)
        config = VulnIntelConfiguration.objects.get()
        self.assertEqual(config.last_error, "")
        self.assertIsNotNone(config.last_run_at)

    @mock.patch(DOWNLOAD)
    def test_one_failing_source_does_not_stop_the_other(self, download):
        epss = epss_document([("CVE-2021-44228", "0.9", "0.99")])

        def fake(url, *args):
            if "known_exploited" in url:
                raise FeedError("Could not download the KEV catalog")
            return epss

        download.side_effect = fake
        configure(enable_kev=True, enable_epss=True)
        summary = refresh_vulnerability_intel()
        self.assertIn("EPSS 2026-11-22", summary)
        self.assertIn("KEV: Could not download", summary)
        self.assertTrue(EpssScore.objects.filter(cve_id="CVE-2021-44228").exists())
        self.assertIn("KEV: Could not download", VulnIntelConfiguration.objects.get().last_error)

    @mock.patch(DOWNLOAD)
    def test_fails_the_task_when_every_source_fails(self, download):
        download.side_effect = FeedError("unreachable")
        configure(enable_kev=True, enable_epss=False)
        with self.assertRaisesMessage(RuntimeError, "KEV: unreachable"):
            refresh_vulnerability_intel()
        self.assertEqual(VulnIntelConfiguration.objects.get().last_error, "KEV: unreachable")

    @mock.patch(DOWNLOAD)
    def test_status_writes_keep_settings_saved_meanwhile(self, download):
        download.return_value = kev_document([kev_entry("CVE-2021-44228"), kev_entry("CVE-2014-0160")])
        config = configure(enable_kev=True)
        # An admin changes a setting while the refresh holds an older copy of the configuration
        VulnIntelConfiguration.objects.filter(pk=config.pk).update(request_timeout=120)
        with mock.patch.object(VulnIntelConfiguration, "get_solo", return_value=config):
            refresh_vulnerability_intel()
        self.assertEqual(VulnIntelConfiguration.objects.get().request_timeout, 120)


class LookupEpssScoresTests(TestCase):
    @mock.patch(DOWNLOAD)
    def test_does_nothing_when_disabled(self, download):
        configure(enable_epss=False)
        self.assertEqual(lookup_epss_scores(["CVE-2021-44228"]), "EPSS is disabled")
        download.assert_not_called()

    @mock.patch(DOWNLOAD)
    def test_looks_up_only_unscored_cves(self, download):
        configure(enable_epss=True, epss_api_url="https://api.example.com/epss")
        EpssScore.objects.create(cve_id="CVE-2014-0160", epss="0.5", percentile="0.5", score_date=date(2026, 11, 1))
        download.return_value = epss_api_document([("CVE-2021-44228", "0.99999", "1.0", "2026-11-22")])
        summary = lookup_epss_scores(["cve-2021-44228", "CVE-2014-0160", "Log4Shell"])
        self.assertEqual(summary, "EPSS lookup: 1 of 1 CVE IDs scored")
        url = download.call_args[0][0]
        self.assertTrue(url.startswith("https://api.example.com/epss?cve="))
        self.assertIn("CVE-2021-44228", url)
        self.assertNotIn("CVE-2014-0160", url)
        self.assertEqual(EpssScore.objects.get(cve_id="CVE-2014-0160").epss, 0.5)
        self.assertEqual(EpssScore.objects.get(cve_id="CVE-2021-44228").score_date, date(2026, 11, 22))

    @mock.patch("ghostwriter.vulnintel.tasks.EPSS_API_BATCH", 2)
    @mock.patch(DOWNLOAD)
    def test_batches_requests(self, download):
        configure(enable_epss=True)
        download.return_value = epss_api_document([])
        lookup_epss_scores([f"CVE-2020-{n:04d}" for n in range(1, 6)])
        self.assertEqual(download.call_count, 3)

    @mock.patch(DOWNLOAD)
    def test_nothing_to_do(self, download):
        configure(enable_epss=True)
        EpssScore.objects.create(cve_id="CVE-2014-0160", epss="0.5", percentile="0.5", score_date=date(2026, 11, 1))
        self.assertEqual(lookup_epss_scores(["CVE-2014-0160"]), "Every CVE ID already has a score")
        download.assert_not_called()


class StatusDatesTests(TestCase):
    @mock.patch.object(feeds, "MIN_KEV_ENTRIES", 2)
    def test_catalog_release_time_is_stored_in_utc(self):
        config = configure(enable_kev=True)
        refresh_kev(config, kev_document([kev_entry("CVE-2021-44228"), kev_entry("CVE-2014-0160")]))
        config.refresh_from_db()
        self.assertEqual(config.kev_released_at, datetime(2026, 11, 20, 17, 48, 39, 151600, tzinfo=timezone.utc))
