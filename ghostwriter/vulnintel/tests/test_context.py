"""Tests for KEV and EPSS data in the report data, the template linter, and pages."""

# Standard Libraries
from datetime import date

# Django Imports
from django.test import TestCase, override_settings
from django.urls import reverse

# Ghostwriter Libraries
from ghostwriter.factories import (
    FindingFactory,
    MgrFactory,
    ReportFactory,
    ReportFindingLinkFactory,
)
from ghostwriter.modules.custom_serializers import ReportDataSerializer
from ghostwriter.modules.linting_utils import LINTER_CONTEXT
from ghostwriter.vulnintel.context import VulnIntelLookup, add_report_vuln_intel
from ghostwriter.vulnintel.models import EpssScore, KnownExploitedVulnerability, VulnIntelConfiguration
from ghostwriter.vulnintel.samples import SAMPLE_FINDING, SAMPLE_REPORT, SAMPLE_TOTALS
from ghostwriter.vulnintel.templatetags.vulnintel_tags import percent

PASSWORD = "SuperNaturalReporting!"


def seed():
    KnownExploitedVulnerability.objects.create(
        cve_id="CVE-2021-44228",
        vendor="Apache",
        product="Log4j2",
        name="Apache Log4j2 Remote Code Execution Vulnerability",
        date_added=date(2021, 12, 10),
        due_date=date(2021, 12, 24),
        known_ransomware=True,
        required_action="Apply updates per vendor instructions.",
        cwes=["CWE-917"],
    )
    KnownExploitedVulnerability.objects.create(
        cve_id="CVE-2021-45046", date_added=date(2023, 5, 1), due_date=date(2023, 5, 22)
    )
    # Removed from the catalog, so it no longer counts
    KnownExploitedVulnerability.objects.create(
        cve_id="CVE-2014-0160", date_added=date(2022, 5, 1), removed_on=date(2026, 1, 1)
    )
    EpssScore.objects.create(cve_id="CVE-2021-44228", epss=0.99999, percentile=1.0, score_date=date(2026, 11, 22))
    EpssScore.objects.create(cve_id="CVE-2021-45046", epss=0.99, percentile=0.998, score_date=date(2026, 11, 22))
    EpssScore.objects.create(cve_id="CVE-2023-0001", epss=0.02, percentile=0.8, score_date=date(2026, 11, 22))


@override_settings(DATE_FORMAT="Y-m-d")
class VulnIntelLookupTests(TestCase):
    def setUp(self):
        seed()

    def test_finding_context(self):
        lookup = VulnIntelLookup(["CVE-2021-45046", "CVE-2021-44228", "CVE-2014-0160", "CVE-2099-0001"], threshold=0.1)
        context = lookup.finding_context(["CVE-2014-0160", "CVE-2021-44228", "CVE-2021-45046", "CVE-2099-0001"])
        self.assertTrue(context["kev"])
        self.assertEqual(context["kev_cves"], ["CVE-2021-44228", "CVE-2021-45046"])
        self.assertTrue(context["kev_ransomware"])
        self.assertEqual(context["kev_due_date"], "2021-12-24")
        self.assertEqual(context["kev_due_date_iso"], "2021-12-24")
        self.assertEqual(context["epss_max"], 0.99999)
        self.assertEqual(context["epss_max_percentile"], 1.0)
        self.assertEqual(context["epss_max_cve"], "CVE-2021-44228")
        self.assertTrue(context["epss_over_threshold"])
        self.assertEqual(
            [entry["cve"] for entry in context["vuln_intel"]],
            ["CVE-2014-0160", "CVE-2021-44228", "CVE-2021-45046", "CVE-2099-0001"],
        )
        heartbleed, log4shell, _, unknown = context["vuln_intel"]
        self.assertIsNone(heartbleed["kev"])
        self.assertEqual(log4shell["kev"]["due_date"], "2021-12-24")
        self.assertEqual(log4shell["kev"]["required_action"], "Apply updates per vendor instructions.")
        self.assertEqual(
            log4shell["epss"],
            {
                "score": 0.99999,
                "percentile": 1.0,
                "score_date": "2026-11-22",
                "score_date_iso": "2026-11-22",
                "model_version": "",
            },
        )
        self.assertEqual(unknown, {"cve": "CVE-2099-0001", "kev": None, "epss": None})

    @override_settings(DATE_FORMAT="d/m/Y")
    def test_iso_dates_whatever_the_display_format(self):
        context = VulnIntelLookup(["CVE-2021-44228"], threshold=0.1).finding_context(["CVE-2021-44228"])
        self.assertEqual(context["kev_due_date"], "24/12/2021")
        self.assertEqual(context["kev_due_date_iso"], "2021-12-24")
        kev = context["vuln_intel"][0]["kev"]
        self.assertEqual((kev["date_added_iso"], kev["due_date_iso"]), ("2021-12-10", "2021-12-24"))
        self.assertEqual(context["vuln_intel"][0]["epss"]["score_date_iso"], "2026-11-22")

    def test_finding_without_data(self):
        context = VulnIntelLookup(["CVE-2023-0001"], threshold=0.1).finding_context(["CVE-2023-0001"])
        self.assertFalse(context["kev"])
        self.assertEqual(context["kev_cves"], [])
        self.assertEqual(context["kev_due_date"], "")
        self.assertEqual(context["epss_max"], 0.02)
        self.assertFalse(context["epss_over_threshold"])
        empty = VulnIntelLookup([], threshold=0.1).finding_context([])
        self.assertIsNone(empty["epss_max"])
        self.assertEqual(empty["vuln_intel"], [])

    def test_threshold_comes_from_the_configuration(self):
        config = VulnIntelConfiguration.get_solo()
        config.epss_threshold = 0.01
        config.save()
        self.assertTrue(VulnIntelLookup(["CVE-2023-0001"]).finding_context(["CVE-2023-0001"])["epss_over_threshold"])


@override_settings(DATE_FORMAT="Y-m-d")
class ReportDataTests(TestCase):
    def setUp(self):
        seed()
        config = VulnIntelConfiguration.get_solo()
        config.kev_catalog_version = "2026.11.20"
        config.epss_score_date = date(2026, 11, 22)
        config.epss_model_version = "v2026.06.15"
        config.save()
        self.report = ReportFactory()
        ReportFindingLinkFactory(report=self.report, cves=["CVE-2021-44228"])
        ReportFindingLinkFactory(report=self.report, cves=["CVE-2023-0001", "CVE-2021-45046"])
        ReportFindingLinkFactory(report=self.report, cves=[])

    def test_serializer_adds_finding_keys_report_keys_and_totals(self):
        data = ReportDataSerializer(self.report, exclude=["id"]).data
        by_cves = {tuple(finding["cves"]): finding for finding in data["findings"]}
        log4shell = by_cves[("CVE-2021-44228",)]
        self.assertTrue(log4shell["kev"])
        self.assertTrue(log4shell["kev_ransomware"])
        mixed = by_cves[("CVE-2021-45046", "CVE-2023-0001")]
        self.assertEqual(mixed["kev_cves"], ["CVE-2021-45046"])
        self.assertEqual(mixed["epss_max_cve"], "CVE-2021-45046")
        self.assertFalse(by_cves[()]["kev"])
        self.assertEqual(
            data["vuln_intel"],
            {
                "cves": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2023-0001"],
                "kev_cves": ["CVE-2021-44228", "CVE-2021-45046"],
                "kev_catalog_version": "2026.11.20",
                "kev_released": "",
                "kev_updated": "",
                "epss_score_date": "2026-11-22",
                "epss_score_date_iso": "2026-11-22",
                "epss_model_version": "v2026.06.15",
                "epss_threshold": 0.1,
            },
        )
        self.assertEqual(data["totals"]["findings_kev"], 2)
        self.assertEqual(data["totals"]["findings_kev_ransomware"], 1)
        self.assertEqual(data["totals"]["findings_epss_over"], 2)
        # The existing totals are untouched
        self.assertEqual(data["totals"]["findings"], 3)

    def test_report_without_findings(self):
        rep = add_report_vuln_intel({"findings": [], "totals": {}})
        self.assertEqual(rep["vuln_intel"]["cves"], [])
        self.assertEqual(rep["totals"]["findings_kev"], 0)


class LinterSampleTests(TestCase):
    """Templates that use the new keys must lint, so the samples must match the real data."""

    def test_samples_have_the_real_keys(self):
        seed()
        lookup = VulnIntelLookup(["CVE-2021-44228"], threshold=0.1)
        real = lookup.finding_context(["CVE-2021-44228"])
        self.assertEqual(set(SAMPLE_FINDING), set(real))
        self.assertEqual(set(SAMPLE_FINDING["vuln_intel"][0]), set(real["vuln_intel"][0]))
        self.assertEqual(set(SAMPLE_FINDING["vuln_intel"][0]["kev"]), set(real["vuln_intel"][0]["kev"]))
        self.assertEqual(set(SAMPLE_FINDING["vuln_intel"][0]["epss"]), set(real["vuln_intel"][0]["epss"]))
        rep = add_report_vuln_intel({"findings": [], "totals": {}})
        self.assertEqual(set(SAMPLE_REPORT), set(rep["vuln_intel"]))
        self.assertEqual(set(SAMPLE_TOTALS), set(rep["totals"]))

    def test_linter_context_includes_the_samples(self):
        self.assertTrue(LINTER_CONTEXT["findings"][0]["kev"])
        self.assertEqual(LINTER_CONTEXT["vuln_intel"]["epss_threshold"], 0.1)
        self.assertEqual(LINTER_CONTEXT["totals"]["findings_kev"], 1)


class PercentFilterTests(TestCase):
    def test_percent(self):
        self.assertEqual(percent(0.97352), "97.4%")
        self.assertEqual(percent(1.0, 0), "100%")
        self.assertEqual(percent(None), "")
        self.assertEqual(percent("bad"), "")


class PageTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = MgrFactory(password=PASSWORD)

    def setUp(self):
        seed()
        self.client.login(username=self.user.username, password=PASSWORD)

    def test_finding_page_shows_kev_and_epss_badges(self):
        finding = FindingFactory(cves=["CVE-2021-44228", "CVE-2023-0001"])
        response = self.client.get(reverse("reporting:finding_detail", kwargs={"pk": finding.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "finding-kev-badge", count=1)
        self.assertContains(response, "known ransomware use")
        self.assertContains(response, "EPSS 100.0%")
        self.assertContains(response, "EPSS 2.0%")
        self.assertContains(response, "EPSS by FIRST.org")

    def test_finding_page_without_cves(self):
        finding = FindingFactory(cves=[])
        response = self.client.get(reverse("reporting:finding_detail", kwargs={"pk": finding.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "finding-kev-badge")
        self.assertNotContains(response, "finding-epss-badge")

    def test_library_list_summarises_each_finding(self):
        FindingFactory(title="Log4Shell finding", cves=["CVE-2021-44228"])
        FindingFactory(title="Low EPSS finding", cves=["CVE-2023-0001"])
        response = self.client.get(reverse("reporting:findings"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "finding-kev-badge")
        self.assertContains(response, "<span>Ransomware</span>")
        self.assertContains(response, "EPSS 2.0%")

    def test_report_findings_table_summarises_each_finding(self):
        report = ReportFactory()
        ReportFindingLinkFactory(report=report, cves=["CVE-2021-45046", "CVE-2023-0001"])
        response = self.client.get(reverse("reporting:report_detail", kwargs={"pk": report.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "finding-kev-badge")
        self.assertContains(response, "EPSS 99.0%")
        self.assertContains(response, "Highest score among this finding")

    def test_one_lookup_serves_every_row(self):
        from ghostwriter.reporting.models import Finding

        for n in range(20):
            FindingFactory(cves=[f"CVE-2023-{n:04d}", "CVE-2021-44228"])
        findings = list(Finding.objects.all())
        # The KEV entries, the EPSS scores, and the configuration, whatever the number of findings
        with self.assertNumQueries(3):
            lookup = VulnIntelLookup.for_findings(findings)
        with self.assertNumQueries(0):
            for finding in findings:
                lookup.finding_context(finding.cve_ids)
