"""Tests for CVE identifiers on findings."""

# Standard Libraries
from io import StringIO

# Django Imports
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import connection
from django.test import Client, TestCase
from django.urls import reverse

# 3rd Party Libraries
from tablib import Dataset

# Ghostwriter Libraries
from ghostwriter.factories import (
    FindingFactory,
    FindingTypeFactory,
    MgrFactory,
    ReportFactory,
    ReportFindingLinkFactory,
    SeverityFactory,
)
from ghostwriter.modules.custom_serializers import FindingLinkSerializer, FindingSerializer
from ghostwriter.reporting.filters import FindingFilter
from ghostwriter.reporting.models import Finding, ReportFindingLink
from ghostwriter.reporting.resources import FindingResource
from ghostwriter.reporting.validators import (
    clean_cves,
    find_cves,
    normalize_cves,
    validate_cve_list,
)

PASSWORD = "SuperNaturalReporting!"


class CveValidatorTests(TestCase):
    """Collection of tests for the CVE identifier helpers."""

    def test_normalize_cves_sorts_and_removes_duplicates(self):
        self.assertEqual(
            normalize_cves(["cve-2021-44228", "CVE-2014-0160", " CVE-2021-44228 "]),
            ["CVE-2014-0160", "CVE-2021-44228"],
        )

    def test_normalize_cves_sorts_sequence_numbers_numerically(self):
        self.assertEqual(
            normalize_cves(["CVE-2021-10000", "CVE-2021-9999"]),
            ["CVE-2021-9999", "CVE-2021-10000"],
        )

    def test_normalize_cves_accepts_separated_text(self):
        self.assertEqual(
            normalize_cves("CVE-2023-4966, CVE-2021-44228;CVE-2019-19781\nCVE-2023-4966"),
            ["CVE-2019-19781", "CVE-2021-44228", "CVE-2023-4966"],
        )

    def test_normalize_cves_empty_values(self):
        for value in (None, "", [], ["", "  "]):
            self.assertEqual(normalize_cves(value), [])

    def test_normalize_cves_rejects_other_values(self):
        for value in (["CVE-21-44228"], ["CVE-2021-123"], ["GHSA-jfh8-c2jp-5v3q"], [42], {"a": 1}):
            with self.assertRaises(ValueError):
                normalize_cves(value)

    def test_clean_cves_drops_malformed_entries(self):
        self.assertEqual(
            clean_cves(["cve-2021-44228", "not a cve", 7, None, "CVE-2014-0160"]),
            ["CVE-2014-0160", "CVE-2021-44228"],
        )
        self.assertEqual(clean_cves({"cve": "CVE-2021-44228"}), [])
        self.assertEqual(clean_cves(None), [])

    def test_find_cves_in_text(self):
        text = (
            "<p>Log4Shell (cve-2021-44228) and "
            '<a href="https://nvd.nist.gov/vuln/detail/CVE-2014-0160">Heartbleed</a>; '
            "not CVE-21-1 or XCVE-2020-0001X.</p>"
        )
        self.assertEqual(find_cves(text), ["CVE-2014-0160", "CVE-2021-44228"])
        self.assertEqual(find_cves(None), [])

    def test_validate_cve_list(self):
        validate_cve_list(["CVE-2021-44228"])
        with self.assertRaises(ValidationError):
            validate_cve_list(["CVE-2021-44228", "Log4Shell"])


class CveModelTests(TestCase):
    """Collection of tests for the ``cves`` field on findings."""

    def test_save_normalizes_cves(self):
        finding = FindingFactory(cves=["cve-2021-44228", "CVE-2014-0160", "junk"])
        finding.refresh_from_db()
        self.assertEqual(finding.cves, ["CVE-2014-0160", "CVE-2021-44228"])

        rfl = ReportFindingLinkFactory(cves="CVE-2023-4966 cve-2023-4966")
        rfl.refresh_from_db()
        self.assertEqual(rfl.cves, ["CVE-2023-4966"])

    def test_default_is_empty_list(self):
        self.assertEqual(FindingFactory().cves, [])
        self.assertEqual(ReportFindingLinkFactory().cves, [])

    def test_cve_ids_ignores_values_written_without_validation(self):
        finding = FindingFactory()
        # Writes through the GraphQL API skip Django, which ``update()`` imitates
        Finding.objects.filter(pk=finding.pk).update(cves=["cve-2021-44228", {"x": 1}, "nope"])
        finding.refresh_from_db()
        self.assertEqual(finding.cve_ids, ["CVE-2021-44228"])

    def test_full_clean_rejects_invalid_cves(self):
        finding = FindingFactory()
        finding.cves = ["Log4Shell"]
        with self.assertRaises(ValidationError) as context:
            finding.full_clean()
        self.assertIn("cves", context.exception.message_dict)

    def test_database_defaults_to_empty_list(self):
        # Inserts through the GraphQL API that omit the column rely on the database default
        with connection.cursor() as cursor:
            for table in ("reporting_finding", "reporting_reportfindinglink"):
                cursor.execute(
                    "SELECT column_default FROM information_schema.columns "
                    "WHERE table_name = %s AND column_name = 'cves'",
                    [table],
                )
                self.assertEqual(cursor.fetchone()[0], "'[]'::jsonb")


class CveCopyTests(TestCase):
    """Collection of tests for copying CVE identifiers between the library and reports."""

    @classmethod
    def setUpTestData(cls):
        cls.user = MgrFactory(password=PASSWORD)
        cls.report = ReportFactory()

    def setUp(self):
        self.client = Client()
        self.assertTrue(self.client.login(username=self.user.username, password=PASSWORD))

    def test_assign_finding_copies_cves(self):
        finding = FindingFactory(cves=["CVE-2021-44228", "CVE-2014-0160"])
        response = self.client.post(
            reverse("reporting:ajax_assign_finding", kwargs={"pk": finding.pk}),
            data={"report": self.report.pk},
        )
        self.assertEqual(response.status_code, 200)
        rfl = ReportFindingLink.objects.get(report=self.report, title=finding.title)
        self.assertEqual(rfl.cves, ["CVE-2014-0160", "CVE-2021-44228"])

        # The copy is independent of the library finding
        finding.cves = ["CVE-2023-4966"]
        finding.save()
        rfl.refresh_from_db()
        self.assertEqual(rfl.cves, ["CVE-2014-0160", "CVE-2021-44228"])

    def test_convert_finding_copies_cves(self):
        rfl = ReportFindingLinkFactory(report=self.report, cves=["CVE-2019-19781"])
        response = self.client.post(reverse("reporting:convert_finding", kwargs={"pk": rfl.pk}))
        self.assertEqual(response.status_code, 302)
        finding = Finding.objects.get(title=rfl.title)
        self.assertEqual(finding.cves, ["CVE-2019-19781"])


class CveSerializerTests(TestCase):
    """Collection of tests for CVE identifiers in the report data."""

    def test_serializers_return_clean_cves(self):
        rfl = ReportFindingLinkFactory(cves=["CVE-2021-44228"])
        ReportFindingLink.objects.filter(pk=rfl.pk).update(cves=["cve-2014-0160", "bad", "CVE-2021-44228"])
        rfl.refresh_from_db()
        self.assertEqual(FindingLinkSerializer(rfl).data["cves"], ["CVE-2014-0160", "CVE-2021-44228"])

        finding = FindingFactory(cves=["CVE-2023-4966"])
        self.assertEqual(FindingSerializer(finding).data["cves"], ["CVE-2023-4966"])


class CveResourceTests(TestCase):
    """Collection of tests for importing and exporting CVE identifiers."""

    @classmethod
    def setUpTestData(cls):
        cls.severity = SeverityFactory(severity="Critical")
        cls.finding_type = FindingTypeFactory(finding_type="Network")

    def _dataset(self, rows, with_cves=True):
        headers = ["severity", "finding_type", "title", "tags"]
        if with_cves:
            headers.append("cves")
        dataset = Dataset(headers=headers)
        for title, cves in rows:
            row = ["Critical", "Network", title, ""]
            if with_cves:
                row.append(cves)
            dataset.append(row)
        return dataset

    def test_export_writes_comma_separated_cves(self):
        finding = FindingFactory(cves=["CVE-2021-44228", "CVE-2014-0160"])
        dataset = FindingResource().export([finding], export_fields=["id", "cves"])
        self.assertEqual(dataset[0], (str(finding.pk), "CVE-2014-0160, CVE-2021-44228"))

    def test_import_normalizes_cves(self):
        result = FindingResource().import_data(
            self._dataset([("Imported", "cve-2021-44228; CVE-2014-0160")]), dry_run=False
        )
        self.assertFalse(result.has_errors() or result.has_validation_errors())
        self.assertEqual(Finding.objects.get(title="Imported").cves, ["CVE-2014-0160", "CVE-2021-44228"])

    def test_import_rejects_invalid_cves(self):
        result = FindingResource().import_data(self._dataset([("Bad CVE", "Log4Shell")]), dry_run=False)
        self.assertTrue(result.has_errors() or result.has_validation_errors())
        self.assertFalse(Finding.objects.filter(title="Bad CVE").exists())

    def test_import_without_cves_column(self):
        result = FindingResource().import_data(self._dataset([("Older Export", None)], with_cves=False), dry_run=False)
        self.assertFalse(result.has_errors() or result.has_validation_errors())
        self.assertEqual(Finding.objects.get(title="Older Export").cves, [])


class CveFilterTests(TestCase):
    """Collection of tests for searching findings by CVE identifier."""

    @classmethod
    def setUpTestData(cls):
        cls.log4shell = FindingFactory(cves=["CVE-2021-44228"])
        cls.near_miss = FindingFactory(cves=["CVE-2021-4422"])
        cls.heartbleed = FindingFactory(cves=["CVE-2014-0160"])
        cls.none = FindingFactory()

    def _search(self, value):
        return set(FindingFilter({"cve": value}, queryset=Finding.objects.all()).qs)

    def test_full_identifier_matches_exactly(self):
        self.assertEqual(self._search("cve-2021-4422"), {self.near_miss})

    def test_partial_identifier_matches_substring(self):
        self.assertEqual(self._search("2021-4422"), {self.log4shell, self.near_miss})

    def test_several_identifiers_match_any(self):
        self.assertEqual(self._search("CVE-2021-44228, CVE-2014-0160"), {self.log4shell, self.heartbleed})

    def test_report_findings_can_be_filtered(self):
        rfl = ReportFindingLinkFactory(cves=["CVE-2023-4966"])
        ReportFindingLinkFactory()
        qs = FindingFilter({"cve": "CVE-2023-4966"}, queryset=ReportFindingLink.objects.all()).qs
        self.assertEqual(list(qs), [rfl])


class ExtractCvesCommandTests(TestCase):
    """Collection of tests for the ``extract_cves`` management command."""

    @classmethod
    def setUpTestData(cls):
        cls.finding = FindingFactory(
            title="Apache Log4j RCE (CVE-2021-44228)",
            description="<p>See also cve-2021-45046.</p>",
            references='<p><a href="https://nvd.nist.gov/vuln/detail/CVE-2021-44228">NVD</a></p>',
            cves=["CVE-2021-4104"],
        )
        cls.plain = FindingFactory(title="Weak password policy", description="<p>No CVE here.</p>")
        cls.rfl = ReportFindingLinkFactory(title="Citrix Bleed", description="<p>CVE-2023-4966</p>")

    def _run(self, *args):
        out = StringIO()
        call_command("extract_cves", *args, stdout=out)
        return out.getvalue()

    def test_dry_run_changes_nothing(self):
        output = self._run("--dry-run")
        self.assertIn("1 would be updated", output)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.cves, ["CVE-2021-4104"])

    def test_merges_found_cves_with_existing(self):
        self._run()
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.cves, ["CVE-2021-4104", "CVE-2021-44228", "CVE-2021-45046"])
        self.plain.refresh_from_db()
        self.assertEqual(self.plain.cves, [])
        self.rfl.refresh_from_db()
        self.assertEqual(self.rfl.cves, ["CVE-2023-4966"])

        # A second run has nothing left to change
        self.assertIn("0 updated", self._run())

    def test_library_only(self):
        self._run("--library-only")
        self.rfl.refresh_from_db()
        self.assertEqual(self.rfl.cves, [])
        self.finding.refresh_from_db()
        self.assertIn("CVE-2021-44228", self.finding.cves)

    def test_reports_only(self):
        self._run("--reports-only")
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.cves, ["CVE-2021-4104"])
        self.rfl.refresh_from_db()
        self.assertEqual(self.rfl.cves, ["CVE-2023-4966"])
