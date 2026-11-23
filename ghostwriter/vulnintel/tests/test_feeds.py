"""Tests for downloading and parsing the KEV and EPSS feeds."""

# Standard Libraries
from datetime import date, datetime, timezone
from unittest import mock

# Django Imports
from django.test import SimpleTestCase

# 3rd Party Libraries
import requests

# Ghostwriter Libraries
from ghostwriter.vulnintel import feeds
from ghostwriter.vulnintel.feeds import FeedError, download, parse_epss, parse_epss_api, parse_kev
from ghostwriter.vulnintel.tests.fixtures import epss_api_document, epss_document, kev_document, kev_entry


class FakeResponse:
    def __init__(self, body=b"", url="https://example.com/feed", headers=None, status=200):
        self.body = body
        self.url = url
        self.headers = headers or {}
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def raise_for_status(self):
        if self.status >= 400:
            raise requests.HTTPError(f"{self.status} Error")

    def iter_content(self, chunk_size=1):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start : start + chunk_size]


@mock.patch.object(feeds, "MIN_KEV_ENTRIES", 2)
class ParseKevTests(SimpleTestCase):
    def test_parses_entries(self):
        catalog = parse_kev(
            kev_document(
                [
                    kev_entry("CVE-2021-44228", knownRansomwareCampaignUse="Known"),
                    kev_entry("cve-2014-0160", dueDate=""),
                ]
            )
        )
        self.assertEqual(catalog.version, "2026.11.20")
        self.assertEqual(catalog.released_at, datetime(2026, 11, 20, 17, 48, 39, 151600, tzinfo=timezone.utc))
        self.assertEqual([entry["cve_id"] for entry in catalog.entries], ["CVE-2021-44228", "CVE-2014-0160"])
        log4shell, heartbleed = catalog.entries
        self.assertTrue(log4shell["known_ransomware"])
        self.assertFalse(heartbleed["known_ransomware"])
        self.assertEqual(log4shell["date_added"], date(2026, 11, 1))
        self.assertEqual(log4shell["due_date"], date(2026, 11, 22))
        self.assertIsNone(heartbleed["due_date"])
        self.assertEqual(log4shell["cwes"], ["CWE-502"])
        self.assertEqual(log4shell["vendor"], "Example Vendor")

    def test_skips_malformed_and_duplicate_entries(self):
        catalog = parse_kev(
            kev_document(
                [
                    kev_entry("CVE-2021-44228"),
                    kev_entry("CVE-2021-44228"),
                    kev_entry("Log4Shell"),
                    "not an object",
                    kev_entry("CVE-2014-0160", cwes="CWE-119"),
                ]
            )
        )
        self.assertEqual(len(catalog.entries), 2)
        self.assertEqual(catalog.skipped, 3)
        self.assertEqual(catalog.entries[1]["cwes"], [])

    def test_rejects_truncated_catalog(self):
        with self.assertRaisesMessage(FeedError, "probably truncated"):
            parse_kev(kev_document([kev_entry("CVE-2021-44228")]))

    def test_rejects_other_documents(self):
        for data in (b"<html>maintenance</html>", b'{"vulnerabilities": "none"}', b"[]"):
            with self.assertRaises(FeedError):
                parse_kev(data)

    def test_tolerates_missing_release_date(self):
        catalog = parse_kev(
            kev_document([kev_entry("CVE-2021-44228"), kev_entry("CVE-2014-0160")], released="not a date")
        )
        self.assertIsNone(catalog.released_at)


@mock.patch.object(feeds, "MIN_EPSS_ROWS", 3)
class ParseEpssTests(SimpleTestCase):
    rows = [
        ("CVE-1999-0001", "0.04753", "0.92097"),
        ("CVE-2014-0160", "0.99999", "0.99997"),
        ("CVE-2021-44228", "0.999990000", "1.000000000"),
    ]

    def test_parses_gzipped_file(self):
        scores = parse_epss(epss_document(self.rows))
        self.assertEqual(scores.model_version, "v2026.06.15")
        self.assertEqual(scores.score_date, date(2026, 11, 22))
        self.assertEqual(scores.total_rows, 3)
        self.assertEqual(scores.scores["CVE-2021-44228"], (0.99999, 1.0))

    def test_parses_plain_file(self):
        self.assertEqual(len(parse_epss(epss_document(self.rows, compress=False)).scores), 3)

    def test_keeps_only_wanted_cves_but_counts_every_row(self):
        scores = parse_epss(epss_document(self.rows), wanted={"CVE-2014-0160", "CVE-2099-0001"})
        self.assertEqual(list(scores.scores), ["CVE-2014-0160"])
        self.assertEqual(scores.total_rows, 3)

    def test_ignores_rows_with_bad_scores(self):
        rows = self.rows + [("CVE-2020-0001", "1.5", "0.5"), ("CVE-2020-0002", "NaN", "0.5"), ("bad", "0.1", "0.1")]
        scores = parse_epss(epss_document(rows))
        self.assertNotIn("CVE-2020-0001", scores.scores)
        self.assertNotIn("CVE-2020-0002", scores.scores)
        self.assertEqual(scores.total_rows, 6)

    def test_rejects_truncated_file(self):
        with self.assertRaisesMessage(FeedError, "probably truncated"):
            parse_epss(epss_document(self.rows[:2]))

    def test_rejects_missing_header_lines(self):
        with self.assertRaisesMessage(FeedError, "model version and score date"):
            parse_epss(b"cve,epss,percentile\nCVE-2021-44228,0.9,0.9\n")
        with self.assertRaisesMessage(FeedError, "columns"):
            parse_epss(b"#model_version:v1,score_date:2026-11-22T00:00:00Z\ncve,score\n")

    def test_rejects_corrupt_gzip(self):
        with self.assertRaises(FeedError):
            parse_epss(epss_document(self.rows)[:40])

    def test_limits_decompressed_size(self):
        rows = [(f"CVE-2020-{n:05d}", "0.1", "0.5") for n in range(5000)]
        with self.assertRaisesMessage(FeedError, "larger than"):
            parse_epss(epss_document(rows), max_bytes=1024 * 1024 // 16)


class ParseEpssApiTests(SimpleTestCase):
    def test_parses_scores(self):
        scores = parse_epss_api(
            epss_api_document(
                [
                    ("CVE-2021-44228", "0.999990000", "1.000000000", "2026-11-22"),
                    ("CVE-2014-0160", "bad", "0.9", "2026-11-22"),
                ]
            )
        )
        self.assertEqual(scores, {"CVE-2021-44228": (0.99999, 1.0, date(2026, 11, 22))})

    def test_rejects_errors(self):
        for data in (epss_api_document([], status="ERROR"), b"not json"):
            with self.assertRaises(FeedError):
                parse_epss_api(data)


class DownloadTests(SimpleTestCase):
    @mock.patch("ghostwriter.vulnintel.feeds.requests.get")
    def test_returns_body_with_verified_tls(self, get):
        get.return_value = FakeResponse(b"payload")
        self.assertEqual(download("https://example.com/feed", 30, 1024), b"payload")
        _, kwargs = get.call_args
        self.assertEqual(kwargs["timeout"], 30)
        self.assertTrue(kwargs["stream"])
        self.assertNotIn("verify", kwargs)

    @mock.patch("ghostwriter.vulnintel.feeds.requests.get")
    def test_refuses_large_downloads(self, get):
        get.return_value = FakeResponse(b"x" * 2048)
        with self.assertRaisesMessage(FeedError, "larger than"):
            download("https://example.com/feed", 30, 1024)
        get.return_value = FakeResponse(b"", headers={"Content-Length": "999999"})
        with self.assertRaisesMessage(FeedError, "larger than"):
            download("https://example.com/feed", 30, 1024)

    @mock.patch("ghostwriter.vulnintel.feeds.requests.get")
    def test_refuses_redirect_away_from_https(self, get):
        get.return_value = FakeResponse(b"payload", url="http://example.com/feed")
        with self.assertRaisesMessage(FeedError, "non-HTTPS"):
            download("https://example.com/feed", 30, 1024)

    @mock.patch("ghostwriter.vulnintel.feeds.requests.get")
    def test_wraps_request_errors(self, get):
        get.side_effect = requests.ConnectionError("unreachable")
        with self.assertRaisesMessage(FeedError, "Could not download"):
            download("https://example.com/feed", 30, 1024)
        get.side_effect = None
        get.return_value = FakeResponse(status=503)
        with self.assertRaisesMessage(FeedError, "503"):
            download("https://example.com/feed", 30, 1024)
