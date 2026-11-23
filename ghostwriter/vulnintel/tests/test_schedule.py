"""Tests for keeping the refresh schedule in step with the configuration, and for the lookup signal."""

# Standard Libraries
from datetime import datetime, time, timedelta
from datetime import timezone as dt_timezone
from unittest import mock

# Django Imports
from django.core.cache import cache
from django.test import TestCase, override_settings

# 3rd Party Libraries
from django_q.models import Schedule

# Ghostwriter Libraries
from ghostwriter.factories import FindingFactory, ReportFindingLinkFactory
from ghostwriter.home.django_q_policy import validate_schedule
from ghostwriter.vulnintel.models import EpssScore, VulnIntelConfiguration
from ghostwriter.vulnintel.schedule import SCHEDULE_NAME, first_run, get_refresh_schedule, sync_schedule
from ghostwriter.vulnintel.tasks import LOOKUP_TASK, REFRESH_TASK

UTC = dt_timezone.utc
NOW = datetime(2026, 11, 22, 15, 0, tzinfo=UTC)


def configure(**fields):
    config = VulnIntelConfiguration.get_solo()
    for name, value in fields.items():
        setattr(config, name, value)
    config.save()
    return config


class FirstRunTests(TestCase):
    def test_daily_runs_at_the_next_run_time(self):
        self.assertEqual(first_run(NOW, time(14, 0), timedelta(days=1)), datetime(2026, 11, 23, 14, 0, tzinfo=UTC))
        self.assertEqual(first_run(NOW, time(16, 30), timedelta(days=1)), datetime(2026, 11, 22, 16, 30, tzinfo=UTC))

    def test_intervals_follow_the_run_time_grid(self):
        self.assertEqual(first_run(NOW, time(14, 0), timedelta(hours=6)), datetime(2026, 11, 22, 20, 0, tzinfo=UTC))
        self.assertEqual(first_run(NOW, time(2, 0), timedelta(hours=12)), datetime(2026, 11, 23, 2, 0, tzinfo=UTC))

    def test_accepts_other_time_zones(self):
        eastern = dt_timezone(timedelta(hours=-5))
        self.assertEqual(
            first_run(datetime(2026, 11, 22, 10, 0, tzinfo=eastern), time(14, 0), timedelta(days=1)),
            datetime(2026, 11, 22, 14, 0, tzinfo=UTC) + timedelta(days=1),
        )


class SyncScheduleTests(TestCase):
    def test_no_schedule_until_a_source_is_enabled(self):
        configure()
        self.assertIsNone(get_refresh_schedule())

    def test_saving_settings_creates_a_valid_daily_schedule(self):
        configure(enable_kev=True, run_at=time(14, 0))
        schedule = get_refresh_schedule()
        self.assertEqual(schedule.name, SCHEDULE_NAME)
        self.assertEqual(schedule.func, REFRESH_TASK)
        self.assertEqual(schedule.schedule_type, Schedule.DAILY)
        self.assertEqual(schedule.repeats, -1)
        self.assertEqual(schedule.next_run.astimezone(UTC).time(), time(14, 0))
        # The server's Django Q policy accepts it
        validate_schedule(schedule)

    def test_frequencies(self):
        expected = {
            VulnIntelConfiguration.FREQUENCY_6_HOURS: (Schedule.MINUTES, 360),
            VulnIntelConfiguration.FREQUENCY_12_HOURS: (Schedule.MINUTES, 720),
            VulnIntelConfiguration.FREQUENCY_DAILY: (Schedule.DAILY, None),
            VulnIntelConfiguration.FREQUENCY_WEEKLY: (Schedule.WEEKLY, None),
        }
        for frequency, (schedule_type, minutes) in expected.items():
            with self.subTest(frequency=frequency):
                configure(enable_epss=True, update_frequency=frequency)
                schedule = get_refresh_schedule()
                self.assertEqual((schedule.schedule_type, schedule.minutes), (schedule_type, minutes))
        self.assertEqual(Schedule.objects.filter(func=REFRESH_TASK).count(), 1)

    def test_disabling_removes_the_schedule(self):
        configure(enable_kev=True)
        configure(update_frequency=VulnIntelConfiguration.FREQUENCY_DISABLED)
        self.assertIsNone(get_refresh_schedule())
        configure(update_frequency=VulnIntelConfiguration.FREQUENCY_DAILY)
        self.assertIsNotNone(get_refresh_schedule())
        configure(enable_kev=False)
        self.assertIsNone(get_refresh_schedule())

    def test_status_updates_leave_the_schedule_alone(self):
        config = configure(enable_kev=True)
        schedule = get_refresh_schedule()
        Schedule.objects.filter(pk=schedule.pk).update(minutes=99)
        config.kev_count = 5
        config.save(update_fields=["kev_count"])
        self.assertEqual(get_refresh_schedule().minutes, 99)

    def test_restores_and_deduplicates(self):
        config = configure(enable_kev=True)
        Schedule.objects.filter(func=REFRESH_TASK).delete()
        self.assertIsNotNone(sync_schedule(config, now=NOW))
        Schedule.objects.create(func=REFRESH_TASK, name="Duplicate", schedule_type=Schedule.HOURLY)
        sync_schedule(config, now=NOW)
        self.assertEqual(Schedule.objects.filter(func=REFRESH_TASK).count(), 1)
        self.assertEqual(get_refresh_schedule().next_run, datetime(2026, 11, 23, 14, 0, tzinfo=UTC))

    def test_no_schedule_when_the_policy_omits_the_task(self):
        configure(enable_kev=True)
        with override_settings(GHOSTWRITER_DJANGO_Q_SCHEDULE_TASKS={}):
            self.assertIsNone(sync_schedule())
        self.assertIsNone(get_refresh_schedule())


@mock.patch("ghostwriter.vulnintel.signals.async_task")
class LookupSignalTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_queues_lookup_for_unscored_cves(self, async_task):
        configure(enable_epss=True)
        EpssScore.objects.create(cve_id="CVE-2014-0160", epss="0.5", percentile="0.5", score_date="2026-11-01")
        with self.captureOnCommitCallbacks(execute=True):
            FindingFactory(cves=["CVE-2021-44228", "CVE-2014-0160"])
        async_task.assert_called_once_with(LOOKUP_TASK, ["CVE-2021-44228"])

    def test_report_findings_queue_lookups_too(self, async_task):
        configure(enable_epss=True)
        with self.captureOnCommitCallbacks(execute=True):
            ReportFindingLinkFactory(cves=["CVE-2023-4966"])
        async_task.assert_called_once_with(LOOKUP_TASK, ["CVE-2023-4966"])

    def test_no_lookup_when_disabled_or_nothing_new(self, async_task):
        configure(enable_epss=False)
        with self.captureOnCommitCallbacks(execute=True):
            FindingFactory(cves=["CVE-2021-44228"])
        configure(enable_epss=True)
        EpssScore.objects.create(cve_id="CVE-2021-44228", epss="0.9", percentile="0.9", score_date="2026-11-01")
        with self.captureOnCommitCallbacks(execute=True):
            FindingFactory(cves=["CVE-2021-44228"])
            FindingFactory()
        async_task.assert_not_called()

    def test_repeated_saves_queue_one_lookup(self, async_task):
        configure(enable_epss=True)
        finding = FindingFactory()
        for _ in range(3):
            finding.cves = ["CVE-2021-44228"]
            with self.captureOnCommitCallbacks(execute=True):
                finding.save()
        async_task.assert_called_once_with(LOOKUP_TASK, ["CVE-2021-44228"])

    def test_queue_failure_does_not_break_the_save(self, async_task):
        configure(enable_epss=True)
        async_task.side_effect = ConnectionError("broker unavailable")
        with self.captureOnCommitCallbacks(execute=True):
            finding = FindingFactory(cves=["CVE-2021-44228"])
        finding.refresh_from_db()
        self.assertEqual(finding.cves, ["CVE-2021-44228"])
        # The failed CVE ID can be queued again by the next save
        async_task.side_effect = None
        with self.captureOnCommitCallbacks(execute=True):
            finding.save()
        self.assertEqual(async_task.call_count, 3)
