"""Keep the Django Q schedule for the refresh job in step with the configuration."""

# Standard Libraries
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

# Django Imports
from django.db import transaction
from django.utils import timezone

# 3rd Party Libraries
from django_q.models import Schedule

# Ghostwriter Libraries
from ghostwriter.home.django_q_policy import get_schedule_policy
from ghostwriter.vulnintel.models import VulnIntelConfiguration
from ghostwriter.vulnintel.tasks import REFRESH_TASK

SCHEDULE_NAME = "Refresh Vulnerability Intelligence"

# How each frequency maps onto a Django Q schedule: (schedule type, minutes, step to the first run)
FREQUENCIES = {
    VulnIntelConfiguration.FREQUENCY_6_HOURS: (Schedule.MINUTES, 360, timedelta(hours=6)),
    VulnIntelConfiguration.FREQUENCY_12_HOURS: (Schedule.MINUTES, 720, timedelta(hours=12)),
    VulnIntelConfiguration.FREQUENCY_DAILY: (Schedule.DAILY, None, timedelta(days=1)),
    VulnIntelConfiguration.FREQUENCY_WEEKLY: (Schedule.WEEKLY, None, timedelta(days=1)),
}


def first_run(now, run_at, step):
    """Return the first time after ``now`` on the grid that starts at ``run_at`` (UTC) and repeats every ``step``."""
    now = now.astimezone(dt_timezone.utc)
    candidate = datetime.combine(now.date(), run_at, tzinfo=dt_timezone.utc) - timedelta(days=1)
    while candidate <= now:
        candidate += step
    return candidate


def get_refresh_schedule():
    return Schedule.objects.filter(func=REFRESH_TASK).order_by("pk").first()


def sync_schedule(config=None, now=None):
    """
    Create, update, or delete the refresh schedule to match the configuration, and return it (or None).

    The configuration is authoritative: saving it resets the schedule's type, interval, and next run.
    """
    config = config or VulnIntelConfiguration.get_solo()
    timing = FREQUENCIES.get(config.update_frequency)
    with transaction.atomic():
        schedules = Schedule.objects.select_for_update().filter(func=REFRESH_TASK).order_by("pk")
        if timing is None or not config.any_source_enabled or REFRESH_TASK not in get_schedule_policy():
            schedules.delete()
            return None

        schedule_type, minutes, step = timing
        schedule = schedules.first()
        # Duplicates can only come from manual edits in the Django Q admin
        schedules.exclude(pk=getattr(schedule, "pk", None)).delete()
        schedule = schedule or Schedule(func=REFRESH_TASK)
        schedule.name = SCHEDULE_NAME
        schedule.args = None
        schedule.kwargs = None
        schedule.hook = None
        schedule.schedule_type = schedule_type
        schedule.minutes = minutes
        schedule.repeats = -1
        schedule.next_run = first_run(now or timezone.now(), config.run_at, step)
        schedule.save()
        return schedule
