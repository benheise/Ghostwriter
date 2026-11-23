"""Refresh the enabled vulnerability intelligence sources now, without waiting for the schedule."""

# Django Imports
from django.core.management.base import BaseCommand, CommandError

# Ghostwriter Libraries
from ghostwriter.vulnintel.tasks import refresh_vulnerability_intel


class Command(BaseCommand):
    help = "Download and store the KEV catalog and EPSS scores now, for the sources enabled in the configuration."

    def handle(self, *args, **options):
        try:
            summary = refresh_vulnerability_intel()
        except RuntimeError as exception:
            raise CommandError(str(exception)) from exception
        self.stdout.write(summary)
