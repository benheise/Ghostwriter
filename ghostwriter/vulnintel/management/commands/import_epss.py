"""Load EPSS scores from a file, for servers that cannot reach FIRST."""

# Django Imports
from django.core.management.base import BaseCommand, CommandError

# Ghostwriter Libraries
from ghostwriter.vulnintel.feeds import FeedError
from ghostwriter.vulnintel.models import VulnIntelConfiguration
from ghostwriter.vulnintel.tasks import refresh_epss


class Command(BaseCommand):
    help = (
        "Load EPSS scores from a copy of FIRST's daily file (epss_scores-YYYY-MM-DD.csv or .csv.gz), keeping "
        "the scores for CVE IDs your findings reference. Works whether or not EPSS downloads are enabled."
    )

    def add_arguments(self, parser):
        parser.add_argument("path", help="Path to the EPSS scores file")

    def handle(self, *args, **options):
        config = VulnIntelConfiguration.get_solo()
        try:
            with open(options["path"], "rb") as handle:
                data = handle.read(config.max_download_bytes + 1)
        except OSError as exception:
            raise CommandError(f"Could not read {options['path']}: {exception}") from exception
        if len(data) > config.max_download_bytes:
            raise CommandError(f"{options['path']} is larger than the {config.max_download_mb} MB limit")
        try:
            self.stdout.write(refresh_epss(config, data=data))
        except FeedError as exception:
            raise CommandError(str(exception)) from exception
