"""Load the CISA KEV catalog from a file, for servers that cannot reach CISA."""

# Django Imports
from django.core.management.base import BaseCommand, CommandError

# Ghostwriter Libraries
from ghostwriter.vulnintel.feeds import FeedError
from ghostwriter.vulnintel.models import VulnIntelConfiguration
from ghostwriter.vulnintel.tasks import refresh_kev


class Command(BaseCommand):
    help = (
        "Load CISA's KEV catalog from a copy of known_exploited_vulnerabilities.json. Works whether or not "
        "KEV downloads are enabled."
    )

    def add_arguments(self, parser):
        parser.add_argument("path", help="Path to the KEV catalog JSON file")

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
            self.stdout.write(refresh_kev(config, data=data))
        except FeedError as exception:
            raise CommandError(str(exception)) from exception
