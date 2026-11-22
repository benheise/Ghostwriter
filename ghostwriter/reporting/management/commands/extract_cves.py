"""Fill the ``cves`` field of findings with the CVE identifiers already written in their text."""

# Django Imports
from django.core.management.base import BaseCommand
from django.db import transaction

# Ghostwriter Libraries
from ghostwriter.reporting.models import Finding, ReportFindingLink
from ghostwriter.reporting.validators import clean_cves, find_cves

# Text fields searched for CVE identifiers
SCANNED_FIELDS = (
    "title",
    "description",
    "impact",
    "mitigation",
    "replication_steps",
    "references",
)


class Command(BaseCommand):
    help = (
        "Add the CVE identifiers mentioned in each finding's title, description, impact, recommendation, "
        "replication steps, and references to its CVE IDs field. Existing CVE IDs are kept."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report the changes without saving them",
        )
        scope = parser.add_mutually_exclusive_group()
        scope.add_argument(
            "--library-only",
            action="store_true",
            help="Only update findings in the findings library",
        )
        scope.add_argument(
            "--reports-only",
            action="store_true",
            help="Only update findings attached to reports",
        )

    def handle(self, *args, **options):
        models = []
        if not options["reports_only"]:
            models.append(Finding)
        if not options["library_only"]:
            models.append(ReportFindingLink)

        for model in models:
            changed = self.extract(model, options["dry_run"], options["verbosity"])
            action = "would be updated" if options["dry_run"] else "updated"
            self.stdout.write(f"{model._meta.verbose_name_plural}: {changed} {action}")

    def extract(self, model, dry_run, verbosity):
        """Add the CVE identifiers found in the text of each ``model`` entry and return how many changed."""
        pending = []
        for entry in model.objects.only("pk", "cves", *SCANNED_FIELDS).iterator():
            found = set()
            for field in SCANNED_FIELDS:
                found.update(find_cves(getattr(entry, field)))
            current = clean_cves(entry.cves)
            merged = clean_cves(current + sorted(found))
            if merged == entry.cves:
                continue
            if verbosity >= 2:
                self.stdout.write(f"{model.__name__} {entry.pk}: {', '.join(merged) or 'none'}")
            entry.cves = merged
            pending.append(entry)

        if pending and not dry_run:
            # ``bulk_update`` writes only this field, so it doesn't change timestamps or fire save signals
            with transaction.atomic():
                model.objects.bulk_update(pending, ["cves"], batch_size=500)
        return len(pending)
