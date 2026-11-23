"""This contains the configuration of the Vulnerability Intelligence application."""

# Django Imports
from django.apps import AppConfig


class VulnIntelConfig(AppConfig):
    name = "ghostwriter.vulnintel"
    verbose_name = "Vulnerability Intelligence"

    def ready(self):
        import ghostwriter.vulnintel.signals  # noqa F401 isort:skip
