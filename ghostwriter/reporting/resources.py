"""This contains all the ``import_export`` model resources used by the Reporting application."""

# 3rd Party Libraries
from import_export import resources
from import_export.fields import Field
from import_export.widgets import ForeignKeyWidget, Widget
from taggit.models import Tag

# Ghostwriter Libraries
from ghostwriter.modules.shared import TagFieldImport, TagWidget, taggit_before_import_row
from ghostwriter.reporting.models import Finding, FindingType, Observation, Severity
from ghostwriter.reporting.validators import clean_cves, normalize_cves


class CveListWidget(Widget):
    """Import and export CVE identifiers as one comma-separated column."""

    def clean(self, value, row=None, **kwargs):
        # Raises ``ValueError`` for an entry that is not a CVE identifier, which fails the row
        return normalize_cves(value)

    def render(self, value, obj=None, **kwargs):
        return ", ".join(clean_cves(value))


class FindingResource(resources.ModelResource):
    """Import and export :model:`reporting.Finding`."""

    severity = Field(
        attribute="severity",
        column_name="severity",
        widget=ForeignKeyWidget(Severity, "severity"),
    )
    finding_type = Field(
        attribute="finding_type",
        column_name="finding_type",
        widget=ForeignKeyWidget(FindingType, "finding_type"),
    )
    cves = Field(attribute="cves", column_name="cves", widget=CveListWidget())
    tags = TagFieldImport(attribute="tags", column_name="tags", widget=TagWidget(Tag, separator=","))

    def before_import_row(self, row, **kwargs):
        taggit_before_import_row(row)

    class Meta:
        model = Finding
        skip_unchanged = False
        fields = (
            "id",
            "severity",
            "cvss_score",
            "cvss_vector",
            "cves",
            "finding_type",
            "title",
            "description",
            "impact",
            "mitigation",
            "replication_steps",
            "host_detection_techniques",
            "network_detection_techniques",
            "references",
            "finding_guidance",
            "tags",
            "extra_fields",
        )
        export_order = (
            "id",
            "severity",
            "cvss_score",
            "cvss_vector",
            "cves",
            "finding_type",
            "title",
            "description",
            "impact",
            "mitigation",
            "replication_steps",
            "host_detection_techniques",
            "network_detection_techniques",
            "references",
            "finding_guidance",
            "tags",
            "extra_fields",
        )


class ObservationResource(resources.ModelResource):
    """Import and export :model:`reporting.Observation`."""

    tags = TagFieldImport(attribute="tags", column_name="tags", widget=TagWidget(Tag, separator=","))

    def before_import_row(self, row, **kwargs):
        taggit_before_import_row(row)

    class Meta:
        model = Observation
        skip_unchanged = False
        fields = (
            "id",
            "title",
            "description",
            "tags",
            "extra_fields",
        )
        export_order = (
            "id",
            "title",
            "description",
            "tags",
            "extra_fields",
        )
