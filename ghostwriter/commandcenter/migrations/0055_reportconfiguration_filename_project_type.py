# Standard Libraries
import re

# Django Imports
from django.db import migrations, models

# The report context exposes a project's type as ``project.type``; ``project.project_type`` is undefined,
# so filenames built from the old default lost the project type
OLD_VARIABLE = re.compile(r"\{\{\s*project\.project_type\s*\}\}")
NEW_VARIABLE = "{{project.type}}"
DEFAULT_FILENAME = '{{now|format_datetime("Y-m-d_His")}} {{company.name}} - {{client.name}} {{project.type}} Report'


def replace_project_type(apps, schema_editor):
    ReportConfiguration = apps.get_model("commandcenter", "ReportConfiguration")
    for config in ReportConfiguration.objects.all():
        report_filename = OLD_VARIABLE.sub(NEW_VARIABLE, config.report_filename)
        project_filename = OLD_VARIABLE.sub(NEW_VARIABLE, config.project_filename)
        if (report_filename, project_filename) != (
            config.report_filename,
            config.project_filename,
        ):
            config.report_filename = report_filename
            config.project_filename = project_filename
            config.save(update_fields=["report_filename", "project_filename"])


class Migration(migrations.Migration):
    dependencies = [
        ("commandcenter", "0054_generalconfiguration_token_lifecycle"),
    ]

    operations = [
        migrations.AlterField(
            model_name="reportconfiguration",
            name="report_filename",
            field=models.CharField(
                default=DEFAULT_FILENAME,
                help_text="Jinja2 template for report filenames. All template variables are available, plus {{now}} and {{company_name}}. The file extension is added to this. Individual templates may override this option.",
                max_length=255,
                verbose_name="Default Name for Report Downloads",
            ),
        ),
        migrations.AlterField(
            model_name="reportconfiguration",
            name="project_filename",
            field=models.CharField(
                default=DEFAULT_FILENAME,
                help_text="Jinja2 template for project filenames. All template variables are available, plus {{now}} and {{company_name}}. The file extension is added to this. Individual templates may override this option.",
                max_length=255,
                verbose_name="Default Name for Project Downloads",
            ),
        ),
        migrations.RunPython(replace_project_type, migrations.RunPython.noop),
    ]
