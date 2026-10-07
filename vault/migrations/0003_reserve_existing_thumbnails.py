from django.db import migrations


def reserve_existing(apps, schema_editor):
    version = apps.get_model("vault", "Version")
    version.objects.filter(mime_type__startswith="image/", thumbnail_size=0).update(thumbnail_size=1024 * 1024)


class Migration(migrations.Migration):
    dependencies = [("vault", "0002_version_thumbnail_size")]
    operations = [migrations.RunPython(reserve_existing, migrations.RunPython.noop)]
