from django.db import migrations

TABLES = ("vault_folder", "vault_foldergrant", "vault_document", "vault_documentgrant")


class Migration(migrations.Migration):
    dependencies = [("vault", "0003_reserve_existing_thumbnails")]

    operations = [
        migrations.RunSQL(
            sql=[
                """
                CREATE FUNCTION vault_serialize_policy_write() RETURNS trigger
                LANGUAGE plpgsql AS $$
                BEGIN
                    PERFORM pg_advisory_xact_lock(731012);
                    RETURN NULL;
                END;
                $$;
                """,
                *[
                    f"""
                    CREATE TRIGGER vault_policy_write_guard
                    BEFORE INSERT OR UPDATE OR DELETE ON {table}
                    FOR EACH STATEMENT EXECUTE FUNCTION vault_serialize_policy_write();
                    """
                    for table in TABLES
                ],
            ],
            reverse_sql=[
                *[f"DROP TRIGGER vault_policy_write_guard ON {table};" for table in TABLES],
                "DROP FUNCTION vault_serialize_policy_write();",
            ],
        ),
    ]
