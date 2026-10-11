from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("vault", "0006_publication_integrity")]
    operations = [
        migrations.RunSQL(
            """
            CREATE FUNCTION vault_validate_folder_hierarchy() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF EXISTS (
                    WITH RECURSIVE ancestry AS (
                        SELECT id, parent_id, ARRAY[id] AS visited, 0 AS depth, false AS cycle
                        FROM vault_folder
                        UNION ALL
                        SELECT ancestry.id, parent.parent_id, ancestry.visited || parent.id,
                               ancestry.depth + 1, parent.id = ANY(ancestry.visited)
                        FROM ancestry JOIN vault_folder parent ON parent.id = ancestry.parent_id
                        WHERE NOT ancestry.cycle AND ancestry.depth < 21
                    )
                    SELECT 1 FROM ancestry WHERE cycle OR depth > 20
                ) THEN
                    RAISE EXCEPTION 'Folder cycle or descendant depth exceeds 20 levels'
                        USING ERRCODE = '23514';
                END IF;
                RETURN NULL;
            END;
            $$;
            CREATE TRIGGER vault_folder_hierarchy_guard
            AFTER INSERT OR UPDATE ON vault_folder FOR EACH STATEMENT
            EXECUTE FUNCTION vault_validate_folder_hierarchy();
            """,
            """
            DROP TRIGGER vault_folder_hierarchy_guard ON vault_folder;
            DROP FUNCTION vault_validate_folder_hierarchy();
            """,
        )
    ]
