# PostgreSQL image transition

The hardened PostgreSQL 17 image now uses patched Alpine packages. The previous
Debian image is retained in `deploy/Dockerfile.db.debian` for recovery. Both run
as UID/GID 999, but their C libraries and locale implementations differ.

**Do not attach an existing Debian database volume to the Alpine image.** The
new entrypoint refuses an initialized volume without its runtime marker. Do not
bypass the guard by adding the marker manually. PostgreSQL warns that changing
collation behavior can invalidate text indexes. Use a logical dump and restore
into a fresh cluster so indexes are rebuilt under the destination runtime.
[PostgreSQL locale documentation](https://www.postgresql.org/docs/17/locale.html).

This transition affects self-hosted Docker databases. Managed databases used by
the Render web service continue to run under their provider's database image.

1. Preserve the exact old database image reference and its current data volume.
   If necessary, build the recovery image with
   `docker build -f deploy/Dockerfile.db.debian -t ssdc-postgres-debian-recovery .`.
   Keep using the old image for the original database while exporting it.
2. Drain writers/processors and create an authenticated encrypted paired snapshot
   with the existing backup command, using the old stack and separately held key.
3. Create an isolated project with a new database volume and the new pinned image.
   Initialize the bootstrap, migration and runtime roles using `deploy/init-db.sh`.
4. Follow `scripts/backup.py restore` in the deployment runbook, with an explicit
   `ssdc-restore-<reference>` project and filesystem recovery storage. The command
   restores the schema/data logically, applies pending migrations/runtime grants,
   checks file/MFA integrity and revokes old sessions. It leaves web traffic stopped.
5. Verify MFA, document hashes, previews/ranges and access denials over HTTPS, then
   reconnect the approved primary storage and switch traffic using the deployment
   procedure. Preserve the original stack/snapshot until acceptance is recorded.

For a synthetic rehearsal that never uses application data or existing database
volumes:

```sh
python scripts/rehearse_release.py \
  --app-image ssdc-vault-app:release-candidate \
  --db-image ssdc-postgres-debian-recovery \
  --restore-db-image ssdc-postgres:release-candidate \
  --scanner-image ssdc-clamav:release-candidate
```

The rehearsal generates private fixture secrets, uses loopback-only HTTPS ports
8081/8443, and removes only its randomly named containers/volumes. It exercises
real scanning, encrypted paired backup, full logical recovery and restored MFA/PDF
access. Evidence is saved under `artifacts/rehearsal-<reference>/`.
