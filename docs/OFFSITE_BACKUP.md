# Offsite backup destination

Use a **private Cloudflare R2 Standard bucket** named `ssdc-vault-backups`, owned
by the same person or organization responsible for the Render service. This gives
the paired snapshots a storage provider separate from the primary Google Drive
document library. No bucket, subscription, billing change or upload has been made.

R2 Standard includes 10 GB-month of storage, one million Class A requests and ten
million Class B requests each month. Usage beyond the allowances is billable;
retaining multiple full vault snapshots can exceed the included storage. Measure
the encrypted snapshot and choose a budget before enabling scheduled uploads.
[Current R2 pricing](https://developers.cloudflare.com/r2/pricing/).

## Private setup

1. The operator creates the Cloudflare account/R2 subscription and private bucket.
   Leave public access, `r2.dev` access and custom-domain access disabled.
2. Create a bucket-scoped backup credential. Keep it outside the web application's
   runtime secrets. Give the recovery operator separate read access.
3. Keep the backup encryption key in the operator's password manager or equivalent
   restricted recovery store, separately from the bucket and database snapshots.
   Preserve the MFA and Drive credential keys needed for recovery as well.
4. Configure an operator-controlled job to create the authenticated encrypted
   paired snapshot using `scripts/backup.py` or `scripts/backup_pilot.py` for the
   applicable deployment. A native Render deployment needs its own maintenance
   coordination and direct PostgreSQL/Drive access; the Docker CLI backup command
   does not operate against a Render service URL.
5. Upload the `.ssdcbackup` ciphertext using a unique timestamp/hash object name;
   download it and compare its SHA-256 before recording a successful offsite copy.
   Run the isolated restore procedure against the downloaded copy.
6. Assign a named backup/alert owner, approve a schedule/retention policy and
   configure failure notifications. Keep deletion/retention changes explicit.

## Verified recovery and remaining activation

The local rehearsal has verified AES-GCM paired backup, schema/data restoration,
document hashes, MFA seed decryption and restored MFA/PDF/range access over HTTPS.
It uses generated synthetic fixtures and separate empty Docker volumes.

Real offsite backup remains inactive until the account, bucket credential, key
custody, budget and hosted maintenance job are configured. Neither a mock upload
nor a local restore should be represented as a verified offsite backup.
