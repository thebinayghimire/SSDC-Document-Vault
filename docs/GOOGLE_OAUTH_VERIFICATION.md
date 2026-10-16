# Google OAuth verification text

Use the public production homepage, privacy policy, and terms URLs on the same verified
domain. The OAuth client requests only
`https://www.googleapis.com/auth/drive.file` for SSDC's single storage-owner account.

## How user data is handled, stored and shared

OAuth refresh and access tokens for the single storage-owner account are encrypted at
rest with a separate application key and stored in our managed PostgreSQL database over
TLS. The encryption key is held as an isolated environment secret in the application
runtime, completely separate from the database and database backups. Tokens are never
logged, displayed, or transmitted anywhere other than to Google's token endpoint over
HTTPS.

Document contents remain in the storage owner's Google Drive. Our server stores document
metadata, permission grants, and audit records. No Google user data is sold, transferred
to advertisers or data brokers, or shared with any third party. Access is served over
HTTPS only, every document request is re-checked against the requesting staff member's
current permissions, uploaded files are validated by type and size before publication,
and all access is recorded in an audit log. Privileged roles require two-factor
authentication.

If the organization disconnects the integration, we delete the stored credentials; files
already in Drive remain under the storage owner's control.
