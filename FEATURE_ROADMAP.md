# SSDC Document Vault — feature roadmap

Prepared: **7 October 2026 (Asia/Kathmandu)**

Goal: make the vault dependable in everyday use, easy for staff to navigate, and easier for administrators to operate and recover.

This is a **proposal list**, not a list of completed features or a deployment sign-off. It builds on the existing roles, permissions, PDF/image previews, version history, scanning, Google Drive storage integration, and recent staff dashboard improvements. Some proposals extend existing controls; others introduce new capabilities.

The current experience stays the starting point: a simple staff library, no preview watermark, and **89% initial preview zoom**. New features should appear only when useful, rather than filling the dashboard with widgets.

## How to prioritize

- **Foundation:** dependable operation and recovery. Reconcile these proposals with the open findings in [DEPLOYMENT_FIXES.md](DEPLOYMENT_FIXES.md); existing implementation work needs current verification before being called complete.
- **Next:** everyday improvements that remove friction for staff and managers.
- **Later:** larger workflows or experiments, introduced after measuring demand.

Effort is a relative planning estimate: **S** = a focused change; **M** = several connected components; **L** = a new subsystem or substantial operational work. These are not delivery-time promises.

## 1. Reliability staff can trust

| ID | Feature | What it would do | Priority | Effort |
|---|---|---|---|---|
| 01 | Document-service health dashboard | Show operators whether database access, storage authorization, preview delivery, scanner freshness, background jobs, and backups are actually working. Staff see a plain service notice only when affected. | Foundation | M |
| 02 | Verified recovery, not just scheduled backups | Back up database records and document bytes as a consistent pair, keep encrypted copies in a separate failure domain, and automatically restore samples in an isolated environment. Report the last successful restore drill. | Foundation | L |
| 03 | Durable upload queue | Accept an upload once, then process it through explicit queued, checking, ready, and needs-attention states. Bound worker concurrency and safely recover interrupted jobs. | Foundation | L |
| 04 | Retry without duplicates | Give each upload an operation identity. A double click, repeated request, or reconnect returns the same result instead of creating another document or version. | Foundation | M |
| 05 | Storage outage handling | Classify temporary storage failures, retry with bounded backoff, and stop overwhelming an unavailable provider. Display a useful retry message and alert operators when authorization needs repair. | Foundation | M |
| 06 | Continuous integrity patrol | Periodically compare originals and generated previews against recorded hashes. Quarantine mismatches and notify an operator instead of silently serving changed bytes. | Foundation | M |
| 07 | Recovery-safe maintenance mode | Drain uploads, pause mutating jobs, display a maintenance notice, and verify services before reopening. Preserve the prior service state when backup or deployment steps fail. | Foundation | M |
| 08 | Capacity early-warning system | Track storage growth, queue age, temporary-disk use, and memory pressure. Warn before exhaustion and give a controlled refusal when an operation cannot safely fit. | Foundation | M |
| 09 | Preview self-repair | Regenerate a missing or corrupt thumbnail/derived preview from a verified original using a bounded job. Never overwrite the original or bypass scanning. | Next | M |
| 10 | Release rehearsal | Run a synthetic login, upload, scan, PDF/image preview, permission revocation, and restore check against exact release images before upgrading the real service. | Foundation | L |

**Acceptance examples:** disconnect storage during an upload; retry the same request; terminate a worker mid-job; restore onto an empty host. Every operation should have a recoverable outcome with no duplicate publication, lost original, or false success message.

Google documents quota handling and exponential backoff for Drive requests. Use error-specific retry rules rather than retrying every failure, and never fall back to public file links. [Google Drive usage limits](https://developers.google.com/workspace/drive/api/guides/limits).

For PostgreSQL recovery, choose verification appropriate to the backup format. `pg_verifybackup` validates supported base backups; it is not a verifier for a custom encrypted bundle or a `pg_dump` archive. Those still need decryption, restore, and application-level checks. [PostgreSQL backup and restore](https://www.postgresql.org/docs/17/backup.html), [pg_verifybackup](https://www.postgresql.org/docs/17/app-pgverifybackup.html).

## 2. A calmer, faster staff experience

| ID | Feature | What it would do | Priority | Effort |
|---|---|---|---|---|
| 11 | Personal bookmarks | Let staff pin permitted documents and folders to a small “Pinned” section. Remove unavailable items when access changes. | Next | M |
| 12 | Recently opened documents | Provide a private, short list of recently viewed documents with a clear-history control. Recheck access before showing titles or previews. | Next | M |
| 13 | Resume reading | Offer to return to the last page of the same document version. New versions open with an update notice; previews still start at 89% zoom. | Next | M |
| 14 | Better search without extra complexity | Search titles, approved tags, document type, project, and date range; support saved searches. Explain active filters and keep one visible clear action. | Next | M |
| 15 | Permission-safe full-text search | Index approved PDF text and optional OCR output. Search results, snippets, counts, suggestions, and caches must all respect current access. | Later | L |
| 16 | English and Nepali interface | Translate navigation, actions, and error messages; support Devanagari titles and search input. Test font rendering and sorting with representative documents. | Next | M |
| 17 | Accessible reading and navigation | Improve keyboard navigation, focus visibility, semantic document text, screen-reader status messages, and zoom/reflow. Provide an approved alternative for scanned pages with no readable text. | Foundation | L |
| 18 | Low-bandwidth viewing | Prioritize the visible PDF page, defer unnecessary thumbnails, show useful progress, and preserve navigation during connection problems. | Next | M |
| 19 | Contextual recovery messages | Replace generic errors with clear next actions: sign in again, retry, return to the library, or contact the document owner. Preserve safe navigation state through reauthentication. | Next | S |
| 20 | Helpful empty states | Distinguish “no documents shared yet,” “folder is empty,” and “no search matches.” Give the relevant next step without revealing inaccessible documents. | Next | S |

**Acceptance examples:** a staff member finds a document, opens it, resumes reading, and returns to the same filtered list on a phone. A keyboard-only user completes the same flow. Use WCAG 2.2 AA as the proposed acceptance target, supported by manual assistive-technology testing. [W3C WCAG overview](https://www.w3.org/WAI/standards-guidelines/wcag/).

## 3. Better document workflows

| ID | Feature | What it would do | Priority | Effort |
|---|---|---|---|---|
| 21 | Structured document metadata | Add optional project, department, document type, owner, language, effective date, and review date. Keep required fields minimal and offer approved values. | Next | M |
| 22 | Draft, reviewed, and published states | Let managers prepare a document privately and assign an authorized reviewer before staff can see it. Keep approval attached to the exact version reviewed. | Later | L |
| 23 | Version comparison | Show metadata changes and page-level visual changes between two permitted versions. Mark comparison limits for scans, layout changes, and inserted pages. | Later | L |
| 24 | Duplicate detection with a safe choice | Warn a manager when matching bytes already exist in a scope they can access. Offer to use the existing record or intentionally create a separate one. | Next | M |
| 25 | Request access | Provide a controlled route for staff to request access to a known document, with a reason and an approver. Permission checks decide how much metadata the request page can reveal. | Next | M |
| 26 | Document problem reporting | Add “Report an issue” for unreadable scans, wrong versions, missing pages, or outdated information. Attach the exact document version and page automatically. | Next | M |
| 27 | Review and expiry reminders | Notify owners when a policy, agreement, or certificate needs review. Show a clear stale-document notice without automatically deleting it. | Next | M |
| 28 | Retention holds and reversible cleanup | Define approved retention rules, preview the affected records, honor holds, and require an appropriate review before irreversible deletion. | Foundation | L |

**Acceptance examples:** approving version 2 must not approve a later replacement automatically; a duplicate warning must not expose a private document; an expired review date must not silently revoke legitimate access or delete records.

## 4. Less obvious ideas worth exploring

| ID | Feature | What it would do | Priority | Effort |
|---|---|---|---|---|
| 29 | Document confidence card | Show a compact factual panel: current owner, approved version, last review, integrity-check date, and any unresolved issue. Avoid an invented numerical “trust score.” | Next | M |
| 30 | Collections across folders | Assemble an onboarding pack, project pack, or meeting pack using references to documents, without duplicating files or granting additional access. | Next | M |
| 31 | “What changed for me?” digest | Show newly shared documents and relevant version changes since the user's last visit. Use a quiet in-app digest rather than a stream of interruptions. | Next | M |
| 32 | Replacement impact preview | Before publishing a replacement, show authorized references, collections, pending acknowledgements, and review tasks it will affect. | Later | M |
| 33 | Policy acknowledgement with context | Ask staff to acknowledge a specific policy version and allow “I need clarification.” Acknowledgement records receipt, not proof that someone understood it. | Later | M |
| 34 | Search-gap inbox | Collect explicit “I could not find what I needed” requests so managers can improve titles, tags, and missing content. Prefer voluntary feedback over retaining raw searches. | Later | M |
| 35 | Project handover pack | Generate a permission-checked collection of active documents, owners, pending reviews, and open issues for a staff transition. Reassignment requires explicit approval. | Later | L |
| 36 | Page-cited question answering | Optionally answer questions from permitted documents with exact version/page links, and say when evidence is missing or contradictory. Start with a small approved corpus. | Later | L |

### How the standout ideas could feel

**Document confidence card:** a staff member opens a policy and sees “Approved version 3 · Owner: HR · Reviewed 2 October 2026.” If a new version is awaiting review, the current published copy remains clear. Every status comes from recorded evidence; antivirus success alone never means a document's claims are accurate.

**Collections:** an administrator creates “New staff essentials” containing references to HR, safeguarding, and office-procedure documents from different folders. Each staff member sees only the permitted items. Pinning a collection never grants permission to its contents.

**What changed for me:** instead of making staff repeatedly inspect every folder, show “Two shared documents have newer versions.” Each item links to a concise change note and the current preview. Recheck access when building and opening the digest.

**Replacement impact preview:** a manager learns that a document is used in an onboarding collection and has outstanding acknowledgements before replacing it. They can add a change note and choose an approved notification path. Do not expose inaccessible collections or staff identities.

**Search-gap inbox:** a staff member selects “Couldn't find it” and submits “I need the current travel reimbursement form.” The responsible manager receives a useful request; the staff member does not need to understand the folder structure.

**Page-cited question answering:** a user asks “What is the travel advance limit?” The answer cites the relevant page and version, or reports that the permitted sources disagree. Document text is untrusted input; it cannot instruct the assistant to change permissions, send data, or execute actions. Retrieval, citations, generated answers, and conversation history all need authorization handling. Revocation must prevent further server access, though previously displayed text cannot be withdrawn from a recipient.

## 5. Administration without constant babysitting

| ID | Feature | What it would do | Priority | Effort |
|---|---|---|---|---|
| 37 | “View access as staff” inspector | Show administrators why a selected account can or cannot access a document, including direct grants and inheritance. Keep it an audited diagnostic view, without impersonating the user. | Next | M |
| 38 | Time-limited access and review | Grant approved temporary access with an expiry, send review reminders, and revoke expired grants transactionally. Model temporary grants separately so expiry does not erase a permanent grant. | Next | M |
| 39 | Clear incident and audit timeline | Link upload, scan, publication, access changes, restoration, and cleanup events by operation identity. Offer redacted support references that operators can use to investigate. | Foundation | M |
| 40 | Practiced account and key recovery | Provide tested operator procedures for lost administrator MFA, credential rotation, storage reconnection, and staff departure. Revoke sessions and preserve audit evidence. | Foundation | L |

**Acceptance examples:** an administrator can explain an access decision without trial-and-error grants; a temporary grant expires while the service is running; a lost sole-admin authenticator can be recovered through the approved identity-verification procedure on a disposable deployment.

## Suggested implementation order

### Stage 1 — establish a dependable foundation

Reconcile existing remediation work first, then prioritize **01, 02, 03, 04, 05, 06, 07, 08, 10, 17, 28, 39, and 40**. Do not add a second backup, monitoring, or processing system when an existing implementation can be completed and verified.

Agree who receives incidents, how long the vault can be unavailable, and how much recent work SSDC can tolerate losing. Measure those recovery targets through drills. Keep deployment approval tied to the existing release checklist.

### Stage 2 — remove everyday friction

Start with **11 bookmarks, 13 resume reading, 19 useful errors, 20 empty states, 21 metadata, 26 issue reports, and 37 access inspection**. Add **12 recent documents** if staff want it. Keep these sections collapsible or contextual so the dashboard remains calm.

### Stage 3 — make documents easier to discover and keep current

Introduce **14 better search, 16 localization, 24 duplicate detection, 27 review reminders, 29 confidence cards, 30 collections, and 31 change digests**. Pilot them with actual staff workflows rather than synthetic content alone.

### Stage 4 — trial larger ideas

Choose from approvals, version comparison, policy acknowledgements, full-text/OCR search, handover packs, and question answering after confirming demand and operating capacity. OCR and AI would be new scope beyond the original v1 specification.

## Five candidates for the next visible improvement

1. **Bookmarks:** immediate value for frequently used documents.
2. **Resume reading:** smoother use of long PDFs, while keeping the requested 89% opening zoom.
3. **Report a document issue:** a direct path to fixing unreadable or outdated content.
4. **Document confidence card:** clear ownership and currency at the point of use.
5. **Collections:** a practical way to find related documents without reorganizing every folder.

These can follow or run alongside foundation work; they do not replace it.

## Rules for adding features without creating clutter or leaks

- Every title, thumbnail, suggestion, count, notification, and collection needs current permission checks. Search indexes and personal-history caches are part of that boundary.
- Keep staff actions focused on finding and reading. Place management and operational controls in the appropriate role's screens.
- Keep notifications in-app by default. Email, messaging, or external integrations need a separate decision about channels and permitted content.
- If an optional service fails, preserve the core library and explain the affected capability. If authorization or integrity cannot be established, refuse content access.
- Preserve the requested watermark-free previews and 89% initial zoom. Do not reintroduce tracking overlays as a substitute for permission controls.
- Offline copies need a separate SSDC policy decision: access revocation cannot reliably retract bytes already downloaded to a device. Start with low-bandwidth online viewing.
- AI, OCR, and external processing need decisions about data location, retention, operational cost, and approved document classes before implementation.
- Use real usability trials and restore exercises alongside automated tests. Success metrics must come from observed results, not dashboard decoration.

## Definition of done for a selected feature

- [ ] A concrete user problem and owner are recorded.
- [ ] Its place in the interface is agreed, including mobile and empty/error states.
- [ ] Current access checks cover the feature's data, metadata, and caches.
- [ ] Failures, retries, and interruption behavior are defined where relevant.
- [ ] Appropriate automated checks and user or operator acceptance checks pass.
- [ ] Deployment, migration, recovery, and rollback implications are documented.
- [ ] Evidence is tied to the exact release candidate.
- [ ] The release checklist and current product documentation reflect the verified result.

## How to measure whether the vault improved

| Outcome | Useful measurement |
|---|---|
| Staff find information faster | Time and success rate for representative find-and-open tasks in a staff trial. |
| Previews are dependable | Successful authorized preview loads and measured load times on approved office/mobile networks. |
| Uploads are understandable | Time in each processing state, interruption recovery results, and duplicate-operation rate. |
| Recovery is real | Age of last successful isolated restore, measured recovery time, and verified database/file consistency. |
| Documents remain current | Overdue reviews, unresolved reported issues, and documents without an assigned owner. |
| Support work decreases | Repeated access/navigation incidents and time to diagnose failures using safe operation references. |

Collect the minimum operational data needed. Avoid document contents, credentials, raw search queries, and unnecessary per-person activity rankings in telemetry.
