# Document Vault interface redesign

## Audit and scope

The existing product is a server-rendered Django 5.2 document vault. Django
templates and a single stylesheet provide the interface; self-hosted PDF.js
renders authorized PDFs, with a separate image preview. Forms, validation,
pagination, messages, permissions, sessions, and MFA are owned by Django.
Administration uses Django's built-in widgets and authorization.

The previous presentation used green accents, serif headings, 8–13px interface
text, decorative banners, gradients on authentication, inconsistent controls,
and a library navigation selection that appeared on every page. Mobile navigation
was a horizontal strip of desktop links. Management and security forms used
unstructured paragraph layouts.

`DESIGN.md` is the supplied design reference, copied into the repository without
changing its contents. Its color, typography, spacing, radius, and restraint
principles are adapted to an operational document browser. Marketing tiles and
photography are not appropriate to this product's workflows.

## Screen map

| Screens | Primary goal | Presentation |
| --- | --- | --- |
| `/`, `/folders/<id>/` | Find and open permitted documents | Folder browser, search and filters, list/gallery, metadata, pagination |
| `/documents/<id>/` | Read a PDF or image | Quiet controls, fit/zoom/page navigation, watermarked preview, skeleton and errors |
| `/manage/` | Review document lifecycle | Operational rows with explicit publication, archive, and deletion states |
| `/documents/<id>/manage/` | Edit details and review versions | Details form, visibility controls, retained version history |
| Folder creation, upload, replacement | Add or organise documents | Focused form with contextual guidance and clear submit/cancel actions |
| Login, MFA challenge/enrollment/recovery | Authenticate and secure access | Restrained authentication panels and stepped enrollment |
| Password change and identity confirmation | Manage account security | Readable form, helper text, error focus, explicit progress |
| Administration index/app index | Find administrative resources | Grouped accounts, access, audit, and recent changes |
| Administration lists/forms/history | Manage accounts, grants, and records | Shared styling around native Django filters, sorting, actions, and widgets |
| 404 and 500 | Recover from a failed request | Plain explanation and a path back to the library |

Content, thumbnail, health, and POST lifecycle endpoints remain nonvisual.
Routes, form field names, CSRF, access checks, scanning, data, and business rules
are preserved. Concurrent pre-existing backend changes are outside the redesign.

## Design system and interactions

- `static/css/tokens.css` centralizes colors, type, spacing, radii, widths, motion,
  elevation, and layer levels. Media query breakpoints are documented there.
- Inter is the primary UI font, as explicitly requested after the redesign.
  Regular and italic variable WOFF2 files are bundled under `static/fonts/inter/`
  with their upstream license. Both application shells preload the regular face;
  headings, navigation, forms, tables, buttons, and watermarks use the shared font
  token. Monospace security codes and original document content keep their
  appropriate presentation. Fonts load from the app itself under the existing CSP.
- `static/css/app.css` replaces the old theme, with flat surfaces and a single
  blue interactive accent. Only the document preview uses an elevation shadow.
- Reusable template includes provide icons, navigation, and form fields.
  Bound Django fields preserve native validation and error/helper relationships.
- A neutral sidebar selects the current destination from the resolved route.
  Mobile uses a native disclosure menu with Escape and outside-click dismissal.
- Delete uses a native dialog with explicit keyboard focus wrapping, Escape,
  cancel, and focus restoration. The underlying authorized POST is unchanged.
- Submit controls announce progress and prevent repeated submission. Browser
  history navigation restores the controls. File selection advertises supported
  types while server-side validation remains authoritative.
- Previews disable controls until content loads, fit to actual available width,
  refit after resize while in fit mode, and present a usable failure state. PDF
  page text is exposed to screen readers when present in the source PDF.
- Native administration filters, actions, account forms, permission checks, and
  the existing light/dark/automatic theme switch are retained. Dark surfaces and
  links use their own tokens. The staff workspace continues to use its light theme.

## Responsive and accessibility checks

The browser matrix checks 375, 390, 430, 768, 1024, 1280, 1440, and 1920px.
Mobile list records retain type, size, and date beneath the title; long titles,
folder names, and staff IDs wrap or truncate without widening the page. Version
and administration tables scroll inside their containers. The gallery becomes
one column on small phones. Forms and lifecycle panels stack, and navigation is
replaced with a touch-friendly disclosure below 834px.

Visible keyboard focus, a skip link, table captions and headers, labelled controls,
error summary focus, current navigation semantics, live status messages, native
dialog behavior, practical 44px targets, and reduced-motion rules are included.
Accessible PDF text depends on the document containing extractable text; this
redesign does not add OCR to scanned PDFs.

## Validation

Run the normal Django/PostgreSQL tests plus `tests/test_ui.py`. The browser suite
uses an isolated test database and temporary private storage; it never resets
existing user accounts or captures authenticator keys/recovery codes. Screenshots
and the responsive matrix are saved to ignored `artifacts/redesign/`.

```powershell
.\.venv\Scripts\pytest.exe -q --tb=short
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run
node --check static/js/app.mjs
node --check static/js/viewer.mjs
docker compose build app
```

Browser coverage includes authenticated route rendering, responsive layout,
light/dark administration, search/filter/view preservation, file upload and
replacement, metadata updates, archive/deletion/restoration, version restoration,
dialog keyboard handling, mobile navigation, sign-in errors, MFA setup/recovery,
PDF page controls, resizing, protected access, and failed content delivery.

### Results — 7 October 2026

- Full suite: **107 passed**, including the four Chromium browser suites.
- Responsive matrix: **120 combinations** across 15 authenticated screens and
  eight widths, plus MFA/security states and long-value checks.
- Inter update: the responsive matrix passed again; browser checks confirmed
  locally served regular and italic fonts and actual Inter glyph rendering in
  both the vault and administration. The rebuilt Docker app passed font loading
  and mobile/desktop layout checks.
- Ruff lint and formatting, Django system checks, migration consistency,
  JavaScript syntax, and Git whitespace checks passed.
- Docker image build/static asset collection passed. The rebuilt local app is
  healthy; login, health, and the compiled UI assets return HTTP 200.
- Desktop/mobile screenshots were visually reviewed, including administration
  light/dark surfaces, the document browser, and management forms.
- The older `scripts/browser_check.py` run rejected the existing saved demo
  credentials. Existing accounts were not reset; authenticated workflows were
  verified independently using the isolated synthetic browser suite above.
- Browser verification used Chromium. Scanned PDF accessibility still depends
  on an existing text layer; no OCR service or external assets were added.
