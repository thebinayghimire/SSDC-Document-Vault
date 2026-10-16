# Pilot image audit — 15 October 2026

Docker Scout 1.25.0 analyzed the locally built AMD64 candidates. No images were
pushed. Python runtime/development lockfile and npm audits reported no known
vulnerabilities; those checks do not cover OS packages.

| Image | Image ID | Scout result |
| --- | --- | --- |
| ssdc-app:pilot-candidate | sha256:2788d28006d040682fcffe17bb5ec9716c64fab7db5c38a747cc14ca7721f1d9 | **28 findings: 1 high, 1 medium, 26 low**, 13 Debian source packages; exit 2. |
| ssdc-scanner:pilot-candidate | sha256:e478a4c8cdd68154fac1450c8a61440f581545369945a4518ae012d11697a80a | No vulnerable packages reported; exit 0. |
| ssdc-proxy:pilot-candidate | sha256:755c780194c9c69c12a3aad3ba7e5e6c6fd98112334c0652df69bbfc93ac052f | No vulnerable packages reported; exit 0. |

All 28 application findings have no fixed Debian package version reported. The
audit remains **failed/open**, not suppressed. Scout emitted Windows temporary
archive cleanup warnings but completed indexing and wrote all three SARIF files.
No broad cache deletion was attempted.

## High: CVE-2026-85091, zlib

Installed Debian source package: `1:1.3.dfsg+really1.3.1-1`; Python reports both
compile/runtime zlib **1.3.1**. The CVE description refers to 1.3.1.2–1.3.2 and
non-blocking gzip-writer behavior. However, Debian currently labels trixie's
package vulnerable/unfixed, and upstream discussion still questions applicability
to older writer paths. The apparent version mismatch is **not sufficient to
dismiss the finding**.
[Debian status](https://security-tracker.debian.org/tracker/CVE-2026-85091),
[upstream discussion/fix](https://github.com/madler/zlib/issues/1310).

No vendor-provided fixed trixie version was identified. Do not blindly upgrade to
an affected 1.3.2 package or replace distro libraries with an unreviewed source
build. Before public use, obtain a supported fixed base/package or documented
vendor applicability determination reviewed by the release owner; then rebuild,
rescan and repeat TLS/PDF/image/parser/backup acceptance. No VEX exception or
security waiver was created here.

## Evidence for the zlib finding (recorded 16 October 2026)

The high finding is not an assertion; it is reproduced below from the retained
scan output and corroborated by distribution trackers.

**Scanner record** — `artifacts/pilot-app-cves.sarif`, rule `CVE-2026-85091`,
result `kind: fail`, `level: error`:

```text
Vulnerability    :CVE-2026-85091
Severity         :HIGH
Package          :pkg:deb/debian/zlib@1%3A1.3.dfsg%2Breally1.3.1-1?os_distro=trixie&os_name=debian&os_version=13
Affected range   :>0
Fixed version    :not fixed
EPSS Score       :0.003560
EPSS Percentile  :0.275930
```

Rule properties: `security-severity: 8.3`, `cvssV3_severity: HIGH`,
`fixed_version: not fixed`. Detection locations inside the image:
`/usr/share/doc/zlib1g/copyright` and `/var/lib/dpkg/status`. The same SARIF
file holds 28 rules in total — **1 at 8.3 (HIGH), 1 at 4.1 (MEDIUM), 26 at 3.1
(LOW)** — which is the arithmetic behind the 1/1/26 split reported above.

**Vulnerability description** (Scout rule help text, matching the CVE record):

> zlib versions 1.3.1.2 through 1.3.2 contain a heap buffer overflow
> vulnerability in the `gz_vacate()` function when processing non-blocking
> `gzwrite()` operations with stale external buffer pointers. Attackers can
> trigger the overflow by calling `gzprintf()` or `gzvprintf()` after a write
> stall, causing an unchecked `memmove()` to write beyond the internal input
> buffer boundary.

**Upstream references carried in the same record:**

- Issue: <https://github.com/madler/zlib/issues/1310>
- Pull request: <https://github.com/madler/zlib/pull/1317>
- Fix commit: <https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148>
- Affected-range discussion: <https://github.com/madler/zlib/issues/1310#issuecomment-5979623265>
- Non-blocking `gz*` support introduced in v1.3.1.2:
  <https://github.com/madler/zlib/commit/81cc0bebedd935daeb81b0b6e475d8786b51af3d>

**Distribution status, rechecked 16 October 2026:**

- Debian marks both bookworm (`1:1.2.13.dfsg-1`) and trixie
  (`1:1.3.dfsg+really1.3.1-1`) **vulnerable**, with unstable **unfixed**,
  tracked as Debian bug 1146895. No DSA and no trixie point-release entry names
  this CVE. [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-85091),
  [bug 1146895](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1146895).
- Ubuntu's tracker likewise reports its zlib packages as vulnerable, fix
  deferred. [Ubuntu CVE page](https://ubuntu.com/security/CVE-2026-85091).
- Alpine shipped a fixed build (`zlib 1.3.2-r1` in `v3.22/main`), which is why
  the Alpine-based scanner and proxy images report no vulnerable packages while
  the Debian-based application image still does.
  [alpinelinux/docker-alpine#492](https://github.com/alpinelinux/docker-alpine/issues/492).

**Why the version mismatch does not close the finding.** The CVE text names
1.3.1.2–1.3.2 and the image carries 1.3.1, which looks like a non-match. But
the vendor of record (Debian) still labels the shipped package vulnerable and
applies no fix, Scout's affected range is `>0`, and upstream discussion has not
settled applicability to the older writer paths. Dismissing it on version
string alone would be a self-issued exception against the vendor's own status.
The finding therefore stays **open**, and the application image scan continues
to exit 2. No VEX exception and no security waiver has been created.

**Exposure note, not a dismissal:** the application does not call the `gz*`
writer interface on attacker-controlled non-blocking streams; `zlib1g` is
present as a transitive dependency of the base image and Python. That bounds
likely reachability but does not constitute a vendor applicability
determination, which is what the release gate requires.

## Medium: CVE-2025-45582, GNU tar

Debian marks this issue disputed and links upstream's documented extraction
behavior. The app accepts PDFs/images, not uploaded tar files; paired restore
uses Python `tarfile` with the `data` filter, not GNU tar. This reduces exposure to
the described multi-archive CLI scenario; it is an application-path assessment,
not a vendor-wide declaration of safety. Retain the finding and reviewed operator
restore procedure.
[Debian entry](https://security-tracker.debian.org/tracker/CVE-2025-45582).

## Low findings and repeatable checks

The remaining 26 findings cover tar, shadow, OpenSSL, glibc, apt, Perl, systemd,
coreutils, SQLite, util-linux, dash and diffutils. Scout's Debian notes describe
unimportant/negligible impacts, disputed behavior or limited scenarios. Non-root
execution, read-only root, dropped capabilities and bounded parsers mitigate
exposure; they do not prove every finding unreachable. Preserve raw reports and
rescan the exact final release images.

```sh
docker scout cves local://ssdc-app:pilot-candidate --format sarif --output artifacts/pilot-app-cves.sarif --exit-code
docker scout cves local://ssdc-scanner:pilot-candidate --format sarif --output artifacts/pilot-scanner-cves.sarif --exit-code
docker scout cves local://ssdc-proxy:pilot-candidate --format sarif --output artifacts/pilot-proxy-cves.sarif --exit-code
```

The application scan currently exits 2. Do not filter it into a passing result or
describe all vulnerability audits as clean.

## Base-image recheck — 16 October 2026 (F10 acceptance path 1)

Rechecked whether a vendor-patched base removes the high finding before asking
for a release decision. Pulled `python:3.13-slim-trixie` fresh and queried the
package database inside it:

```text
installed: 1:1.3.dfsg+really1.3.1-1+b1
zlib1g:
  Installed: 1:1.3.dfsg+really1.3.1-1+b1
  Candidate: 1:1.3.dfsg+really1.3.1-1+b1
```

The current base carries a binary rebuild (`+b1`) of the same source version the
audit recorded; `apt` offers no higher candidate, so **no supported fixed Debian
package exists today** and rebuilding on the latest base cannot clear
CVE-2026-85091. Debian bug 1146895 remains open with no DSA.

Consequence for F10: acceptance path 1 (supported patched images/packages) is
unavailable. Closure now depends solely on path 2 — a qualified, documented
applicability determination with a named owner and revisit date, decided by the
SSDC release owner. No waiver, VEX exception or suppression was created in this
step; the application image scan still exits 2.
