# Hosting setup — free-first plan

Prepared 7 October 2026 (Asia/Kathmandu). **No cloud server, domain, or live certificate has been provisioned.** This guide prepares the hosting layer; application release approval remains governed by [DEPLOYMENT_FIXES.md](../DEPLOYMENT_FIXES.md).

**15 October update:** the user selected an x86-64 Linux VM with Supabase PostgreSQL
and private Google Drive, with provider/hostname undecided. Follow
[HOSTED_PILOT.md](HOSTED_PILOT.md) for current limits, standalone pilot configuration
and commands. Historical alternatives below are not selected/provisioned resources.

## Hosting choice

**Latest preference (16 October 2026, supersedes the earlier statement below):**
the priority is **zero recurring hosting cost**. An organisation-controlled
computer is available after all, with a hostname SSDC controls. The selected
route to evaluate is therefore **self-hosting the existing Docker stack on that
machine, published through a named Cloudflare Tunnel**. See
[Self-hosting on an SSDC computer with Cloudflare Tunnel](#self-hosting-on-an-ssdc-computer-with-cloudflare-tunnel).
Nothing has been provisioned, published or connected.

**Earlier statements, retained for history and now partly superseded:** the
Oracle website was too slow for the user to complete setup, and at that time the
user reported no spare office computer. The eligibility correction still stands:
**SSDC is not a nonprofit. Remove nonprofit grants from the hosting plan.**
No provider or subscription has been selected or provisioned. Remaining cloud
routes are Oracle's eligible ongoing free allocation, a time-limited Google/AWS
trial for a pilot, or a paid server if the budget changes.

### Next actions for the corrected hosting plan

1. Confirm the organisation-controlled computer against the hardware table in
   [Self-hosting on an SSDC computer with Cloudflare Tunnel](#self-hosting-on-an-ssdc-computer-with-cloudflare-tunnel):
   CPU, RAM, disk, dedicated use, UPS, wired network, physical security.
2. Confirm the controlled hostname and that its DNS can be moved into the
   Cloudflare account that will own the Tunnel.
3. Obtain SSDC approval for Cloudflare terminating public TLS for document
   traffic, before any real document is uploaded.
4. Decide the off-site backup destination, retention, schedule, alert owner and
   RPO/RTO, and run a complete restore drill.
5. Only if the machine is rejected, price the minimum paid alternative below.
   Do not describe trial-funded hosting as permanently free production hosting.
6. Supply only non-secret setup details: hostname, region if relevant, and
   operator identity. No passwords or private keys belong in chat.

### Minimum recurring cost if the SSDC computer is rejected

If no suitable machine is available, there is **no** ongoing-free x86 option
that runs this stack: Oracle's free x86 shapes are 1 GB each, A1 is ARM and
subject to idle reclamation, and Google/AWS offers are time-limited credits.
The minimum workable paid alternative is a small x86-64 VPS sized for ClamAV:
**about 8 GB RAM, 4 vCPU, 80-160 GB SSD**, which is the entry bracket at
mainstream European/Asian VPS providers and typically falls in the region of
**USD 10-20 per month**, plus any domain and off-site backup storage. No
provider or region has been selected, so no price is quoted as a commitment;
obtain a current quote for the chosen provider, region and disk size, including
egress and backup charges, before approval. A 4 GB VM is cheaper but does not
meet the scanner's memory requirement and is not recommended.

### Cloud-only alternatives under the free budget

| Route | What it offers | Boundary |
|---|---|---|
| Google Cloud trial | Eligible new customers receive USD 300 for up to 90 days, ending earlier if exhausted. | A pilot, not ongoing free production. Keep trial billing status; Google says paid charges require manual upgrade. Export/restore the full vault before trial expiry. |
| AWS Free plan | Eligible new customers receive USD 100 initially and can earn up to USD 100 more. | Ends after six months or credit exhaustion, whichever comes first. Verify eligible services and account status before provisioning; credits do not guarantee six months of this stack. |

Sources: [Google Cloud trial FAQ](https://cloud.google.com/signup-faqs),
[AWS Free plan](https://aws.amazon.com/free/).

Use an x86-64 Ubuntu VM with approximately 8 GB RAM for a credit-funded pilot,
subject to service eligibility and a complete compute/disk/network/backup cost
estimate. This preserves the existing scanner architecture. Set budget alerts,
but remember alerts are not hard spending caps. Account opening, eligibility,
host/domain selection, and production release checks remain outstanding.

## Self-hosting on an SSDC computer with Cloudflare Tunnel

Evaluated 16 October 2026 against official sources. **Nothing provisioned,
published or connected.** This is the only evaluated route with no recurring
provider charge, and it is workable for SSDC's document sizes, subject to the
hardware, power and backup conditions below.

### Verdict for expected document sizes

`MAX_UPLOAD_BYTES` defaults to **25 MiB** per document, the settings ceiling is
100 MiB, and Nginx accepts `client_max_body_size 26m`
([settings.py](../config/settings.py), [nginx.prod.conf](../deploy/nginx.prod.conf)).
Cloudflare's documented maximum upload size is **100 MB on Free and Pro**;
larger requests get `413 Request Entity Too Large`, and only Enterprise can
raise it. The 25 MiB default therefore passes through a Tunnel with roughly a
4x margin. **Do not raise `MAX_UPLOAD_BYTES` toward the 100 MiB settings
ceiling on this route**: that lands at Cloudflare's cap and fails at the edge
before Django sees the request. If documents above ~90 MB are ever needed,
either keep that hostname DNS-only (which gives up the Tunnel) or change the
upload path; do not assume an increase is a settings change alone.
[Cloudflare error 413 / upload limits](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-413/).

Second edge limit: uploads are synchronous (upload, then ClamAV scan, then
Drive publication) and Gunicorn's timeout is 120 s. Cloudflare's current
documented default Proxy Read Timeout is **125 s**, with a 30 s write timeout
that cannot be adjusted, and increases are Enterprise-only; a slow scan or slow
Drive publication surfaces as a `524` at the edge rather than a Django error.
Measure end-to-end time for the largest realistic document on the actual
machine and link before pilot sign-off.
[Cloudflare error 524](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-524).

### Required hardware

| Item | Requirement | Why |
| --- | --- | --- |
| CPU | x86-64, 4 physical cores or more | Keeps the existing pinned AMD64 images; no ARM scanner rebuild is needed, unlike Oracle A1. |
| RAM | **16 GB recommended, 8 GB minimum** | ClamAV is the constraint: 4 GiB ceiling, app 1.5 GiB, plus PostgreSQL, proxy, OS and build headroom. Signature reloads briefly hold two engines in memory. [ClamAV: 3 GiB minimum, 4 GiB preferred](https://docs.clamav.net/manual/Installing/Docker.html). |
| Disk | SSD/NVMe, 256 GB or more, encrypted at rest | PostgreSQL, private quarantine/legacy volume, images, signatures, local backup staging. Readiness fails when free space drops below four times the upload limit. |
| Power | UPS sized for a clean shutdown, plus BIOS **restore-on-AC-power** | A hard cut during a write risks PostgreSQL corruption; the machine must come back without a person pressing a button. |
| Network | Wired Ethernet | Wi-Fi sleep and roaming drop the tunnel connector. |
| Role | **Dedicated machine**, not a daily-use laptop or shared desktop | Docker access is privileged access; sleep, logout and updates on a staff machine take the vault offline. |

Disable sleep, hibernate and suspend-on-lid-close explicitly; the default
desktop power profile is the most common cause of unexplained outages here.

### Operating system

Ubuntu Server 24.04 LTS, x86-64, with full-disk encryption, unattended security
updates, Docker Engine and the Compose plugin from Docker's own repository, and
the existing `compose.prod.yaml` stack (self-hosted PostgreSQL). This route does
**not** need Supabase; `compose.pilot.yaml` and
[HOSTED_PILOT.md](HOSTED_PILOT.md) apply only to the remote-database variant.
Windows or a desktop edition is not supported by this runbook.

### Uptime, power and internet reliability

There is no SLA and no redundancy. The vault is unreachable whenever the
machine, the office power or the office internet is down, and recovery is
manual unless auto-restart is configured. Record the honest expectation before
staff depend on it:

- Set every Compose service to `restart: unless-stopped` and enable the Docker
  service at boot, so a reboot restores service without an operator.
- A single-site office machine on consumer power and a single ISP link is
  realistically a **business-hours** service with occasional multi-hour
  outages, not a 24/7 one. State that in the pilot agreement.
- Cloudflare's edge stays up while the origin is down, so staff see a Cloudflare
  error page, not a DNS failure. Configure an external uptime check against
  `/live/` with alerts to the named operator; the Tunnel hides origin outages
  from casual observation.
- A fixed public IP is **not** required: the connector dials out. A CGNAT or
  dynamic-IP connection is fine, and no router port forwarding is needed.
- Internet loss stops Drive publication and ClamAV signature updates as well as
  browser access. Stale signatures fail readiness and quarantine uploads by
  design; that is correct behaviour, not a bug to work around.

### Tunnel limits and configuration

`cloudflared` makes **outbound-only** connections to Cloudflare, so the origin
needs no inbound ports and no public reachability
([Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)).
Publishing a public hostname requires a Cloudflare account and a domain whose
DNS is managed in that **same account**: the `cfargotunnel.com` subdomain only
proxies traffic for DNS records in the same Cloudflare account
([DNS routing](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/)).
Tunnel itself needs no paid Access plan; Cloudflare Access is an optional extra
layer with its own user limits, and the app's own authentication and MFA remain
the control of record.

Known limits to design around, not discover in production:

- 100 MB request body cap (see verdict above).
- About 125 s proxy read timeout, 30 s write timeout (see verdict above).
- Cloudflare terminates public TLS, so SSDC document bytes pass through
  Cloudflare in cleartext at the edge. **This changes the data-processing path
  and must fit SSDC's approved hosting arrangement before any real document is
  uploaded.** It is the main governance difference versus a direct VM.

A Tunnel deployment still needs a separately tested production overlay: keep
origin ports private and bound to loopback, terminate origin TLS or restrict the
connector to localhost, establish canonical host, client-IP and HTTPS trust
through the connector instead of trusting arbitrary forwarded headers, disable
caching for authenticated content, omit OAuth query strings from logs, and test
PDF byte-range requests and uploads through Cloudflare. Public certificate
renewal moves to Cloudflare and **replaces** the direct-edge Certbot procedure
below; the `ssdc-cert-renew` timer is then not applicable. Do not publish the
current development app.

### Google OAuth compatibility

Compatible, with no change to the OAuth design. Google requires an `https://`
redirect URI on a public hostname; a Cloudflare-fronted hostname satisfies this
exactly as a VM would, because Google only sees the public hostname. Conditions:

- Register the callback exactly, including the trailing slash:
  `https://vault.<ssdc-domain>/storage/google/callback/`, and keep
  `PORTAL_HOST`, `ALLOWED_HOSTS`, `HEALTHCHECK_HOST`, `CSRF_TRUSTED_ORIGINS`
  and `GOOGLE_DRIVE_REDIRECT_URI` on that same hostname.
- The OAuth flow is a browser redirect to the public hostname, so it works
  through the Tunnel without inbound ports. Outbound HTTPS to
  `accounts.google.com`, `oauth2.googleapis.com` and `www.googleapis.com` must
  be allowed from the office network.
- While consent is in **Testing**, external users get seven-day Drive refresh
  tokens, which forces weekly reconnection. Set the publishing and audience
  status appropriately before the pilot. Scope stays `drive.file`
  (non-sensitive).
- Caching must stay off for authenticated paths, and the callback query string
  must stay out of Cloudflare and Nginx logs.

### Backups and recovery

Self-hosting removes the provider's safety net entirely: there are no VM
snapshots and no managed database backups. Backups are mandatory, not optional.

- Use the existing paired encrypted backup tooling (`scripts/backup.py` for the
  self-hosted PostgreSQL stack) on a schedule, with the database, the private
  quarantine/legacy volume and the referenced Drive bytes captured together.
- **3-2-1:** one encrypted copy off the machine, one off-site (a second SSDC
  location or encrypted removable media rotated off-site), none of them in the
  same Google account that holds the documents. Drive trash and version history
  are **not** an independent backup.
- Store recovery keys (Django `SECRET_KEY`, MFA key, Drive credential key,
  backup key, OAuth client details) outside the machine, outside Git and
  outside the backup archives. Loss of the MFA or Drive key cannot be repaired
  by restoring PostgreSQL alone.
- Run a complete restore drill into an isolated environment before real
  documents, and repeat it on a fixed schedule. Record RPO and RTO honestly:
  with a nightly backup and one spare machine, realistic RTO is **hours to a
  day**.
- The recovery plan must name a second authorised operator with separately held
  access, and a spare or replacement machine path. A single machine with a
  single operator is a single point of failure for the whole vault.
- Theft or seizure of the physical machine is a real threat here that a cloud VM
  does not have. Full-disk encryption plus a locked room is the minimum.

### What this route costs

No recurring provider charge: Cloudflare Tunnel and the Cloudflare account are
free at this scale, Cloudflare provides the public certificate, and the machine
is already owned. Real costs remain: electricity for a continuously running
machine, the existing office internet connection, eventual hardware
replacement, off-site backup media, and operator time for patches, monitoring,
backups and incident response. These are not zero; they are simply not a
recurring invoice from a hosting provider.

### Domain

Use an existing SSDC-controlled domain where possible and add a subdomain such
as `vault.<ssdc-domain>`. Eligible `.np` registrations, including organisational
extensions, are free under Nepal's registry policy; approval, name eligibility
and documents still apply. [Official registry policy](https://register.com.np/registry-policy).
Whichever domain is used, its DNS must be moved into the same Cloudflare account
as the Tunnel.

### Rejected free hosting options

Free Render is a demo option, not a replacement production server: it sleeps
after 15 minutes idle, has no persistent disk, and its free PostgreSQL database
expires after 30 days. Koyeb's free instance has only 512 MB RAM and also
sleeps, so it cannot host this stack.
[Render free-service limitations](https://render.com/docs/free),
[Koyeb instance limits](https://www.koyeb.com/docs/reference/instances).

### Firebase and serverless are not applicable — correction

Earlier handoff material suggested a Firebase or serverless deployment. **That
is incorrect for this application and must not be attempted.** The reasons are
structural, not preference:

- This is a container stack: Django/Gunicorn, PostgreSQL, Nginx and a
  **long-lived ClamAV daemon** holding a large signature database in memory and
  reloading it on a schedule. Firebase Hosting serves static assets and does
  not run it.
- Serverless containers (Cloud Run and equivalents) provide an **in-memory,
  ephemeral writable filesystem** that does not survive instance shutdown, so
  the private quarantine/legacy volume and the ClamAV signature store have no
  durable home, and writes consume instance memory.
  [Cloud Run overview](https://docs.cloud.google.com/run/docs/overview/what-is-cloud-run).
- Firebase's free **Spark** plan does not deploy Cloud Functions to production
  and blocks outbound network requests to non-Google services; Cloud Functions
  deployment requires the pay-as-you-go **Blaze** plan, which is a billing
  account with usage charges, so it is not zero recurring cost.
  [Firebase pricing](https://firebase.google.com/pricing).
- The scanner, the PostgreSQL session advisory locks used during scan
  processing and the synchronous upload path all assume a persistent process.
  Reworking them to fit a serverless runtime would mean weakening or removing
  malware scanning, which is not acceptable for this vault.

Firebase and serverless are therefore removed from the hosting options, not
deferred.

## Cloud fallback: Oracle Always Free — reconciled allowances

**Reconciliation, 16 October 2026.** Earlier notes and third-party guides
circulate two different Ampere A1 figures (3,000 OCPU-hours / 18,000 GB-hours,
equivalent to 4 OCPUs / 24 GB, versus 1,500 / 9,000, equivalent to 2 OCPUs /
12 GB). Oracle's current official Always Free page states the **lower** figure,
and that is the number to plan against. Verified quotes from
[Oracle Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm):

| Allowance | Official wording (checked 16 October 2026) |
| --- | --- |
| AMD x86 | "All tenancies get up to two Always Free VM instances using the VM.Standard.E2.1.Micro shape, which has an AMD processor." Memory: **1 GB** each. |
| Ampere A1 (Arm) | "All tenancies get the first 1,500 OCPU hours and 9,000 GB hours per month for free for VM instances using the VM.Standard.A1.Flex shape... For Always Free tenancies, this is equivalent to **2 OCPUs and 12 GB of memory**." |
| Storage | "All tenancies receive a total of **200 GB of Block Volume storage**, and five volume backups... These amounts apply to both boot volumes and block volumes combined." |
| Capacity | "If you receive an 'out of host capacity' error... this indicates a temporary lack of Always Free shapes in your home region." |
| Reclamation | "Idle Always Free compute instances may be reclaimed by Oracle" after a 7-day period below 20% CPU, 20% network and (A1 only) 20% memory utilisation. |

The older 4 OCPU / 24 GB figure is **superseded**; treat any document or guide
repeating it as out of date. Note also that the page is internally inconsistent
on default boot volume size (47 GB in the Compute section, 50 GB in the Block
Volume section), so confirm the actual value in the console.

Consequences for this stack:

- The two x86 micro instances have **1 GB RAM each and do not combine**, so the
  x86 Always Free route cannot run the scanner. This is unchanged by the
  reconciliation.
- A1 at 2 OCPUs / 12 GB would fit the stack's memory needs, but it is **ARM64**
  (see the architecture blocker below), and the reclamation rule actively
  penalises a low-traffic internal vault: a quiet document portal can sit under
  20% utilisation for a week and be reclaimed.
- If this route is reconsidered, confirm the account-wide console limits before
  creating anything, and do not select a paid shape or rely on trial credits.

Signup requires an eligible payment card for identity verification; the free tier has no SLA or normal Oracle Support entitlement. This is a conditional pilot option, with independently recoverable backups, rather than a promise of uninterrupted production service. [Oracle Free Tier FAQ](https://www.oracle.com/cloud/free/faq/).

Choose the home region deliberately: it cannot be changed. Compare an available nearby region with SSDC's data-location requirements; do not assume an instance is available in Singapore or India. [Oracle region management](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingregions.htm).

**Architecture blocker:** A1 is ARM64. The currently pinned ClamAV image manifest offers AMD64 only. Before using A1, build and test a native ARM64 scanner variant and verify all four release images and Python dependencies on that architecture. Do not deploy the existing scanner through CPU emulation or disable scanning to make it fit. The ARM release is not yet prepared by this guide.

If free capacity or card verification is unavailable, the SSDC-owned machine
with Cloudflare Tunnel above is the preferred route; it needs power,
connectivity, backups and a network-access plan, but no provider account and no
ARM rebuild. A temporary-credit VM does not meet the ongoing free-hosting
requirement.

## Domain and operator decisions

Use a subdomain of an SSDC-controlled domain, such as `vault.<SSDC-domain>`. This is a placeholder, not an available or registered name. If SSDC already has a domain, adding a DNS record generally avoids buying another one. Otherwise confirm a domain registration route and ownership before creating production OAuth credentials.

Record these before setup:

| Item | Required value |
|---|---|
| Provider account owner | An authorized SSDC custodian |
| Server operator | Named person responsible for patches, SSH, incidents, renewal, and recovery |
| Alternate operator | Authorized recovery contact with separately held access |
| Server architecture and region | Verified from the chosen instance |
| Canonical hostname | Controlled DNS name, not a local address |
| DNS administrator | Person who can create and update records |
| Operator source addresses | Current public IP/CIDR or an approved VPN/bastion |
| Recovery copies | Location outside the server, with separately held keys |

## Network layout

```text
Staff browser -- HTTPS :443 --> Nginx proxy --> Django app :8000
                                               |          |
                                     PostgreSQL :5432   ClamAV :3310
                                               |
                                      Google Drive outbound HTTPS

Operator -- restricted SSH :22 --> Linux host
Certificate authority -- HTTP :80 --> ACME challenge files / HTTPS redirect
```

Only the proxy has published Docker web ports. PostgreSQL, Django, and ClamAV stay on Docker networks without host port mappings. Do not apply `compose.host.yaml` to production.

At the cloud firewall/security-list layer, allow TCP 80/443 from the internet, TCP 22 only from approved operator addresses, and deny other unsolicited inbound traffic. Configure IPv6 consistently if enabled; publish an AAAA DNS record only after IPv6 routing and firewall checks work. Retain required ICMP for network operation.

On Oracle, check effective security lists and network security groups: an additional broad rule can defeat a restricted SSH rule. Do not expose the Docker API.

Docker-published ports can bypass UFW rules. Use the cloud firewall as well as verified Docker-aware host filtering, and keep service ports unpublished. [Docker firewall documentation](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

## Host preparation

Use an eligible supported Ubuntu LTS image. Prefer 24.04 LTS for this runbook if available for the selected architecture. Install security updates, Docker Engine with the Compose plugin from its official repository, Python 3, OpenSSL, and Certbot. Follow the applicable architecture instructions. [Docker Ubuntu installation](https://docs.docker.com/engine/install/ubuntu/).

Create a named operator account with sudo and SSH-key authentication. Verify that account in a **second SSH session** before disabling root/password login or changing firewall rules. Verify provider console recovery access too.

For example, after key access is verified, an operator-owned SSH configuration drop-in can contain:

```text
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
```

Run `sudo sshd -t`, inspect the effective settings with `sudo sshd -T`, then reload SSH and test a fresh login while keeping the existing session open. Do not assume the drop-in overrides earlier cloud-image settings. [Ubuntu OpenSSH guidance](https://ubuntu.com/server/docs/how-to/security/openssh-server/).

Keep application release files at `/srv/ssdc/app` and the private environment at `/srv/ssdc/.env.production`. The renewal service executes code there as root: release scripts and their parent directories must be root-owned and writable only by trusted administrators. Docker access is privileged access; do not give it to staff.

Provision private service secrets according to [DEPLOYMENT.md](DEPLOYMENT.md). Do not upload a dirty workspace wholesale: it contains local credentials and untracked artifacts. Transfer a reviewed release package and import necessary credentials privately. Existing Google client/owner changes require a storage migration plan, not a blind credential swap.

## Initial certificate

Complete DNS first: an A record points the chosen hostname to the server's reachable public IPv4 address. Confirm propagation from outside the server and check any CAA restrictions. At initial issuance, no service should occupy port 80.

On the server, replace the example hostname and email with the actual values:

```sh
sudo install -d -m 0755 /srv/ssdc/acme
sudo install -d -m 0700 /srv/ssdc/tls

sudo certbot certonly --standalone --preferred-challenges http \
  --cert-name vault.example.org -d vault.example.org \
  --email operator@example.org --agree-tos --non-interactive

sudo python3 /srv/ssdc/app/scripts/install_tls.py \
  --hostname vault.example.org \
  --lineage /etc/letsencrypt/live/vault.example.org
```

The installer checks hostname, remaining validity, and certificate/private-key match. It stores a private certificate pair and switches one directory pointer so Nginx sees a consistent pair. Initial installation does not try to reload a proxy that has not started.

For an existing TLS directory with unmanaged files, use a new dedicated directory and update the mount before starting the proxy. The installer deliberately refuses to overwrite an unmanaged pair.

Set these in the private production environment alongside the existing release/secret settings:

```dotenv
PORTAL_HOST=vault.example.org
ALLOWED_HOSTS=vault.example.org
HEALTHCHECK_HOST=vault.example.org
CSRF_TRUSTED_ORIGINS=https://vault.example.org
GOOGLE_DRIVE_REDIRECT_URI=https://vault.example.org/storage/google/callback/
TLS_DIRECTORY=/srv/ssdc/tls
TLS_CERT_FILE=/srv/ssdc/tls/cert.pem
TLS_KEY_FILE=/srv/ssdc/tls/key.pem
ACME_WEBROOT=/srv/ssdc/acme
HTTPS_PORT=443
```

Use both Compose files for this hosting configuration:

```sh
cd /srv/ssdc/app
sudo docker compose --env-file /srv/ssdc/.env.production \
  -f compose.prod.yaml -f deploy/compose.acme.yaml config --quiet
```

Apply the verified release's database and role setup from the deployment guide before starting the app/proxy. Reuse the two-file command prefix for subsequent service operations. Restrict web ingress to pilot/test addresses until release gates are satisfied; opening a host does not approve confidential uploads.

## Automatic renewal without stopping the app

The optional ACME overlay mounts a challenge-only directory read-only in Nginx. The canonical HTTP server serves `/.well-known/acme-challenge/` from it and redirects other paths to HTTPS. Unknown hostnames remain rejected.

Create root-owned `/etc/ssdc-hosting.conf` with mode `0600`:

```dotenv
SSDC_PORTAL_HOST=vault.example.org
```

Install the supplied units:

```sh
sudo install -m 0644 /srv/ssdc/app/deploy/systemd/ssdc-cert-renew.service /etc/systemd/system/
sudo install -m 0644 /srv/ssdc/app/deploy/systemd/ssdc-cert-renew.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

First validate the running webroot with a Certbot staging renewal:

```sh
sudo certbot renew --cert-name vault.example.org \
  --webroot --webroot-path /srv/ssdc/acme --dry-run
```

This tests issuance without installing a staging certificate. Separately test the reload hook using the current valid production lineage:

```sh
sudo python3 /srv/ssdc/app/scripts/install_tls.py \
  --hostname vault.example.org \
  --lineage /etc/letsencrypt/live/vault.example.org --reload-proxy

sudo systemctl enable --now ssdc-cert-renew.timer
sudo systemctl start ssdc-cert-renew.service
sudo systemctl list-timers ssdc-cert-renew.timer
```

The timer explicitly uses webroot renewal even though the first issuance used standalone. Its deploy hook verifies and installs the renewed pair, runs `nginx -t`, and requests a graceful reload. If that command fails, the installer restores the previous pair pointer and returns a failure. It does not prove the public endpoint has adopted the new certificate; verify that externally.

Use one renewal scheduler for this lineage. After this timer passes, remove/disable overlapping Certbot cron/timer scheduling only if no other certificates depend on it. Do not disable unrelated renewal jobs. Keep DNS and port 80 functional for HTTP-01 renewal. [Certbot renewal and hooks](https://eff-certbot.readthedocs.io/en/stable/using.html).

Configure failure alerts to the named operator and monitor certificate expiry independently. Inspect `journalctl -u ssdc-cert-renew.service` after failures. Retain the prior valid pair for recovery; certificate version directories need controlled periodic housekeeping.

## External acceptance and handover

- Verify a trusted HTTPS chain and expected hostname from an external network, with no browser exceptions.
- Follow HTTP redirects and confirm they remain on the canonical hostname.
- Verify ACME challenge delivery and that unrelated HTTP requests redirect.
- Verify only 80/443 are publicly reachable and SSH is reachable only from approved sources. Test IPv4 and IPv6 separately where enabled.
- Confirm there are no published ports for 5432, 3310, 8000, or the Docker API.
- Confirm a fresh operator-key login works and root/password logins are rejected as intended.
- Verify renewal dry run, reload, timer persistence, alerts, and externally served certificate validity.
- Record image architecture, identifiers, server resources, domain ownership, operator/recovery contacts, and renewal evidence.
- Complete the application release checklist, restore drill, and small staff pilot before general staff access.

## Current status

The repository now includes the ACME route/overlay, a certificate-pair installer, and renewal timer templates. Actual provider signup, ARM64 scanner support, hostname ownership, server provisioning, DNS, certificate issuance, and external acceptance remain to be completed. No paid service has been selected or purchased.

**16 October 2026.** The self-hosted machine plus Cloudflare Tunnel route was
evaluated against official sources and documented above. Nothing has been
provisioned, published or connected: no Cloudflare account or tunnel, no DNS
record, no certificate, no remote database change. Oracle's Always Free
allowances were reconciled against Oracle's current documentation. Firebase and
serverless were removed as structurally incompatible with this stack. Open items
for this route: machine confirmation against the hardware table, hostname and
Cloudflare DNS, SSDC approval for Cloudflare TLS termination, a tested Tunnel
production overlay, off-site backup and restore drill, and the application
release gate (including the open zlib finding in
[PILOT_IMAGE_AUDIT.md](PILOT_IMAGE_AUDIT.md)) before any real document.

Local preparation checks passed: four real-certificate Linux installer tests
(pair rotation, invalid-pair rejection, unmanaged-file preservation, and failed
reload rollback), five deployment-configuration tests, and an isolated Linux
Nginx check for ACME delivery, canonical redirects, unknown-host rejection, and
configuration validity. Proxy evidence: `artifacts/hosting-proxy-check.json`.
These are local checks, not Oracle ARM execution, public DNS/TLS acceptance, or
proof that a host renewal timer is operating.
