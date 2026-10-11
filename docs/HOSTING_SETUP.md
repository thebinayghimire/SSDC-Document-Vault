# Hosting setup — free-first plan

Prepared 7 October 2026 (Asia/Kathmandu). **No cloud server, domain, or live certificate has been provisioned.** This guide prepares the hosting layer; application release approval remains governed by [DEPLOYMENT_FIXES.md](../DEPLOYMENT_FIXES.md).

## Hosting choice

**Latest preference:** the Oracle website is too slow for the user to complete
setup. The user has confirmed there is no spare office computer and requires
cloud hosting. The user has corrected the earlier eligibility statement:
**SSDC is not a nonprofit. Remove nonprofit grants from the hosting plan.**
No provider or subscription has been selected or provisioned. The remaining
cloud routes are Oracle's eligible ongoing free allocation, a time-limited
Google/AWS trial for a pilot, or a paid server if the budget changes.

### Next actions for the corrected hosting plan

1. Choose between an eligible temporary cloud pilot and revisiting Oracle setup.
   Do not describe trial-funded hosting as permanently free production hosting.
2. Before provisioning a trial VM, estimate compute, disk, public IP, transfer,
   and backup costs together, and record an exit/restore date before expiry.
3. Supply only non-secret setup details: proposed region, controlled domain if
   any, and operator identity. No passwords or private keys belong in chat.

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

### Alternative: existing office computer with Cloudflare Tunnel

Run the production Docker services on a dedicated Linux computer. For remote
browser access, use a stable hostname on a domain controlled by SSDC and a named
Cloudflare Tunnel. Cloudflare provides the public HTTPS endpoint; the connector
makes outbound connections, so the office does not need router port forwarding
or a publicly reachable origin. Publishing through Tunnel does not require a
paid Access plan. [Cloudflare Tunnel architecture](https://developers.cloudflare.com/tunnel/),
[published applications](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/).

This avoids server rental, but electricity, connectivity, hardware, backups, and
operator time remain real costs. The vault is unavailable while the computer
sleeps, loses power, or loses internet. Prefer a dedicated machine with restart
after power loss and reliable power rather than a daily-use laptop.

Use an existing authorized domain where possible. Eligible `.np` registrations,
including organizational extensions, are free under Nepal's registry policy;
approval, name eligibility, and documents still apply. [Official registry policy](https://register.com.np/registry-policy).

Tunnel deployment needs a separate tested production overlay: keep origin ports
private, establish canonical host/client-IP/HTTPS trust through the connector,
disable caching for authenticated content, omit OAuth query strings from logs,
and test PDF byte ranges and uploads through Cloudflare. Do not publish the
current development app. Use its existing portal authentication; Cloudflare
Access is an optional additional layer with separate user limits. Cloudflare
terminates public HTTPS, so this also changes the document-data processing path
and must fit SSDC's approved hosting arrangement.

Public certificate renewal at Cloudflare would replace the direct-edge Certbot
procedure below. Origin TLS, DNS/OAuth migration, backup recovery, alerts, and
release verification remain required. This alternative has not been configured
or published.

Free Render is a demo option, not a replacement production server: it sleeps
after 15 minutes idle, has no persistent disk, and its free PostgreSQL database
expires after 30 days. Koyeb's free instance has only 512 MB RAM and also sleeps,
so it cannot host the current complete stack within its allocation.
[Render free-service limitations](https://render.com/docs/free),
[Koyeb instance limits](https://www.koyeb.com/docs/reference/instances).

### Original cloud candidate: Oracle

The user's budget is **free hosting**. The original candidate was Oracle Cloud Always Free **VM.Standard.A1.Flex**, using an eligible Ubuntu image, 2 OCPUs, and 12 GB RAM. If this route is reconsidered, start with a 100 GB boot volume and confirm the account-wide console limits before creating anything. Do not select a paid shape or rely on trial credits.

Oracle's current documentation lists 1,500 OCPU-hours and 9,000 GB-hours monthly, equivalent to 2 OCPUs/12 GB for an Always Free tenancy, and 200 GB total eligible boot/block storage in the home region. Capacity can be unavailable and idle instances can be reclaimed. [Oracle Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm).

Signup requires an eligible payment card for identity verification; the free tier has no SLA or normal Oracle Support entitlement. This is a conditional pilot option, with independently recoverable backups, rather than a promise of uninterrupted production service. [Oracle Free Tier FAQ](https://www.oracle.com/cloud/free/faq/).

Choose the home region deliberately: it cannot be changed. Compare an available nearby region with SSDC's data-location requirements; do not assume an instance is available in Singapore or India. [Oracle region management](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingregions.htm).

**Architecture blocker:** A1 is ARM64. The currently pinned ClamAV image manifest offers AMD64 only. Before using A1, build and test a native ARM64 scanner variant and verify all four release images and Python dependencies on that architecture. Do not deploy the existing scanner through CPU emulation or disable scanning to make it fit. The ARM release is not yet prepared by this guide.

If free capacity or card verification is unavailable, reassess hosting. A continuously running SSDC-owned Linux machine is another possibility, but requires power, connectivity, backups, and a network-access plan. A temporary-credit VM does not meet the ongoing free-hosting requirement.

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

Local preparation checks passed: four real-certificate Linux installer tests
(pair rotation, invalid-pair rejection, unmanaged-file preservation, and failed
reload rollback), five deployment-configuration tests, and an isolated Linux
Nginx check for ACME delivery, canonical redirects, unknown-host rejection, and
configuration validity. Proxy evidence: `artifacts/hosting-proxy-check.json`.
These are local checks, not Oracle ARM execution, public DNS/TLS acceptance, or
proof that a host renewal timer is operating.
