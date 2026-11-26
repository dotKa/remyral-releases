# Installing and upgrading Remyral (self-hosted)

- **Applies to:** a customer installing the Remyral control plane for one company on their own Linux server
- **Turkish version:** [docs/guide/tr/kurulum.md](../guide/tr/kurulum.md) (shipped in every release as `KURULUM.md`)
- **Design / decision:** [p16-selfhost-onboarding](../design/p16-selfhost-onboarding.md), [ADR-0063](../adr/0063-selfhost-distribution-and-update-trust.md)

The control plane (console, API, database, queue, backups) runs on **one Linux server**. Agents do not run there: they
run on your machines (Linux, macOS, Windows, Raspberry Pi), which connect outbound to the server.

## 1. System requirements

| | Minimum | Recommended |
| --- | --- | --- |
| OS | Linux, x86_64 or aarch64 (Ubuntu 22.04+, Debian 12+, RHEL / Rocky / Alma 9+) | Ubuntu 24.04 LTS |
| CPU / memory | 2 vCPU, 4 GiB | 4 vCPU, 8 GiB |
| Disk (data directory) | 10 GiB free | 20 GiB+ (backups grow with the database) |
| Software | Docker Engine ≥ 24 with the compose plugin ≥ 2.24, OpenSSL ≥ 3, curl | — |
| Network | a DNS name for the console; ports 80 + 443 (Let's Encrypt / Cloudflare) or one HTTPS port behind your proxy | outbound HTTPS to your release URL and registry |

**Not supported for the control plane:** Windows and macOS (also not Docker Desktop on them). They are fully supported
as **worker machines** (Makineler → Makine ekle). The installer refuses other systems.

## 2. Install

1. Point the DNS name (e.g. `remyral.example.com`) at the server.
2. Download the installer of the release and check it. The official release channel is
   `https://releases.remyral.com/control-plane`; the current release is **0.9.0** (the first public release, before
   1.0), signed with the release key **`9439dfaca133e249`** (the key id is also in each release announcement on
   GitHub):

   ```sh
   curl -fsSLO https://releases.remyral.com/control-plane/0.9.0/install.sh
   # the key id of the release key the installer trusts — must print 9439dfaca133e249:
   k="$(sed -n "s/^REMYRAL_TRUSTED_KEYS='\([^ ']*\).*/\1/p" install.sh)"
   printf '%s=' "$k" | tr '_-' '/+' | base64 -d | sha256sum | cut -c1-16
   sudo bash install.sh --dry-run --domain remyral.example.com --tls letsencrypt --email ops@example.com
   ```

   `--dry-run` downloads the release, verifies its signature and every file, and prints each step without changing
   anything. A channel of your own works the same way (`--release-url https://<release-url>`).

3. Run it as root. Pick one TLS mode:

   ```sh
   # A) This server answers on 80/443 itself; Let's Encrypt issues the certificate.
   sudo bash install.sh --domain remyral.example.com --tls letsencrypt --email ops@example.com

   # B) DNS proxied by Cloudflare (SSL mode "Full", or "Full (strict)" with an origin certificate).
   sudo bash install.sh --domain remyral.example.com --tls cloudflare \
     [--tls-cert origin.pem --tls-key origin.key]

   # C) Your own reverse proxy terminates TLS and forwards to this server.
   sudo bash install.sh --domain remyral.example.com --tls proxy --https-port 8443 --http-port 8080 \
     --bind 10.0.0.5 --trusted-proxy 10.0.0.2/32
   ```

   Useful flags: `--data-dir /srv/remyral` (default `/var/lib/remyral`), `--version 1.2.0` (default: the newest
   release), `--registry registry.example.com/remyral` (your mirror; digests are kept), `--bundle <dir>` (an offline
   copy of a release directory), `--backup-recipient age1…` (your age public key: backups then also carry the
   encrypted key files), `--no-update-check`, `--dry-run` (checks, verifies and prints every step, changes nothing),
   `--yes` (no questions).

4. What it does: checks the prerequisites; downloads the release and **verifies its signature and every file** (it
   stops before changing anything if that fails); creates the data directory; generates the database / Redis passwords
   and key files once (never printed; `stack.env` is root-only); writes the proxy configuration; pulls the images **by
   digest**; migrates the database; starts the stack; waits for the health check; prints a **one-time setup token**.
5. Open `https://remyral.example.com/setup`, enter the token, choose the owner's username and password. Then sign in:
   the first sign-in connects your authenticator app and shows 10 recovery codes — keep them off the phone.
6. The **setup wizard** (Kurulum sihirbazı) opens for the owner: organisation name, security preset, the first
   machine (install command per OS), git connection, optional integrations, the first project and a sample job. Every
   step can be skipped and resumed later (home page → "Kurulumu tamamla").

A new install starts on the **Dengeli** (Balanced) security preset (migration 0221): a code holds for 4 hours and is
asked for credentials, logins, the sandbox, machine administration, production deploys, integrations, releases and MCP
installs besides the safe core; deploys, force push, deletes outside the workspace and secret reads still ask a human.
**Serbest** (Free) waives the code for everything outside the safe core — enabling machine administration, removing the
sandbox, approving machines, production deploys, credentials, integrations — and with "remember this device" one code
at sign-in covers the session; choose it only for a single-person, closed installation. **Sıkı** (Strict) asks for a
code for every privileged action within 10 minutes. The default applies to new installations; an upgrade never
changes a configured preset.

Lost the setup token before creating the owner? `sudo remyral-ctl setup-token` prints a new one. After an account
exists, access recovery is `docker compose … exec -it master remyral-master admin:reset` (docs/ops/admin-bootstrap.md).

Re-running the installer is safe: it keeps the secrets and the choices of the first run and only re-applies the same
release. Change the ports by re-running with the new flags.

### Domain

Change the console's domain (and the TLS mode or the Let's Encrypt e-mail) in the console, no terminal: **Kurulum
sihirbazı → Alan adı ve erişim** (owners; the authenticator code when the security policy asks — event "Konsolun genel
adresini değiştirme"). Point the new name's DNS record at the server first; "DNS’i denetle" tells you whether it does.
"Kaydet ve uygula" hands a request signed by the master to the server: `remyral-ctl apply-pending` (a root systemd path
unit + a one-minute timer the installer sets up) checks the signature and the values, switches the proxy, gets the
certificate (Let's Encrypt), and keeps the old name answering until the new one is healthy (and an hour after). If the
new name is not healthy within 5 minutes it switches back by itself; the wizard shows "Uygulanıyor… / Hazır / Hata: …".
The applier only ever changes the domain, TLS mode and ACME e-mail (ADR-0063 amendment 2026-10-24).
`remyral-ctl status` shows the last change; `<data>/state/domain-history` lists them. Without systemd, run
`remyral-ctl apply-pending` every minute from root's crontab. Installs not made with remyral-ctl (routing done by
another platform) store the address for links only; the wizard says what to route.

## 3. Upgrade

The console shows owners **"Güncelleme mevcut"** when a newer signed release exists (Notlar: notes, breaking changes,
the command). The upgrade itself always runs on the server — started either from the console or by hand:

- **From the console (p17-host-actions):** Ayarlar → Sürümler → **Sunucu** (owners; the banner's "Şimdi güncelle" opens
  it): choose the version (breaking changes must be confirmed), "Şimdi güncelle", enter the authenticator code. The
  console leaves a request signed by the master; `remyral-ctl apply-pending` (root, the same units as the domain change)
  verifies it and runs exactly `remyral-ctl upgrade --to <version>` below. The page shows each step, says "Sunucu
  yeniden başlıyor" while the master is stopped, reconnects and shows the result. "Geri al" goes back to a release still
  on the server, optionally restoring a backup first (the backup id typed again, a second confirmation). The applier
  needs this release of `remyral-ctl`: the first upgrade to it is done by hand (`sudo remyral-ctl upgrade`); after that
  the console can do the next ones.
- **By hand:**

```sh
sudo remyral-ctl upgrade --check          # is there a newer release?
sudo remyral-ctl upgrade --dry-run        # print every step
sudo remyral-ctl upgrade [--to 1.3.0]     # verify → pull → stop master → backup → migrate → start → health check
```

- A release with breaking changes asks for confirmation (`--yes` to confirm non-interactively).
- The pre-upgrade backup is mandatory (it fails → nothing changes and the master starts again); `--skip-backup` only
  deliberately.
- **Health check fails and the database schema did not change:** the old release is started again automatically.
- **Health check fails after the schema advanced:** the new release stays (the old one would refuse the newer schema)
  and the command prints the way back:

  ```sh
  sudo remyral-ctl rollback --to 1.2.0 --restore-backup remana-prod-20261023T120000Z
  ```

  This restores the pre-upgrade database (the replaced one is kept as `remyral_replaced_<time>`) and starts 1.2.0.
- Machines update themselves; the release notes name the minimum worker version.

`sudo remyral-ctl status` shows the release, the schema, every container and whether an update is available;
`sudo remyral-ctl doctor` runs the doctor checks from the server (the full run with the machines: Ayarlar → Tanılama).

## 4. Backups and restore

- A backup service runs in the stack: nightly database dump + restore drill, status in Ayarlar → Yedekler. Details and
  off-site copies (S3 / R2): [backup-restore.md](backup-restore.md) §3.
- **From the console (p17-host-actions):** Ayarlar → Yedekler → Yedekleri yönet (owners): "Şimdi yedek al" (with a
  reason), a restore drill, the schedule / retention / drill / WAL archiving / encryption recipients (at least two age
  public keys — make the private ones offline with `age-keygen`), the off-site target (tested, stored encrypted, written
  into `backup-config/offsite.env` on the server) and a restore of a listed backup. The server applies the settings
  into `stack.env` (`BACKUP_*`, `PG_WAL_ARCHIVE`) and `backup-config/recipients.txt` and restarts the backup service;
  your own edits of those keys are overwritten by the next change from the console.
- **72-hour time lock (p17-panel-settings Part 0, [ADR-0063](../adr/0063-selfhost-distribution-and-update-trust.md)):**
  a console request that **adds** an encryption recipient or **changes** the off-site target (bucket, endpoint, region,
  access key, or a first target) is applied by the server only 72 hours after it first saw it (its own clock). Until
  then backups keep their current recipients and target. Every owner is notified (in the console and by e-mail) and
  reminded 24 h before; the console shows "Bekleyen yedek değişiklikleri" with **İptal et**. On the server:

  ```sh
  sudo remyral-ctl status                       # WAITING … takes effect <time>
  sudo remyral-ctl backup-change show           # what waits, until when
  sudo remyral-ctl backup-change cancel         # withdraw it (not yours? check who has owner access)
  sudo remyral-ctl backup-change confirm --yes  # yours: apply it now instead of waiting
  ```

  Removing a recipient, retention, schedule, drill, WAL and turning the off-site copy off stay immediate.
- Manual backup: `sudo remyral-ctl backup`; drill: `sudo remyral-ctl drill [--backup <id>]`; restore with the running
  release: `sudo remyral-ctl restore --backup <id> --yes`.
- **Back up off the server** (password manager / secret store): `<data>/stack.env` and `<data>/secrets/` (without
  `totp.key` every authenticator must be re-enrolled). With `--backup-recipient` the backups carry them encrypted.
- Restore on the same server: `sudo remyral-ctl rollback --to <current or older version> --restore-backup <id>`
  (ids: `docker exec $(docker ps -qf label=com.docker.compose.service=backup) remyral-backup list`). Restore onto a new
  server: [backup-restore.md](backup-restore.md) §5.

## 5. Uninstall

```sh
sudo remyral-ctl uninstall                 # stop and remove the containers; the data directory stays
sudo remyral-ctl uninstall --purge-data    # also deletes the database, backups and keys (cannot be undone)
```

Images stay in Docker's cache (`docker image prune -a`).

## 6. Files and ports

| Path / port | What |
| --- | --- |
| `/usr/local/bin/remyral-ctl` | the CLI (from the installed release) |
| `<data>/stack.env` | settings and passwords (root, 0600) |
| `<data>/secrets/` | the master's key files (uid 10001, 0400) |
| `<data>/release/<version>/` | the verified release files (three kept) |
| `<data>/backups/` | backups |
| `<data>/trust/keys` | the release keys this installation trusts |
| `<data>/host/requests/`, `<data>/host/status/` | domain change requests from the master (signed), the applier's heartbeat and results |
| 80 / 443 (or your ports) | Traefik; nothing else is published |

## 7. Troubleshooting

| Message | Meaning / fix |
| --- | --- |
| `SIGNATURE CHECK FAILED` / `INTEGRITY CHECK FAILED` | the download is not what the vendor signed — do not override; re-download, check the release URL / mirror |
| `prerequisite check(s) failed` | install the missing piece; `--skip-checks` only if you know why |
| `the stack is not healthy` | `docker compose -p remyral-prod logs master web proxy`; Let's Encrypt needs ports 80/443 reachable from the internet |
| `another remyral-ctl is running` | wait, or remove `<data>/.lock` if no remyral-ctl runs |
