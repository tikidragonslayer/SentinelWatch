# SentinelWatch

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Upstream: MIT](https://img.shields.io/badge/upstream-MIT-green.svg)](https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG)
[![Platform: macOS / Pi](https://img.shields.io/badge/platform-macOS%20%7C%20Raspberry%20Pi-lightgrey.svg)](#deployment)

**Wi-Fi surveillance detection for people who think they might be followed.**

SentinelWatch monitors nearby wireless devices via [Kismet](https://www.kismetwireless.net/) packet capture and flags devices that reappear across multiple time windows or geographic locations — the digital signature of a stalker, a hostile surveillance team, or a malfunctioning IoT device that just won't stop probing.

> **What this is**: a tool for people with a credible threat model — domestic-violence survivors, journalists, activists, abuse victims, security researchers, executive-protection details — to detect Wi-Fi-emitting devices following them across locations.
>
> **What this is not**: a stalking tool, a tool for monitoring people who haven't consented, or a substitute for actual operational security advice. See [Ethics & Lawful Use](#ethics--lawful-use) below.

---

## Upstream

SentinelWatch is a fork of [**ArgeliusLabs/Chasing-Your-Tail-NG**](https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG) (CYT-NG) by [@matt0177](https://github.com/matt0177), originally released under the MIT license. Significant credit goes to the upstream authors for the core Wi-Fi probe-request analysis engine.

This fork adds:

- **PDF intelligence reports** — one-click "Surveillance Audit Reports" with critical alerts, top suspects, and timeline analysis.
- **Live web dashboard** with Leaflet.js dark-mode maps for spatial visualization.
- **Multi-channel alerting** — branded HTML emails (Resend.io) and SMS (Twilio).
- **Multi-location stalker detection** — devices that reappear across geocoded locations, ranked by encounter frequency.
- **Screensaver Detection Mode (macOS)** — autonomous scanning when the system goes idle.
- **Security hardening** — parameterized SQL, input validation, encrypted credential storage.
- **System-health telemetry** — CPU/RAM/disk/thermal monitoring on the dashboard.

See [`NOTICE`](NOTICE) for full attribution and licensing details.

---

## License

SentinelWatch is dual-license-aware:

- New contributions in this fork are licensed under [**AGPL-3.0-or-later**](LICENSE).
- Upstream code from CYT-NG remains under [**MIT**](LICENSE-UPSTREAM-MIT) (notice preserved).

The combined work is distributed under AGPL-3.0. **Anyone who modifies SentinelWatch and runs it as a network service is required to publish their modified source under the same license.** This is intentional — surveillance-detection tooling should not be enclosed by closed forks.

If you have a use case that requires different terms (e.g. embedding SentinelWatch into a closed commercial product), open an issue to discuss commercial dual-licensing.

---

## Ethics & Lawful Use

SentinelWatch is a **passive defensive tool**. It listens to publicly broadcast Wi-Fi probe requests — frames that any device near you is already shouting into the air. It does not deauthenticate, jam, decrypt traffic, or interact with any device.

That said, this kind of tooling can be misused. Before deploying SentinelWatch, you should know:

- **Local laws on wireless monitoring vary.** In most jurisdictions, passive packet capture in public is legal; in some it is restricted. **You are responsible for ensuring your use is lawful in your jurisdiction.**
- **Do not deploy SentinelWatch in places where you do not have a reasonable expectation of privacy** (e.g. covertly installed at a friend's house, a workplace you don't own, etc.). Operate it on your own devices, in your own spaces.
- **Probe requests can deanonymize people** — they often contain SSIDs the device has connected to in the past, which can reveal where someone has been. Treat captured data as sensitive PII. Do not publish it. Do not share captures with third parties without consent.
- **This is not a substitute for real OPSEC.** If you believe you are being targeted by a state-level adversary, professional surveillance team, or domestic abuser with technical capability, please consult a security professional. Tools like [Access Now's Digital Security Helpline](https://www.accessnow.org/help/) and the [Electronic Frontier Foundation's Surveillance Self-Defense](https://ssd.eff.org/) are good starting points.

We will not knowingly merge contributions whose primary purpose is to enable surveillance of non-consenting parties.

---

## How it works

```
   ┌──────────┐    ┌─────────────────┐    ┌─────────────────┐
   │  Kismet  │───▶│  SentinelWatch  │───▶│   Dashboard     │
   │ (capture)│    │  (correlation)  │    │  (visualization)│
   └──────────┘    └─────────────────┘    └─────────────────┘
                            │                       │
                            ▼                       ▼
                   ┌─────────────────┐    ┌─────────────────┐
                   │   PDF Reports   │    │ Email/SMS Alerts│
                   └─────────────────┘    └─────────────────┘
```

1. **Kismet** captures Wi-Fi management frames (probes, beacons, association requests) and writes them to a local SQLite database.
2. **SentinelWatch** queries that database every 60 seconds across overlapping time windows (5/10/15/20 min). Devices that reappear across multiple windows are flagged as **persistent**.
3. With GPS data (Bluetooth GPS, phone tether, or manual coordinates), SentinelWatch correlates persistent devices to **physical locations** and detects multi-location follows.
4. A scoring model assigns each suspect a **persistence score (0.0–1.0)** combining temporal regularity, location count, signal strength patterns, and SSID probe content.
5. Alerts above a configurable threshold trigger email/SMS/dashboard notifications.

---

## Quick start

### Raspberry Pi 4/5 (recommended deployment)

```bash
# 1. Install Kismet
sudo apt install kismet

# 2. Clone SentinelWatch
git clone https://github.com/tikidragonslayer/SentinelWatch.git
cd SentinelWatch

# 3. Install Python dependencies + run secure setup
pip3 install -r requirements.txt
python3 setup_wizard.py

# 4. Migrate any existing API keys to the encrypted credential store
python3 migrate_credentials.py        # only if you had a config.json before

# 5. Start
./start.sh
```

### macOS (development / portable use)

```bash
git clone https://github.com/tikidragonslayer/SentinelWatch.git
cd SentinelWatch
chmod +x start.sh
./start.sh
```

The setup wizard will install Homebrew (if missing), Python `venv`, and all dependencies. Detailed setup notes are in [`SETUP.md`](SETUP.md).

---

## Configuration

All configuration lives in `config.json` (created on first run). Sensitive values (Resend.io API keys, Twilio tokens, WiGLE credentials) are encrypted via `secure_credentials.py` using a master password — they are never written to disk in plaintext.

Key configuration sections:

```jsonc
{
  "alerts": {
    "dashboard_url": "https://your-dashboard.example",   // optional, used in email/SMS footer
    "resend": { "enabled": false, "api_key": "...", "from_email": "...", "to_email": "..." },
    "twilio": { "enabled": false, "account_sid": "...", "auth_token": "...", "from_number": "...", "to_number": "..." }
  },
  "kismet": { "db_path_pattern": "/var/lib/kismet/*.kismet" },
  "wigle":  { "enabled": false, "username": "...", "token": "..." },
  "windows": { "recent_min": 5, "medium_min": 10, "old_min": 15, "oldest_min": 20 }
}
```

CORS for the dashboard can be extended with the `SENTINELWATCH_CORS_ORIGINS` env var (comma-separated).

---

## Status & roadmap

This release inherits CYT-NG's mature Wi-Fi correlation engine and adds the SentinelWatch-specific reporting/alerting/dashboard layer on top. It has been used in real defensive deployments, but it has not been independently security-audited.

Roadmap (open to PRs):

- Conformance with current MAC-randomization recommendations
- Bluetooth LE detection alongside Wi-Fi
- ESP32-based portable sensor variant
- TLS-protected dashboard out of the box
- Independent security review of `secure_credentials.py` and `secure_database.py`

---

## Contributing

Contributions welcome — particularly:

- Independent security review of the credential and database layers
- Additional notification channels (Signal, Matrix, Telegram bot, etc.)
- Detection-evasion research (we want to know what *defeats* SentinelWatch so we can improve it)
- Documentation translations
- Threat model improvements

By contributing, you agree to license your contribution under AGPL-3.0-or-later.

If you have a security-sensitive finding, please use GitHub's private security advisory feature instead of a public issue.

---

## Acknowledgements

- [@matt0177](https://github.com/matt0177) and [ArgeliusLabs](https://github.com/ArgeliusLabs) for the upstream CYT-NG project this is built on.
- The [Kismet](https://www.kismetwireless.net/) team for the underlying capture engine.
- The defensive-security community for years of research into Wi-Fi probe analysis and surveillance detection.
