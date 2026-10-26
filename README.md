# Linux Security Labs

Two hands-on labs covering the operational side of Linux administration: hardening a
fresh Ubuntu server and automating verified backups.

| Lab | Focus | Stack |
|---|---|---|
| [Lab 05 — Linux Server Hardening](lab05-linux-hardening/) | SSH key-only access, root lockout, UFW, permissions, service reduction | Bash · OpenSSH · UFW · systemd |
| [Lab 06 — Automated Backup System](lab06-automated-backup/) | Timestamped archives, integrity checks, retention, cron scheduling | Bash · tar · gzip · SHA-256 · cron |

## Repository layout

```
.
├── lab05-linux-hardening/
│   ├── README.md
│   └── hardening.sh
└── lab06-automated-backup/
    ├── README.md
    └── backup.sh
```

Both scripts are standalone, idempotent, support `--dry-run`, and were validated on
Ubuntu 24.04 LTS (WSL2 and disposable containers). Each lab README documents the
design, usage, and verification steps.

> ⚠️ Run these scripts on a lab machine or VM. Hardening changes SSH access and firewall
> rules; always keep a console session open until a new SSH connection has been tested.
