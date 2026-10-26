# Lab 05 — Linux Server Hardening

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu&logoColor=white&style=flat-square)
![Bash](https://img.shields.io/badge/Bash-5.x-4EAA25?logo=gnubash&logoColor=white&style=flat-square)
![Security](https://img.shields.io/badge/Security-Hardened-2ea44f?style=flat-square)
![UFW](https://img.shields.io/badge/UFW-Active-2C3E50?style=flat-square)

`hardening.sh` turns a stock Ubuntu 24.04 server into one I would actually expose to the internet: a single named admin account, key-only SSH, no root login, and a firewall that drops everything except port 22. It is idempotent and validates `sshd` before every reload, so a second run is safe and a fresh machine only needs one command.

## Key Security Controls

| Control Metric | Before Hardening | After Hardening |
|---|---|---|
| **SSH Root Access** | `PermitRootLogin yes`; root can log in with a password | `PermitRootLogin no` plus `passwd -l root` — no superuser session left to steal |
| **Password Auth** | Passwords accepted over SSH | `PasswordAuthentication no`, `AuthenticationMethods publickey` — removes the credential-stuffing surface |
| **UFW Firewall** | Inactive; every listening service is reachable | Default `deny incoming`, only `22/tcp` allowed and rate-limited — one port to defend |
| **Privileges (`sysadmin_sec`)** | Everyone logs in as root; no accountability | Named `sysadmin_sec` uses sudo, every command lands in `auth.log` — actions are attributable |
| **File Permissions** | `~/.ssh` is 755, keys are readable | `~/.ssh` 700, `authorized_keys` 600, home 750 — sshd's own strict-mode checks are satisfied |
| **Umask (`027`)** | `022` leaves new files world-readable | `027` creates files as 640 and directories as 750 — least privilege by default |

None of these controls is exotic on its own. What matters is that they are applied together, in the right order, and verified: UFW opens port 22 *before* it is enabled, `sshd -t` runs *before* any reload, and every file the script touches is backed up first. That is the difference between a hardening checklist and a hardening tool.

## Quick Start

```bash
git clone https://github.com/marwane5h/lab05-linux-hardening.git
cd lab05-linux-hardening
chmod +x hardening.sh
sudo ./hardening.sh --force
```

> `--force` bypasses the "do you already have an SSH key?" guard. Keep a console session open, or make sure a key is deployed before running it — otherwise you can lock yourself out. `--dry-run` prints every change first.
>
> The script assumes Ubuntu 24.04 with `sudo` and `openssh-server`, and installs either one if it is missing. Use `--check` for a read-only audit, or `--only ssh,ufw` to change one layer at a time.

## Verification & Evidence

Here is what I check after a run — the firewall first, then whether root can still get in:
<img width="932" height="68" alt="permision denied" src="https://github.com/user-attachments/assets/65a8e8d7-1121-4266-912b-2c2fcced3eed" />
<img width="662" height="194" alt="ufw" src="https://github.com/user-attachments/assets/d22e581a-f87c-4ea3-bda7-fef8684b9ef3" />
<img width="943" height="95" alt="publikey" src="https://github.com/user-attachments/assets/ef99a1bd-b30d-4bf7-a3b4-ac8f5c8ecaed" />

## Key Engineering Takeaways

- **Smaller blast radius, by default.** One reachable port and no root login mean an attacker must clear key authentication before they can see anything else. UFW's default-deny is the backstop when a new service starts listening by accident.
- **Accountability beats shared root.** `sysadmin_sec` with sudo gives every privileged action a name and a timestamp in `auth.log`; root becomes a break-glass path, not a daily login.
- **Repeatable beats heroic.** Each run backs up the files it changes, refuses to reload an invalid `sshd` config, and can be replayed safely — so hardening becomes a deployable step instead of a one-off checklist.
