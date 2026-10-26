# Lab 05 — Linux Server Hardening

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu&logoColor=white&style=flat-square)
![Bash](https://img.shields.io/badge/Bash-5.x-4EAA25?logo=gnubash&logoColor=white&style=flat-square)
![Security](https://img.shields.io/badge/Security-Hardened-2ea44f?style=flat-square)
![UFW](https://img.shields.io/badge/UFW-Active-2C3E50?style=flat-square)

Surface d'attaque réduite à **un seul port** : root n'a plus de login SSH, l'authentification passe exclusivement par clé, et UFW refuse tout le reste. Le script `hardening.sh` applique ces contrôles de bout en bout — idempotent, journalisé, validé par `sshd -t` — pour transformer un Ubuntu par défaut en serveur durci en une commande.

## Key Security Controls

| Domaine | Avant hardening | Après hardening |
|---|---|---|
| **Root SSH** | `PermitRootLogin yes`, mot de passe | `PermitRootLogin no` + compte root verrouillé (`passwd -l`) |
| **Authentification** | Mot de passe, comptes partagés | Clé ED25519 + passphrase, `AuthenticationMethods publickey` |
| **Pare-feu** | Inactif, tous les ports exposés | UFW actif, `deny (incoming)`, seul `22/tcp` en `LIMIT` |
| **Privilèges** | root direct, aucune traçabilité | `sysadmin_sec` + `sudo` nominatif, journalisé dans `auth.log` |
| **Permissions** | `~/.ssh` 755, clés 644 | `~/.ssh` **700**, `authorized_keys` **600**, home 750 |
| **Umask** | `022` → fichiers 644 | `027` → fichiers 640 |
| **Services** | avahi, cups, bluetooth actifs | `disable` **+ `mask`** (insensibles aux dépendances) |

## Architecture & Threat Model

```
Internet / LAN
      │
      ▼
[ UFW ]   deny incoming · allow 22/tcp (limit) · log low
      │
      │  ✅ SSH — clé ED25519 uniquement
      ▼
[ sshd ]  PermitRootLogin no · PasswordAuthentication no · AllowUsers sysadmin_sec
      │
      ▼
[ sysadmin_sec ]  uid 1001 · sudo journalisé
      │
      │  sudo -i (ponctuel, tracé)
      ▼
[ root ]  uid 0 · mot de passe verrouillé · aucun login direct

  ❌ Bloqués : 80/443 · 3306 · root@22 · password auth · X11 / agent forwarding
```

| Menace | Contrôle |
|---|---|
| Brute force SSH | Clé uniquement, `MaxAuthTries 3`, `ufw limit` |
| Élévation via root | Root verrouillé, sudo nominatif journalisé |
| Service oublié exposé | `deny` par défaut + services masqués |
| Régression de config | Script idempotent, `sshd -t` avant tout reload |

## Validation & Evidence

```console
$ sudo ufw status verbose
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

To                    Action      From
--                    ------      ----
22/tcp                LIMIT IN    Anywhere
22/tcp (v6)           LIMIT IN    Anywhere (v6)

$ ssh -o BatchMode=yes sysadmin_sec@lab05 'echo OK'
OK

$ ssh -o PubkeyAuthentication=no root@lab05
root@lab05: Permission denied (publickey).

$ sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication'
permitrootlogin no
passwordauthentication no
```

## Key Takeaways

- **Refuser par défaut.** Un seul port ouvert, le reste implicitement bloqué — et les services inutiles sont `mask`, pas seulement arrêtés.
- **Un compte, une clé, zéro root.** Un admin nominatif avec sudo tracé vaut mieux qu'un root partagé ; une clé ED25519 vaut mieux qu'un mot de passe.
- **Automatiser ne suffit pas : valider.** `sshd -t`, dry-run et sauvegardes automatiques rendent le script sûr à rejouer, encore et encore.
