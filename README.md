# Lab 05 — Linux Server Hardening

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu&logoColor=white)
![WSL2](https://img.shields.io/badge/WSL2-Environnement-0078D4?logo=windows&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-5.x-4EAA25?logo=gnubash&logoColor=white)
![OpenSSH](https://img.shields.io/badge/OpenSSH-Hardened-1F425F?logo=openssh&logoColor=white)
![UFW](https://img.shields.io/badge/UFW-Actif-2C3E50)
![Licence](https://img.shields.io/badge/Licence-MIT-green)

> Laboratoire pratique de durcissement (hardening) d'un serveur Linux Ubuntu.
> Application du **principe du moindre privilège**, de la **gestion stricte des accès SSH**,
> du **filtrage réseau avec UFW** et du **contrôle des services avec systemd**.

---

## Sommaire

1. [Objective](#1-objective)
2. [Architecture](#2-architecture)
3. [Prerequisites](#3-prerequisites)
4. [Implementation](#4-implementation)
   - [Étape 1 — Utilisateur dédié & désactivation du compte root](#étape-1--création-dun-utilisateur-dédié-sysadmin_sec-avec-privilèges-sudo-et-désactivation-du-compte-root-direct)
   - [Étape 2 — Durcissement des permissions](#étape-2--durcissement-des-permissions-chmod--chown)
   - [Étape 3 — Configuration d'OpenSSH](#étape-3--configuration-dopenssh-etcsshsshd_config)
   - [Étape 4 — Pare-feu UFW](#étape-4--configuration-et-activation-du-pare-feu-ufw)
   - [Étape 5 — Audit des services systemd](#étape-5--audit-des-services-actifs-avec-systemctl)
5. [Testing](#5-testing)
6. [Troubleshooting](#6-troubleshooting)
7. [Lessons Learned](#7-lessons-learned)
8. [Références](#8-références)

---

## 1. Objective

Sécuriser un environnement **Linux Ubuntu** en appliquant le principe du moindre privilège, la gestion stricte des accès SSH, le filtrage réseau avec UFW et le contrôle des services avec systemd.

### Objectifs détaillés

| # | Objectif | Critère de réussite |
|---|----------|---------------------|
| 1 | Réduire la surface d'attaque liée aux comptes | `root` non connectable directement, un seul compte d'administration `sysadmin_sec` |
| 2 | Supprimer l'authentification par mot de passe sur SSH | `PasswordAuthentication no` + `PermitRootLogin no` effectifs |
| 3 | Restreindre les permissions des ressources sensibles | Aucun fichier `~/.ssh` accessible par un tiers, fichiers système conformes |
| 4 | Filtrer le trafic réseau entrant | `ufw` actif, politique `deny (incoming)`, seul le port 22/TCP est exposé |
| 5 | Limiter les services en écoute | Chaque service `enabled` est justifié ; les autres sont désactivés/masqués |

### Périmètre

| Inclus | Exclu (hors périmètre de ce lab) |
|--------|----------------------------------|
| Comptes locaux, `sudo`, verrouillage de `root` | Mise en place d'une PKI / CA interne |
| Permissions POSIX (`chmod`, `chown`, `umask`) | Chiffrement de disque (LUKS) |
| Durcissement `sshd` | Bastion SSH / Jump host |
| Politique `ufw` | IDS/IPS réseau (Suricata, Snort) |
| Revue des unités `systemd` | Orchestration (Ansible, Terraform) — voir pistes d'évolution |

### Résultat attendu

Un serveur Ubuntu local isolé (WSL2) dont l'unique voie d'administration est :

```
SSH (clé ED25519 uniquement) ──► sysadmin_sec ──► sudo ──► root (jamais de login direct)
```

---

## 2. Architecture

### 2.1 Vue d'ensemble

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Windows 11 (Hôte)                                                           │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │  WSL2 — Réseau virtuel isolé (NAT)        172.x.x.x/20                │   │
│   │                                                                      │   │
│   │   ┌──────────────────────────────────────────────────────────────┐   │   │
│   │   │  Ubuntu 24.04 LTS — "srv-lab05"  (systemd activé)            │   │   │
│   │   │                                                              │   │   │
│   │   │   ┌────────────────────────────────────────────────────┐     │   │   │
│   │   │   │  UFW  (default: deny incoming / allow outgoing)    │     │   │   │
│   │   │   │  ┌──────────────────────────────────────────────┐  │     │   │   │
│   │   │   │  │  ALLOW  22/tcp  (limit)  ◄── seul port ouvert│  │     │   │   │
│   │   │   │  │  DENY   */*              (log: low)          │  │     │   │   │
│   │   │   │  └──────────────────────────────────────────────┘  │     │   │   │
│   │   │   └───────────────────────────┬────────────────────────┘     │   │   │
│   │   │                               │                              │   │   │
│   │   │                        ┌──────▼──────┐                       │   │   │
│   │   │                        │   sshd      │  pubkey only          │   │   │
│   │   │                        │   :22       │  root login: no       │   │   │
│   │   │                        │  AllowUsers │  sysadmin_sec         │   │   │
│   │   │                        └──────┬──────┘                       │   │   │
│   │   │                               │  PAM / sudo                  │   │   │
│   │   │            ┌──────────────────┴──────────────────┐           │   │   │
│   │   │            │                                     │           │   │   │
│   │   │      ┌─────▼──────────────┐            ┌─────────▼────────┐  │   │   │
│   │   │      │  sysadmin_sec      │            │  root            │  │   │   │
│   │   │      │  uid 1001          │  sudo      │  uid 0           │  │   │   │
│   │   │      │  groupe: sudo      │ ─────────► │  mot de passe:   │  │   │   │
│   │   │      │  shell: /bin/bash  │            │  VERROUILLÉ (*)  │  │   │   │
│   │   │      │  ~/.ssh 0700      │            │  login direct: ✗ │  │   │   │
│   │   │      │  authorized_keys   │            │  (via sudo -i)   │  │   │   │
│   │   │      │  0600              │            └──────────────────┘  │   │   │
│   │   │      └────────────────────┘                                  │   │   │
│   │   │                                                              │   │   │
│   │   │   systemd : services minimalistes (ssh, cron, journald)      │   │   │
│   │   │             avahi / cups / bluetooth / ModemManager : OFF    │   │   │
│   │   └──────────────────────────────────────────────────────────────┘   │   │
│   └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                    ▲
                    │  ssh -i ~/.ssh/id_ed25519 sysadmin_sec@<host>
                    │  (clé privée protégée par passphrase, jamais de mot de passe)
              Poste client / attaquant simulé
```

### 2.2 Matrice d'accès

| Source | Destination | Port / Proto | Décision UFW | Justification |
|--------|-------------|--------------|--------------|---------------|
| Poste d'admin (LAN/WSL) | `srv-lab05` | 22/TCP | `ALLOW` + `limit` | Administration SSH par clé |
| Poste d'admin | `srv-lab05` | 80, 443, 3306, 5432 | `DENY` (implicite) | Aucun service applicatif |
| Réseau WSL | `srv-lab05` | 1-65535 (hors 22) | `DENY` (implicite) | Politique par défaut |
| `srv-lab05` | Internet | 53, 80, 443 | `ALLOW` (outgoing) | Mises à jour APT |
| `root` | `srv-lab05` (SSH) | 22/TCP | Bloqué par `sshd` | `PermitRootLogin no` |

### 2.3 Flux d'authentification

```
Client                        sshd                       PAM / sudo
  │                             │                            │
  │  1. TCP 22 (autorisé UFW)   │                            │
  ├────────────────────────────►│                            │
  │  2. KEX + host key          │                            │
  │◄────────────────────────────┤                            │
  │  3. auth "publickey"        │                            │
  ├────────────────────────────►│                            │
  │                             │ 4. vérifie ~/.ssh/         │
  │                             │    authorized_keys (0600)  │
  │                             │    + ownership             │
  │  5. session ouverte         │                            │
  │◄────────────────────────────┤                            │
  │  6. sudo <cmd>              │                            │
  ├─────────────────────────────┼───────────────────────────►│
  │                             │            7. mot de passe │
  │                             │               utilisateur  │
  │                             │◄───────────────────────────┤
  │  8. exécution privilégiée   │                            │
  │◄────────────────────────────┼────────────────────────────┤
```

---

## 3. Prerequisites

| Composant | Version / Détail | Vérification |
|-----------|------------------|--------------|
| Windows | Windows 10 21H2+ / Windows 11 | `winver` |
| WSL | WSL2 (virtualisation activée) | `wsl -l -v` (VERSION = 2) |
| Distribution | Ubuntu 24.04 LTS (Noble Numbat) | `lsb_release -a` |
| systemd | Activé dans WSL (`systemd=true`) | `systemctl is-system-running` |
| Droits | Utilisateur membre du groupe `sudo` | `sudo -v` |
| OpenSSH | `openssh-server` (serveur) + `openssh-client` | `sshd -V` / `ssh -V` |
| Réseau | Port 22 libre sur l'instance | `ss -tulpn \| grep :22` |

### 3.1 Activation de systemd dans WSL2

Sans systemd, ni `systemctl` ni `ufw` (service) ne fonctionnent correctement.

```bash
# /etc/wsl.conf
[boot]
systemd=true
```

```powershell
# Depuis PowerShell (Windows)
wsl --shutdown
wsl -d Ubuntu
```

```bash
# Vérification
systemctl is-system-running      # "running" ou "degraded"
ps -p 1 -o comm=                 # doit afficher "systemd"
```

### 3.2 Installation des paquets

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y openssh-server ufw sudo openssh-client

# État initial
sudo systemctl status ssh --no-pager
sudo ufw status verbose
```

> ⚠️ **Sauvegarde avant modification** : les étapes suivantes touchent à `sshd` et au pare-feu.
> Toujours conserver une session SSH ouverte **et** un accès de secours (console WSL) pendant l'opération.

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)
sudo cp /etc/sudoers /etc/sudoers.bak.$(date +%F)
```

---

## 4. Implementation

> ⚡ **Version automatisée** : `hardening.sh` (livré à la racine du dépôt) exécute les 5 étapes ci-dessous,
> avec sauvegardes, validation `sshd` et garde-fous. Voir [§4.0](#40-script-dautomatisation--hardeningsh).

### 4.0 Script d'automatisation — `hardening.sh`

Le script est **idempotent**, journalisé et refuse de couper l'accès SSH sans clé déjà installée.

```bash
chmod +x hardening.sh

sudo ./hardening.sh --check        # 1. audit en lecture seule
sudo ./hardening.sh --dry-run      # 2. simulation (aucune modification)
sudo ./hardening.sh                # 3. application interactive
sudo ./hardening.sh -y --only ssh,ufw   # étapes ciblées, sans question
```

| Option | Effet |
|--------|-------|
| `-n`, `--dry-run` | Affiche chaque action sans l'exécuter |
| `-y`, `--yes` | Mode non interactif (compte créé sans mot de passe → à définir ensuite) |
| `-f`, `--force` | Outrepasse le garde-fou « aucune clé SSH » (déconseillé) |
| `--check` | Audit seul : comptes, SSH effectif, permissions, UFW, services |
| `--only LIST` / `--skip LIST` | Cible `users`, `permissions`, `ssh`, `ufw`, `services` |
| `--user NAME` | Compte d'administration (défaut `sysadmin_sec`) |
| `--reset-ufw` | Réinitialise UFW avant d'appliquer la politique |

Ce que le script garantit :

- `~/.ssh` en **700**, `authorized_keys` en **600**, home en **750**, propriétaire = compte cible ;
- `/etc/ssh/sshd_config.d/hardening.conf` en **600 root:root** avec `PermitRootLogin no`
  et `PasswordAuthentication no`, **validé par `sshd -t`** avant tout rechargement ;
- sauvegarde horodatée dans `/var/backups/lab05-hardening/<date>/` et journal dans `/var/log/` ;
- port SSH réellement écouté détecté (`sshd -T`) pour la règle UFW, au lieu de supposer 22 ;
- aucune modification si `sshd -t` échoue : restauration automatique de la configuration précédente.

> ⚠️ Le script ne remplace pas le test humain : garder une session SSH ouverte (ou la console WSL)
> et valider une **nouvelle** connexion avant de fermer l'ancienne.

### Étape 1 — Création d'un utilisateur dédié `sysadmin_sec` avec privilèges `sudo` et désactivation du compte root direct

**Principe** : ne jamais travailler en `root`. L'administrateur dispose d'un compte nominatif, traçable, élévé ponctuellement via `sudo`.

#### 1.1 Création du compte

```bash
# Création avec répertoire home et shell explicite
sudo adduser --gecos "System Administrator (Security)" sysadmin_sec

# Ajout au groupe sudo (élévation contrôlée et journalisée)
sudo usermod -aG sudo sysadmin_sec

# Vérifications
id sysadmin_sec
getent group sudo
```

Sortie attendue :

```
uid=1001(sysadmin_sec) gid=1001(sysadmin_sec) groups=1001(sysadmin_sec),27(sudo)
sudo:x:27:sysadmin_sec
```

#### 1.2 Politique `sudo` renforcée

```bash
sudo visudo -f /etc/sudoers.d/90-sysadmin-sec
```

```sudoers
# Mot de passe obligatoire, délai de grâce court
# (la journalisation des commandes est assurée par défaut dans /var/log/auth.log)
Defaults:sysadmin_sec  timestamp_timeout=5
Defaults:sysadmin_sec  passwd_tries=3
Defaults:sysadmin_sec  lecture=always

sysadmin_sec ALL=(ALL:ALL) ALL
```

```bash
sudo chmod 440 /etc/sudoers.d/90-sysadmin-sec
sudo visudo -c          # validation syntaxique obligatoire
```

#### 1.3 Désactivation du login direct de `root`

```bash
# 1) Verrouillage du mot de passe root (le champ devient "!" / "*")
sudo passwd -l root
sudo passwd -S root          # attendu : root L (Locked)

# 2) Interdiction du login SSH root (détaillé à l'étape 3)
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
```

> ℹ️ Sous WSL, `sudo` continue de fonctionner : il s'appuie sur le mot de passe de `sysadmin_sec`, pas sur celui de `root`.
> Pour repasser `root` en mode maintenance : `sudo passwd -u root` depuis une session `sudo`.

#### 1.4 Bannière légale (dissuasion)

```bash
sudo tee /etc/issue.net >/dev/null <<'EOF'
***************************************************************************
*  Accès réservé. Toute connexion est enregistrée et contrôlée.            *
*  Les accès non autorisés font l'objet de poursuites.                     *
***************************************************************************
EOF

# La directive "Banner /etc/issue.net" est ajoutée au drop-in sshd à l'étape 3.
```

Vérification :

```bash
sudo passwd -S root            # root L (verrouillé)
sudo sshd -T | grep -i permitrootlogin
```

---

### Étape 2 — Durcissement des permissions (`chmod` / `chown`)

**Principe** : un secret lisible par un autre utilisateur n'est plus un secret. Les permissions sont la dernière ligne de défense si un compte est compromis.

#### 2.1 Répertoire personnel et clés SSH

```bash
# Répertoire home non accessible en écriture au groupe/autres
sudo chmod 750 /home/sysadmin_sec
sudo chown sysadmin_sec:sysadmin_sec /home/sysadmin_sec

# Dossier ~/.ssh : seul le propriétaire peut entrer
install -d -m 700 -o sysadmin_sec -g sysadmin_sec /home/sysadmin_sec/.ssh

# Clés : lecture propriétaire uniquement
chmod 600 /home/sysadmin_sec/.ssh/authorized_keys
chmod 600 /home/sysadmin_sec/.ssh/id_ed25519          # clé privée (si présente)
chmod 644 /home/sysadmin_sec/.ssh/id_ed25519.pub
chmod 644 /home/sysadmin_sec/.ssh/known_hosts
chown -R sysadmin_sec:sysadmin_sec /home/sysadmin_sec/.ssh
```

> 🔐 `sshd` refuse toute clé si `authorized_keys` (ou son répertoire parent) est accessible en écriture par le groupe ou les autres.
> C'est la cause n°1 de `Permission denied (publickey)`.

#### 2.2 Fichiers système sensibles

```bash
# Bases de comptes et de mots de passe
sudo chown root:root   /etc/passwd   && sudo chmod 644 /etc/passwd
sudo chown root:shadow /etc/shadow   && sudo chmod 640 /etc/shadow
sudo chown root:root   /etc/group    && sudo chmod 644 /etc/group
sudo chown root:shadow /etc/gshadow  && sudo chmod 640 /etc/gshadow

# Configuration SSH (clés d'hôte incluses)
sudo chown root:root /etc/ssh/sshd_config
sudo chmod 600       /etc/ssh/ssh_host_*_key
sudo chmod 644       /etc/ssh/ssh_host_*_key.pub
sudo chmod 755       /etc/ssh

# Sudo et journaux
sudo chown root:root /etc/sudoers && sudo chmod 440 /etc/sudoers
sudo chmod 750 /etc/sudoers.d
sudo chmod 750 /var/log
sudo chmod 640 /var/log/auth.log 2>/dev/null || true
```

#### 2.3 `umask` restrictif

```bash
# Fichiers créés par défaut : 640 (rw-r-----), répertoires : 750 (rwxr-x---)
echo "umask 027" | sudo tee /etc/profile.d/99-umask.sh
sudo chmod 644 /etc/profile.d/99-umask.sh

# Vérification après reconnexion
umask        # attendu : 0027
```

#### 2.4 Recherche des dérives

```bash
# Fichiers inscriptibles par tous (hors /tmp, /proc, /sys)
sudo find / -xdev -type f -perm -0002 ! -path "/tmp/*" ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null

# Fichiers sans propriétaire valide
sudo find / -xdev \( -nouser -o -nogroup \) 2>/dev/null

# Binaires SUID/SGID (à connaître et justifier)
sudo find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
```

Résultat attendu sur le lab : **aucune sortie** pour les deux premières commandes.

#### 2.5 Tableau récapitulatif des permissions cibles

| Chemin | Propriétaire | Mode | Raison |
|--------|--------------|------|--------|
| `/home/sysadmin_sec` | `sysadmin_sec:sysadmin_sec` | `750` | Isole le home des autres comptes |
| `~/.ssh` | `sysadmin_sec:sysadmin_sec` | `700` | `sshd` exige l'exclusivité |
| `~/.ssh/authorized_keys` | `sysadmin_sec:sysadmin_sec` | `600` | Clés publiques autorisées |
| `~/.ssh/id_ed25519` | `sysadmin_sec:sysadmin_sec` | `600` | Clé privée = secret critique |
| `/etc/shadow` | `root:shadow` | `640` | Empreintes de mots de passe |
| `/etc/gshadow` | `root:shadow` | `640` | Mots de passe de groupes |
| `/etc/sudoers` | `root:root` | `440` | Politique d'élévation |
| `/etc/sudoers.d` | `root:root` | `750` | Drop-ins sudo |
| `/etc/ssh/sshd_config` | `root:root` | `600` | Configuration du démon |
| `/etc/ssh/ssh_host_*_key` | `root:root` | `600` | Clés d'hôte (usurpation MITM) |
| `/var/log` | `root:syslog` | `750` | Intégrité des journaux |

---

### Étape 3 — Configuration d'OpenSSH (`/etc/ssh/sshd_config`)

**Objectif** : authentification par clé uniquement, aucun login `root`, surface fonctionnelle minimale.

#### 3.1 Génération de la paire de clés (côté client)

```bash
# Sur le poste client
ssh-keygen -t ed25519 -a 100 -C "sysadmin_sec@lab05" -f ~/.ssh/id_ed25519_lab05

# Protection de la clé privée par passphrase (obligatoire)
# Copie de la clé publique vers le serveur (avant de désactiver les mots de passe)
ssh-copy-id -i ~/.ssh/id_ed25519_lab05.pub sysadmin_sec@<host>
```

#### 3.2 Configuration durcie via un drop-in

Ubuntu 24.04 inclut `/etc/ssh/sshd_config.d/*.conf` **avant** le reste du fichier :
un drop-in surcharge donc proprement la configuration par défaut (approche recommandée, réversible et lisible).

```bash
sudo tee /etc/ssh/sshd_config.d/99-hardening.conf >/dev/null <<'EOF'
# ─────────────────────────────────────────────────────────────
# Lab 05 — OpenSSH hardening
# ─────────────────────────────────────────────────────────────

# Authentification
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthenticationMethods publickey
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30

# Restriction nominative
AllowUsers sysadmin_sec
# AllowGroups sudo            # alternative (décommenter AllowUsers)

# Surface fonctionnelle
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no

# Robustesse de session
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
Banner /etc/issue.net

# Journalisation
LogLevel VERBOSE
SyslogFacility AUTH
EOF

sudo chmod 600 /etc/ssh/sshd_config.d/99-hardening.conf
```

#### 3.3 Validation avant rechargement

```bash
# Le test de configuration est OBLIGATOIRE avant tout reload
sudo sshd -t -f /etc/ssh/sshd_config && echo "OK: configuration valide"

# Application sans couper les sessions existantes
sudo systemctl reload ssh
sudo systemctl status ssh --no-pager
```

> 🚨 **Ordre critique** : tester la connexion par clé **avant** de recharger avec `PasswordAuthentication no`.
> Sinon, la session est perdue et il faut repasser par la console WSL.

#### 3.4 Vérification de la configuration effective

```bash
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|maxauthtries'
```

```
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
allowusers sysadmin_sec
maxauthtries 3
```

#### 3.5 Durcissement complémentaire (optionnel mais recommandé)

```bash
# Limitation des connexions simultanées non authentifiées
sudo tee /etc/ssh/sshd_config.d/98-rate-limit.conf >/dev/null <<'EOF'
MaxStartups 10:30:60
EOF
```

> ℹ️ Les directives `PerSourceMaxStartups` / `PerSourcePenalties` nécessitent **OpenSSH ≥ 9.8**.
> Ubuntu 24.04 embarque OpenSSH 9.6p1 : les ajouter provoquerait `Bad configuration option` au prochain `sshd -t`.
> Vérifier la version avant de les utiliser : `ssh -V`.

---

### Étape 4 — Configuration et activation du pare-feu UFW

**Objectif** : refuser tout trafic entrant non sollicité, n'exposer que SSH, journaliser les rejets.

#### 4.1 Remise à zéro et politique par défaut

```bash
# Repartir d'une base saine (à faire uniquement si aucune règle métier n'existe)
sudo ufw --force reset

sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw default deny routed
```

#### 4.2 Ouverture contrôlée du port SSH

```bash
# "limit" = max 6 connexions / 30 s depuis une même IP (anti-bruteforce basique)
sudo ufw limit 22/tcp comment 'SSH admin (rate-limited)'

# Journalisation des paquets refusés
sudo ufw logging low

# Activation (interactive : répondre "y")
sudo ufw enable

# Démarrage automatique au boot
sudo systemctl enable ufw
```

> ⚠️ **WSL2** : `ufw` filtre le trafic de l'instance Ubuntu, mais le NAT WSL et le pare-feu Windows restent la première couche.
> Pour que `ufw` démarre automatiquement avec systemd : `sudo systemctl enable --now ufw`.
> Ne jamais activer `ufw` sans avoir autorisé SSH au préalable → risque de perte d'accès.

#### 4.3 Règles finales

```bash
sudo ufw status verbose
```

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     LIMIT IN    Anywhere                   # SSH admin (rate-limited)
22/tcp (v6)                LIMIT IN    Anywhere (v6)              # SSH admin (rate-limited)
```

#### 4.4 Politique appliquée

| Direction | Politique | Détail |
|-----------|-----------|--------|
| Entrant | `DENY` | Aucun service exposé par défaut |
| Sortant | `ALLOW` | Nécessaire aux mises à jour APT |
| Routé | `DENY` | L'instance n'est pas un routeur |
| SSH 22/TCP | `LIMIT` | Anti-bruteforce + traçabilité |
| Journalisation | `low` | Rejets consultables via `journalctl` |

---

### Étape 5 — Audit des services actifs avec `systemctl`

**Objectif** : chaque service en écoute doit être **nécessaire, justifié et à jour**. Tout le reste est désactivé.

#### 5.1 Inventaire initial

```bash
# Unités activées au démarrage
systemctl list-unit-files --type=service --state=enabled

# Services actuellement en cours d'exécution
systemctl list-units --type=service --state=running

# Ports réellement en écoute (vue réseau, complémentaire à systemd)
sudo ss -tulpn

# Correspondance port ↔ unité
sudo systemctl list-sockets --all
```

#### 5.2 Décision de durcissement

| Unité | État initial | Décision | Justification |
|-------|--------------|----------|---------------|
| `ssh.service` | enabled | **Conservé** | Voie d'administration unique |
| `cron.service` | enabled | **Conservé** | Tâches planifiées système |
| `systemd-journald.service` | enabled | **Conservé** | Journalisation (forensique) |
| `systemd-resolved.service` | enabled | **Conservé** | Résolution DNS |
| `systemd-timesyncd.service` | enabled | **Conservé** | Synchronisation NTP (fraîcheur des logs) |
| `ufw.service` | enabled | **Conservé** | Filtrage réseau |
| `avahi-daemon.service` | enabled | **Désactivé + masqué** | Découverte mDNS inutile sur un serveur |
| `cups.service` / `cups-browsed` | enabled | **Désactivé + masqué** | Aucune imprimante |
| `bluetooth.service` | enabled | **Désactivé + masqué** | Aucun périphérique Bluetooth |
| `ModemManager.service` | enabled | **Désactivé + masqué** | Pas de modem |
| `snapd.service` | enabled | **Désactivé** (si aucun snap) | Surface d'attaque et sockets supplémentaires |
| `whoopsie.service` | enabled | **Désactivé** | Remontée de crashs non souhaitée |
| `apport.service` | enabled | **Désactivé** | Collecte de rapports de crash |
| `unattended-upgrades.service` | disabled | **À activer** | Correctifs de sécurité automatiques |

#### 5.3 Désactivation des services inutiles

```bash
# disable --now : arrêt immédiat + retrait du démarrage automatique
for svc in avahi-daemon cups cups-browsed bluetooth ModemManager whoopsie apport; do
  if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1; then
    sudo systemctl disable --now "${svc}.service" 2>/dev/null || true
    sudo systemctl mask "${svc}.service"          2>/dev/null || true
  fi
done

# Snap : uniquement si aucun paquet snap n'est installé
if ! snap list 2>/dev/null | tail -n +2 | grep -q .; then
  sudo systemctl disable --now snapd.socket snapd.service 2>/dev/null || true
fi
```

> 🧠 `disable` empêche le démarrage automatique ; `mask` empêche **toute** activation (même par dépendance).
> `mask` est réversible : `sudo systemctl unmask <unit>`.

#### 5.4 Activation des mises à jour de sécurité automatiques

```bash
sudo dpkg-reconfigure --priority=low unattended-upgrades   # répondre "Yes"
sudo systemctl enable --now unattended-upgrades

cat /etc/apt/apt.conf.d/20auto-upgrades
```

```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

#### 5.5 Vérification post-durcissement

```bash
systemctl list-units --type=service --state=running --no-pager
systemctl --failed --no-pager
sudo ss -tulpn
```

Surface d'attaque cible :

```
Netid State  Local Address:Port   Process
tcp   LISTEN 0.0.0.0:22           sshd
udp   UNCONN 127.0.0.53:53        systemd-resolved
```

---

## 5. Testing

### 5.1 Tests d'authentification SSH

| Test | Commande | Résultat attendu |
|------|----------|------------------|
| Connexion par clé | `ssh -i ~/.ssh/id_ed25519_lab05 sysadmin_sec@<host>` | Session ouverte **sans** demande de mot de passe |
| Login `root` refusé | `ssh -o PubkeyAuthentication=no root@<host>` | `Permission denied (publickey)` |
| Mot de passe refusé | `ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no sysadmin_sec@<host>` | `Permission denied (publickey)` |
| Utilisateur hors `AllowUsers` | `ssh autre_user@<host>` | `Permission denied` |
| Mode batch (CI/script) | `ssh -o BatchMode=yes sysadmin_sec@<host> true` | Code retour `0`, aucune interaction |
| Empreinte serveur | `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` | Empreinte connue et stable |

```bash
# Vérification détaillée de la négociation
ssh -vvv -o BatchMode=yes sysadmin_sec@<host> true 2>&1 | grep -Ei \
  'Authentications that can continue|Offering public key|Server accepts key|Authenticated to'
```

Extrait attendu :

```
debug1: Authentications that can continue: publickey
debug1: Offering public key: ... ED25519 SHA256:...
debug1: Server accepts key: ... ED25519 SHA256:...
Authenticated to <host> ([127.0.0.1]:22) using "publickey".
```

> 💡 `ssh -T` : le flag `-T` désactive l'allocation de TTY (mode non interactif).
> Sur un serveur classique : `ssh -T sysadmin_sec@<host> 'echo OK'` → `OK`.
> Sur GitHub : `ssh -T git@github.com` → `Hi <user>! You've successfully authenticated...`

### 5.2 Tests pare-feu UFW

```bash
sudo ufw status verbose
sudo ufw status numbered

# Règles effectives au niveau noyau (vérité terrain, indépendante de ufw)
sudo iptables -S | grep -i ufw
sudo nft list ruleset 2>/dev/null | head -50

# Test de port fermé depuis un autre hôte / depuis Windows
# PowerShell : Test-NetConnection <host> -Port 80     → TcpTestSucceeded : False
#              Test-NetConnection <host> -Port 22     → TcpTestSucceeded : True
```

Attendu :

```
Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
22/tcp    LIMIT IN    Anywhere
22/tcp (v6) LIMIT IN  Anywhere (v6)
```

### 5.3 Tests services / systemd

```bash
# Unités activées
systemctl list-unit-files --type=service --state=enabled

# Unités en échec (doit être vide)
systemctl --failed

# Services désactivés/masqués ciblés par le lab
for svc in avahi-daemon cups bluetooth ModemManager; do
  printf '%-20s %s\n' "$svc" "$(systemctl is-enabled "$svc" 2>/dev/null || echo 'n/a')"
done
# attendu : masked / masked / masked / masked

# Ports ouverts
sudo ss -tulpn

# Démarrage : cible multi-user atteinte ?
systemctl get-default                 # multi-user.target
systemctl is-system-running           # running
```

### 5.4 Tests permissions & comptes

```bash
# Compte root verrouillé
sudo passwd -S root                   # root L ...
sudo awk -F: '$3==0 {print $1}' /etc/passwd   # seul "root" attendu

# Permissions des clés
stat -c '%A %U:%G %n' ~/.ssh ~/.ssh/authorized_keys
# attendu : drwx------ sysadmin_sec:sysadmin_sec .../.ssh
#           -rw------- sysadmin_sec:sysadmin_sec .../.ssh/authorized_keys

# Aucun fichier "world-writable" hors /tmp
sudo find / -xdev -type f -perm -0002 ! -path "/tmp/*" 2>/dev/null | wc -l   # 0

# Mots de passe vides interdits
sudo awk -F: '($2==""){print $1}' /etc/shadow    # aucune sortie
```

### 5.5 Script d'audit complet (bonus)

```bash
#!/usr/bin/env bash
# scripts/security-audit.sh — audit rapide post-durcissement
set -uo pipefail
FAIL=0
ok()   { printf '  [ OK ] %s\n' "$*"; }
ko()   { printf '  [FAIL] %s\n' "$*"; FAIL=$((FAIL+1)); }

echo "== SSH =="
sshd -T 2>/dev/null | grep -q '^permitrootlogin no'          && ok "PermitRootLogin no"        || ko "PermitRootLogin"
sshd -T 2>/dev/null | grep -q '^passwordauthentication no'   && ok "PasswordAuthentication no" || ko "PasswordAuthentication"
sshd -T 2>/dev/null | grep -q '^pubkeyauthentication yes'    && ok "PubkeyAuthentication yes"  || ko "PubkeyAuthentication"

echo "== Pare-feu =="
ufw status | grep -q '^Status: active'                       && ok "UFW actif"                 || ko "UFW inactif"
ufw status | grep -qE '^22/tcp +(LIMIT|ALLOW)'               && ok "SSH autorisé"              || ko "SSH non autorisé"

echo "== Comptes =="
[ "$(passwd -S root | awk '{print $2}')" = "L" ]             && ok "root verrouillé"           || ko "root non verrouillé"
[ "$(awk -F: '$3==0' /etc/passwd | wc -l)" -eq 1 ]           && ok "UID 0 unique"              || ko "Plusieurs UID 0"

echo "== Permissions =="
[ "$(stat -c '%a' "$HOME/.ssh")" = "700" ]                   && ok "~/.ssh 700"                || ko "~/.ssh != 700"
[ "$(stat -c '%a' "$HOME/.ssh/authorized_keys" 2>/dev/null)" = "600" ] \
                                                             && ok "authorized_keys 600"       || ko "authorized_keys != 600"

echo
[ "$FAIL" -eq 0 ] && echo "Audit réussi." || { echo "$FAIL échec(s)."; exit 1; }
```

```bash
chmod +x scripts/security-audit.sh && ./scripts/security-audit.sh
```

---

## 6. Troubleshooting

### 6.1 Tableau de diagnostic rapide

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| `Connection timed out` sur le port 22 | UFW bloque SSH / règle manquante | Console WSL → `ufw allow 22/tcp` (voir 6.2) |
| `Connection refused` | `ssh` arrêté ou port changé | `systemctl status ssh`, `ss -tulpn \| grep :22` |
| `Permission denied (publickey)` | Permissions/ownership de `~/.ssh` | Corriger en `700` / `600`, propriétaire = utilisateur (6.3) |
| `Permission denied (publickey)` malgré tout | Clé non déclarée dans `AllowUsers`/`AuthenticationMethods` | Vérifier `sshd -T \| grep -E 'allowusers\|authenticationmethods'` |
| Demande de mot de passe persistante | Drop-in non chargé / `sshd` non rechargé | `sshd -T`, `systemctl reload ssh` |
| `Bad configuration option` | Faute de frappe dans le drop-in | `sshd -t` puis corriger ; restaurer `.bak` si besoin |
| `systemctl: command not found` / `System has not been booted with systemd` | WSL sans systemd | `[boot] systemd=true` dans `/etc/wsl.conf`, `wsl --shutdown` |
| `ufw` inactif après redémarrage | Service non activé | `systemctl enable --now ufw` |
| `sshd` ne démarre pas : `no hostkeys available` | Clés d'hôte absentes/régénérées | `sudo ssh-keygen -A` puis `systemctl restart ssh` |
| `Too many authentication failures` | Agent SSH proposant trop de clés | `ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519_lab05 ...` |
| `WARNING: UNPROTECTED PRIVATE KEY FILE` | Clé privée `0644` ou home inscriptible par le groupe | `chmod 600 ~/.ssh/id_ed25519*`, `chmod 750 ~` |
| `sudo: 1 incorrect password attempt` en boucle | `passwd_tries` trop bas / politique `sudoers` | Ajuster `passwd_tries` dans le drop-in sudoers |
| `root` verrouillé mais `sudo su` impossible | Verrouillage de `root` + compte hors `sudo` | Ajouter l'utilisateur au groupe `sudo`, ou console WSL |

### 6.2 Perte d'accès après activation d'UFW

**Symptôme** : plus aucune connexion SSH possible, `ssh: connect to host ... port 22: Connection timed out`.

**Cause** : `ufw enable` exécuté sans règle `allow 22/tcp`, ou mauvaise interface/port.

**Résolution** (via la console WSL, toujours accessible) :

```bash
# 1) Diagnostic
sudo ufw status verbose
sudo ss -tulpn | grep :22

# 2) Réouverture du port (ou du port personnalisé)
sudo ufw allow 22/tcp
# sudo ufw allow 2222/tcp        # si Port 2222 dans sshd_config

# 3) Si ufw est bloquant et qu'il faut repartir de zéro
sudo ufw disable
sudo ufw reset
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw enable

# 4) Vérification
sudo ufw status numbered
```

**Prévention** : préparer les règles **avant** `ufw enable`, garder une session SSH ouverte pendant l'opération, et vérifier depuis un second terminal.

### 6.3 `Permission denied (publickey)` — permissions de `~/.ssh`

**Symptôme** : la clé est correcte, mais le serveur refuse l'authentification.

```bash
# Diagnostic côté serveur (la cause exacte est journalisée)
sudo journalctl -u ssh -n 50 --no-pager
sudo grep -i 'authentication refused\|bad ownership\|bad permissions' /var/log/auth.log | tail
```

Messages typiques :

```
Authentication refused: bad ownership or modes for directory /home/sysadmin_sec/.ssh
Authentication refused: bad ownership or modes for file /home/sysadmin_sec/.ssh/authorized_keys
```

**Résolution** :

```bash
sudo chown -R sysadmin_sec:sysadmin_sec /home/sysadmin_sec
sudo chmod 750 /home/sysadmin_sec
sudo chmod 700 /home/sysadmin_sec/.ssh
sudo chmod 600 /home/sysadmin_sec/.ssh/authorized_keys
sudo chmod 600 /home/sysadmin_sec/.ssh/id_ed25519 2>/dev/null || true
sudo systemctl restart ssh    # un reload suffit généralement

# Contrôle
stat -c '%A %U:%G %n' /home/sysadmin_sec /home/sysadmin_sec/.ssh \
                     /home/sysadmin_sec/.ssh/authorized_keys
```

**Pièges fréquents** :

| Piège | Correction |
|-------|------------|
| `authorized_keys` en `644` ou `664` | `chmod 600` |
| Home en `775` (groupe inscriptible) | `chmod 750` et `chown` correct |
| Fichier édité avec `sudo tee` → propriétaire `root` | `chown sysadmin_sec:sysadmin_sec` |
| Clé collée avec retours à la ligne / espaces | Une seule ligne, commençant par `ssh-ed25519 AAAA...` |
| Mauvaise clé (mélange `id_rsa`/`id_ed25519`) | `ssh -o IdentitiesOnly=yes -i <clé_exacte>` |
| `\r\n` (CRLF) dans `authorized_keys` (copie Windows) | `dos2unix ~/.ssh/authorized_keys` ou `sed -i 's/\r$//'` |

### 6.4 Configuration `sshd` invalide

```bash
# Toujours valider AVANT de recharger
sudo sshd -t
# sshd: /etc/ssh/sshd_config.d/99-hardening.conf line 12: Bad configuration option: PasswordAuthenticationn

# Restauration
sudo mv /etc/ssh/sshd_config.d/99-hardening.conf /tmp/
sudo systemctl restart ssh

# Puis correction et nouvelle validation
sudo sshd -t && sudo systemctl reload ssh
```

> 🧯 **Filet de sécurité** : ne jamais fermer la session SSH en cours avant d'avoir validé la nouvelle connexion dans un second terminal.
> Sous WSL, la console reste le recours ultime (`wsl -d Ubuntu`).

### 6.5 `systemd` absent dans WSL

```bash
systemctl status
# System has not been booted with systemd as init system (PID 1). Can't operate.
```

```bash
# Activer systemd
sudo tee /etc/wsl.conf >/dev/null <<'EOF'
[boot]
systemd=true
EOF

# Redémarrer WSL depuis Windows
# powershell> wsl --shutdown
# powershell> wsl -d Ubuntu

# Vérifier
ps -p 1 -o comm=     # systemd
```

### 6.6 Conflit de port 22 (Windows ↔ WSL)

**Symptôme** : `sshd` démarre mais la connexion échoue depuis Windows ; ou `bind: Address already in use`.

```bash
# Côté Ubuntu
sudo ss -tulpn | grep :22
sudo systemctl status ssh

# Côté Windows (PowerShell, admin) : le service OpenSSH Windows peut squatter le port
Get-Service sshd
Get-NetTCPConnection -LocalPort 22 -ErrorAction SilentlyContinue
```

**Solutions** :
- Arrêter le service Windows : `Stop-Service sshd; Set-Service sshd -StartupType Disabled`
- Ou changer le port côté Ubuntu (`Port 2222` dans le drop-in + `ufw allow 2222/tcp` + `ufw delete allow 22/tcp`).

### 6.7 `ufw` et NAT WSL2

**Symptôme** : `ufw` indique `active`, mais les règles semblent sans effet depuis le réseau local.

**Cause** : WSL2 est derrière un NAT ; le trafic entrant est déjà filtré/redirigé par Windows (`netsh interface portproxy`, pare-feu Windows).

**Résolution** :

```bash
# Vérifier la couche réelle
sudo iptables -S | grep -i ufw
sudo ufw show raw | head -40

# Côté Windows
netsh interface portproxy show all
Get-NetFirewallRule -DisplayName '*WSL*'
```

**Prévention** : documenter la chaîne complète (pare-feu Windows → NAT WSL → ufw → sshd) et ne pas conclure trop vite à un défaut d'UFW.

### 6.8 Verrouillage involontaire de `root` / perte de `sudo`

```bash
# Vérifier les groupes de l'utilisateur
id
# Ajouter au groupe sudo si nécessaire (depuis une session root de secours)
sudo usermod -aG sudo sysadmin_sec

# Déverrouiller root temporairement (maintenance)
sudo passwd -u root
# ... opérations ...
sudo passwd -l root
```

> ⚠️ Sur Ubuntu, le compte `root` n'a généralement **pas** de mot de passe utilisable : `passwd -l root` est donc une formalité de traçabilité, la vraie barrière restant `PermitRootLogin no` + `AllowUsers`.

---

## 7. Lessons Learned

### 7.1 Principes retenus

1. **Le moindre privilège n'est pas une option, c'est une architecture.**
   Un compte nominatif + `sudo` journalisé remplace avantageusement un `root` partagé : on sait **qui** a fait **quoi**, et **quand**.
2. **L'ordre des opérations est une mesure de sécurité.**
   Copier la clé → tester la connexion → *puis* désactiver les mots de passe. Une seule inversion et l'accès est perdu.
3. **Les permissions sont un contrôle d'accès à part entière.**
   `~/.ssh` en `700`, `authorized_keys` en `600`, home non inscriptible par le groupe : trois lignes qui évitent la majorité des `Permission denied (publickey)`.
4. **Le pare-feu doit être « deny by default ».**
   Raisonner en liste blanche (n'ouvrir que le strict nécessaire) plutôt qu'en liste noire : oublier une règle devient sans conséquence.
5. **`disable` ≠ `mask`.**
   `disable` empêche le démarrage automatique ; `mask` empêche toute activation, y compris par dépendance. Pour un service réellement inutile, `mask` est la bonne réponse.
6. **Chaque service en écoute est une dette de sécurité.**
   La commande `ss -tulpn` est la vérité terrain ; `systemctl list-unit-files` n'est qu'une intention de configuration.
7. **Toujours valider avant d'appliquer.**
   `sshd -t`, `visudo -c`, `ufw status` : trois contrôles non destructifs qui évitent un verrouillage complet.
8. **Un accès de secours est obligatoire.**
   Console WSL, session SSH déjà ouverte, snapshot : le durcissement sans plan de retour arrière est un incident en attente.

### 7.2 Ce que ce lab m'a appris techniquement

| Domaine | Acquisition clé |
|---------|-----------------|
| Comptes & `sudo` | Création de compte nominatif, politique `sudoers` dédiée, verrouillage de `root`, bannière légale |
| Permissions POSIX | Lecture fine des modes (`rwx`, SUID/SGID/sticky), `find -perm`, `umask 027`, ownership `root:shadow` |
| OpenSSH | Drop-ins `sshd_config.d`, `sshd -T`, `AuthenticationMethods`, `AllowUsers`, clés ED25519 + passphrase |
| Réseau | `ufw` (default deny, `limit` anti-bruteforce, logging), lecture `iptables`/`nft`, diagnostic NAT WSL |
| systemd | `list-unit-files`, `is-enabled`, `mask`, `--failed`, `unattended-upgrades`, corrélation avec `ss` |
| Méthodologie | Validation systématique, sauvegarde des fichiers, test dans un second terminal, documentation des écarts |

### 7.3 Limites du lab & pistes d'évolution

| Limite actuelle | Amélioration envisagée |
|-----------------|------------------------|
| Pas de protection anti-bruteforce applicative | **fail2ban** ou `sshd` + `PerSourcePenalties` |
| Pas de détection d'intrusion hôte | **auditd** + règles d'audit sur `/etc/passwd`, `sudoers`, `~/.ssh` |
| Durcissement partiel du noyau | `sysctl` : `kernel.dmesg_restrict`, `net.ipv4.conf.all.rp_filter`, `kernel.kptr_restrict` |
| Pas de conformité formalisée | **Lynis**, **OpenSCAP** (profil CIS Ubuntu 24.04), `debsecan` |
| Configuration manuelle | Industrialisation **Ansible** (rôles `ssh_hardening`, `ufw`, `users`) |
| Pas de MFA | `libpam-google-authenticator` ou `pam_ssh` en second facteur |
| Mises à jour non supervisées | `unattended-upgrades` + revue mensuelle des CVE (`ubuntu-security-status`) |
| Environnement WSL (NAT) | Reproduction sur VM/cloud pour valider les règles réseau de bout en bout |

### 7.4 Checklist de durcissement réutilisable

- [x] Compte d'administration nominatif, membre de `sudo`
- [x] Compte `root` verrouillé + login SSH interdit
- [x] Politique `sudoers` dédiée, validée (`visudo -c`)
- [x] `~/.ssh` `700`, clés `600`, home `750`
- [x] Fichiers système conformes (`/etc/shadow` `640 root:shadow`, etc.)
- [x] `PermitRootLogin no`, `PasswordAuthentication no`, `PermitEmptyPasswords no`
- [x] `AllowUsers` restreint, `MaxAuthTries` bas
- [x] `sshd -t` validé avant chaque rechargement
- [x] `ufw` actif, `default deny incoming`, seul 22/TCP ouvert en `limit`
- [x] Services inutiles désactivés/masqués, `systemctl --failed` vide
- [x] Mises à jour de sécurité automatiques activées
- [x] Journalisation (`LogLevel VERBOSE`, `ufw logging low`) opérationnelle
- [x] Tests de non-régression exécutés (SSH, UFW, permissions, comptes)
- [x] Procédure de retour arrière documentée

---

## 8. Références

- [Ubuntu Server — Security documentation](https://documentation.ubuntu.com/server/explanation/security/)
- [OpenSSH `sshd_config(5)`](https://man.openbsd.org/sshd_config)
- [UFW — Ubuntu Community Help](https://help.ubuntu.com/community/UFW)
- [systemd — `systemctl` manuel](https://www.freedesktop.org/software/systemd/man/systemctl.html)
- [CIS Ubuntu Linux 24.04 LTS Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [Microsoft Learn — WSL : systemd](https://learn.microsoft.com/windows/wsl/systemd)
- [NIST SP 800-123 — Guide to General Server Security](https://csrc.nist.gov/pubs/sp/800/123/final)

---

## Structure du dépôt

```
lab05-linux-hardening/
├── README.md
├── hardening.sh                   # automatisation des étapes 1 → 5 (idempotent, --dry-run)
├── scripts/
│   └── security-audit.sh          # audit post-durcissement (voir §5.5)
├── configs/
│   ├── 99-hardening.conf          # drop-in sshd
│   ├── 90-sysadmin-sec            # drop-in sudoers
│   └── 99-umask.sh                # profil umask 027
└── docs/
    └── screenshots/
        ├── 01-ufw-status-verbose.png
        ├── 02-sshd-T.png
        └── 03-systemctl-enabled.png
```

---

<p align="center">
  <em>Lab 05 — Linux Server Hardening · Ubuntu 24.04 LTS (WSL2) · Bash / OpenSSH / UFW / systemd</em><br>
  Réalisé dans un cadre d'apprentissage — environnement local isolé, aucune donnée de production.
</p>
