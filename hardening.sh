#!/usr/bin/env bash
# =============================================================================
#  hardening.sh — Lab 05 : Linux Server Hardening (Ubuntu 24.04 / WSL2)
# =============================================================================
#  Automatise les 5 étapes du lab :
#    1. Compte dédié sysadmin_sec (+ sudo) et verrouillage de root
#    2. Durcissement des permissions (POSIX, umask, ~/.ssh en 700)
#    3. Configuration OpenSSH : /etc/ssh/sshd_config.d/hardening.conf
#       (PermitRootLogin no, PasswordAuthentication no, clés uniquement)
#    4. Pare-feu UFW : deny incoming, seul le port SSH est exposé (limit)
#    5. Audit systemd : désactivation/masquage des services inutiles
#
#  Usage :
#    sudo ./hardening.sh                 # exécution complète (interactive)
#    sudo ./hardening.sh --dry-run       # simulation, aucune modification
#    sudo ./hardening.sh --check         # audit en lecture seule
#    sudo ./hardening.sh --only ssh,ufw  # étapes ciblées
#    sudo ./hardening.sh -y              # sans confirmation
#
#  Auteur  : Marwane — Lab 05
#  Licence : MIT
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="${0##*/}"
readonly SCRIPT_VERSION="1.0.0"

# -----------------------------------------------------------------------------
# Paramètres (surchargables par variables d'environnement)
# -----------------------------------------------------------------------------
TARGET_USER="${HARDENING_USER:-sysadmin_sec}"
SSHD_DROPIN="${HARDENING_SSHD_DROPIN:-/etc/ssh/sshd_config.d/hardening.conf}"
SUDOERS_DROPIN="${HARDENING_SUDOERS_DROPIN:-/etc/sudoers.d/90-sysadmin-sec}"
UMASK_PROFILE="${HARDENING_UMASK_PROFILE:-/etc/profile.d/99-umask.sh}"
BANNER_FILE="/etc/issue.net"
LOG_DIR="${HARDENING_LOG_DIR:-/var/log}"
BACKUP_BASE="${HARDENING_BACKUP_DIR:-/var/backups/lab05-hardening}"
ALLOW_USERS="${HARDENING_ALLOW_USERS:-}"

readonly UNNEEDED_SERVICES=(
  avahi-daemon
  cups
  cups-browsed
  bluetooth
  ModemManager
  whoopsie
  apport
)

# -----------------------------------------------------------------------------
# État interne
# -----------------------------------------------------------------------------
DRY_RUN=0
ASSUME_YES=0
FORCE=0
RESET_UFW=0
CHECK_ONLY=0
STEPS="users,permissions,ssh,ufw,services"
LOG_FILE="/dev/null"
BACKUP_DIR=""
HAVE_KEYS=0
SSH_PORT="22"

# -----------------------------------------------------------------------------
# Couleurs / journalisation
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_DIM=$'\033[2m'
else
  C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_DIM=""
fi

log_info()  { printf '%s[*]%s %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
log_ok()    { printf '%s[+]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
log_warn()  { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
log_err()   { printf '%s[x]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }

# Joins les arguments avec une espace simple (IFS global = newline/tab)
fmt_cmd() { local IFS=' '; printf '%s' "$*"; }
log_dry() { printf '%s[dry]%s %s\n' "$C_DIM" "$C_RESET" "$(fmt_cmd "$@")"; }

step() {
  local line
  line="$(printf '─%.0s' {1..58})"
  printf '\n%s%s── %s %s%s\n' "$C_BOLD" "$C_BLUE" "$*" "$line" "$C_RESET"
}

die() { log_err "$*"; exit 1; }

on_error() {
  local code=$1 line=$2
  log_err "Échec inattendu (ligne $line, code $code)."
  log_err "Journal : $LOG_FILE"
  log_err "Sauvegardes : ${BACKUP_DIR:-aucune}"
}
trap 'on_error $? $LINENO' ERR

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
usage() {
  cat <<EOF
$SCRIPT_NAME v$SCRIPT_VERSION — durcissement Ubuntu (Lab 05)

Usage : sudo ./$SCRIPT_NAME [options]

Options :
  -n, --dry-run        Simule les actions, sans rien modifier
  -y, --yes            Ne pose aucune question (mode non interactif)
  -f, --force          Outrepasse les garde-fous (déconseillé)
      --check          Audit en lecture seule, aucune modification
      --only LIST      Exécute seulement certaines étapes
                       (users, permissions, ssh, ufw, services)
      --skip LIST      Ignore certaines étapes
      --user NAME      Compte d'administration cible (défaut : $TARGET_USER)
      --reset-ufw      Réinitialise UFW avant d'appliquer les règles
  -h, --help           Affiche cette aide
  -V, --version        Affiche la version

Variables d'environnement :
  HARDENING_USER           Compte cible           (défaut : sysadmin_sec)
  HARDENING_ALLOW_USERS    AllowUsers SSH         (défaut : \$HARDENING_USER)
  HARDENING_BACKUP_DIR     Répertoire de sauvegarde

Exemples :
  sudo ./$SCRIPT_NAME --dry-run
  sudo ./$SCRIPT_NAME --only ssh,ufw -y
  sudo ./$SCRIPT_NAME --check
EOF
}

run() {
  # Exécute (ou simule) une commande, en la traçant
  if (( DRY_RUN )); then
    log_dry "$@"
    return 0
  fi
  printf '%s$%s %s\n' "$C_DIM" "$C_RESET" "$(fmt_cmd "$@")"
  "$@"
}

confirm() {
  (( ASSUME_YES )) && return 0
  local answer
  read -r -p "$(printf '%s%s%s [y/N] ' "$C_YELLOW" "$1" "$C_RESET")" answer || return 1
  [[ "$answer" =~ ^([yYoO]|yes|oui)$ ]]
}

have_systemd() {
  [[ -d /run/systemd/system ]]
}

ssh_port() {
  local port=""
  if command -v sshd >/dev/null 2>&1; then
    port="$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2; exit }' || true)"
  fi
  [[ -n "$port" ]] || port=22
  printf '%s' "$port"
}

is_step_enabled() {
  [[ ",$STEPS," == *",$1,"* ]]
}

ssh_version_ge_98() {
  local v
  v="$(ssh -V 2>&1 | sed -E 's/^OpenSSH_([0-9]+\.[0-9]+).*/\1/')"
  [[ -n "$v" ]] || return 1
  # true si la liste "9.8, v" est déjà triée → 9.8 <= v
  printf '9.8\n%s\n' "$v" | sort -V -C
}

backup_file() {
  local src="$1"
  [[ -e "$src" ]] || return 0
  local rel="${src#/}"
  local dst="$BACKUP_DIR/${rel//\//_}"
  run mkdir -p "$BACKUP_DIR"
  if (( DRY_RUN )); then
    log_dry "sauvegarde $src → $dst"
  else
    cp -a "$src" "$dst"
    log_ok "sauvegarde : $src → $dst"
  fi
}

# Écrit un fichier root:root avec un contenu fourni sur stdin.
# usage: write_root_file <chemin> <mode> <<'EOF' ... EOF
write_root_file() {
  local path="$1" mode="$2"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp"

  if (( DRY_RUN )); then
    log_dry "écrirait $path (mode $mode, root:root) :"
    sed 's/^/      │ /' "$tmp"
  else
    backup_file "$path"
    install -o root -g root -m "$mode" "$tmp" "$path"
    log_ok "fichier écrit : $path ($mode root:root)"
  fi
  rm -f "$tmp"
}

ensure_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    return 0
  fi
  command -v sudo >/dev/null 2>&1 || die "Ce script doit être exécuté en root (sudo absent)."
  log_info "Élévation de privilèges via sudo…"
  exec sudo --preserve-env=HARDENING_USER,HARDENING_ALLOW_USERS,HARDENING_BACKUP_DIR,HARDENING_LOG_DIR \
    bash "$0" "$@"
}

setup_logging() {
  mkdir -p "$LOG_DIR"
  LOG_FILE="$LOG_DIR/hardening-$(date +%Y%m%d-%H%M%S).log"
  touch "$LOG_FILE"
  chmod 640 "$LOG_FILE"
  # Duplique toute la sortie vers le journal (et la console)
  exec > >(tee -a "$LOG_FILE") 2>&1
  log_info "Journal : $LOG_FILE"
}

setup_backups() {
  BACKUP_DIR="$BACKUP_BASE/$(date +%Y%m%d-%H%M%S)"
  run mkdir -p "$BACKUP_DIR"
  log_info "Sauvegardes : $BACKUP_DIR"
}

# -----------------------------------------------------------------------------
# Étape 1 — Comptes
# -----------------------------------------------------------------------------
step_users() {
  step "1/5 — Comptes : $TARGET_USER, sudo et verrouillage de root"

  local home="/home/$TARGET_USER"

  # Prérequis : sudo et groupe sudo
  if ! command -v sudo >/dev/null 2>&1; then
    log_warn "sudo absent : installation"
    run apt-get update -qq
    run apt-get install -y sudo
  fi
  if ! getent group sudo >/dev/null 2>&1; then
    run groupadd sudo
  fi

  if id "$TARGET_USER" >/dev/null 2>&1; then
    home="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
    log_ok "utilisateur existant : $TARGET_USER (uid=$(id -u "$TARGET_USER"), home=$home)"
  else
    log_info "création de l'utilisateur $TARGET_USER"
    if command -v adduser >/dev/null 2>&1; then
      if (( ASSUME_YES )); then
        run adduser --disabled-password --gecos "System Administrator (Security)" "$TARGET_USER"
        log_warn "compte créé sans mot de passe : définir avec 'sudo passwd $TARGET_USER' avant d'utiliser sudo"
      else
        run adduser --gecos "System Administrator (Security)" "$TARGET_USER"
      fi
    else
      # Repli si adduser n'est pas disponible (image minimale)
      run useradd --create-home --shell /bin/bash \
        --comment "System Administrator (Security)" "$TARGET_USER"
      if (( ASSUME_YES )); then
        log_warn "compte créé sans mot de passe : définir avec 'sudo passwd $TARGET_USER'"
      else
        log_info "définir le mot de passe de $TARGET_USER"
        passwd "$TARGET_USER"
      fi
    fi
  fi

  if id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx sudo; then
    log_ok "membre du groupe sudo"
  else
    run usermod -aG sudo "$TARGET_USER"
    log_ok "ajout au groupe sudo"
  fi

  local group
  group="$(id -gn "$TARGET_USER" 2>/dev/null || echo "$TARGET_USER")"

  # Politique sudo dédiée (validée avant installation)
  log_info "politique sudo dédiée : $SUDOERS_DROPIN"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
# Lab 05 — politique sudo du compte d'administration
# Journalisation : assurée par défaut dans /var/log/auth.log
Defaults:$TARGET_USER  timestamp_timeout=5
Defaults:$TARGET_USER  passwd_tries=3
Defaults:$TARGET_USER  lecture=always

$TARGET_USER ALL=(ALL:ALL) ALL
EOF
  if (( DRY_RUN )); then
    log_dry "écrirait $SUDOERS_DROPIN (440 root:root) :"
    sed 's/^/      │ /' "$tmp"
  else
    visudo -cf "$tmp" >/dev/null || { rm -f "$tmp"; die "syntaxe sudoers invalide — abandon (aucune modification)"; }
    backup_file "$SUDOERS_DROPIN"
    install -o root -g root -m 0440 "$tmp" "$SUDOERS_DROPIN"
    log_ok "fichier écrit : $SUDOERS_DROPIN (440 root:root)"
  fi
  rm -f "$tmp"

  # Répertoire home + ~/.ssh (700) + authorized_keys (600)
  log_info "permissions du home et de ~/.ssh"
  if (( ! DRY_RUN )); then
    chown "$TARGET_USER:$group" "$home"
    chmod 750 "$home"
  else
    log_dry "chown $TARGET_USER:$group $home && chmod 750 $home"
  fi

  run install -d -m 700 -o "$TARGET_USER" -g "$group" "$home/.ssh"
  run chown "$TARGET_USER:$group" "$home/.ssh"
  run chmod 700 "$home/.ssh"
  if [[ ! -e "$home/.ssh/authorized_keys" ]]; then
    run install -m 600 -o "$TARGET_USER" -g "$group" /dev/null "$home/.ssh/authorized_keys"
  else
    run chmod 600 "$home/.ssh/authorized_keys"
    run chown "$TARGET_USER:$group" "$home/.ssh/authorized_keys"
  fi

  # Amorçage de la clé publique depuis le compte appelant (SUDO_USER)
  local ak="$home/.ssh/authorized_keys"
  if [[ -s "$ak" ]]; then
    HAVE_KEYS=1
    log_ok "authorized_keys déjà renseigné ($(grep -cE '^(ssh-|ecdsa-|sk-)' "$ak" 2>/dev/null || echo 0) clé(s))"
  elif (( ! DRY_RUN )); then
    local src_user="${SUDO_USER:-}" src_home="" pub=""
    if [[ -n "$src_user" && "$src_user" != "root" ]]; then
      src_home="$(getent passwd "$src_user" | cut -d: -f6 || true)"
      if [[ -n "$src_home" ]]; then
        pub="$(find "$src_home/.ssh" -maxdepth 1 -name '*.pub' -type f 2>/dev/null | head -n1 || true)"
      fi
    fi
    if [[ -n "$pub" && -r "$pub" ]]; then
      cat "$pub" >>"$ak"
      run chown "$TARGET_USER:$group" "$ak"
      run chmod 600 "$ak"
      HAVE_KEYS=1
      log_ok "clé publique importée depuis $pub"
    else
      log_warn "aucune clé publique trouvée pour $TARGET_USER"
      log_warn "→ copier une clé avant de désactiver les mots de passe :"
      log_warn "  ssh-copy-id -i ~/.ssh/id_ed25519.pub $TARGET_USER@<hôte>"
    fi
  else
    log_dry "importerait une clé publique de ${SUDO_USER:-<utilisateur>} vers $ak"
  fi

  # Bannière légale
  log_info "bannière légale : $BANNER_FILE"
  write_root_file "$BANNER_FILE" 644 <<'EOF'
***************************************************************************
*  Accès réservé. Toute connexion est enregistrée et contrôlée.            *
*  Les accès non autorisés font l'objet de poursuites.                     *
***************************************************************************
EOF

  # Verrouillage du compte root direct
  if (( DRY_RUN )); then
    log_dry "passwd -l root"
  elif [[ "$(passwd -S root 2>/dev/null | awk '{print $2}')" == "L" ]]; then
    log_ok "compte root déjà verrouillé"
  else
    run passwd -l root
    log_ok "compte root verrouillé (login direct impossible)"
  fi
}

# -----------------------------------------------------------------------------
# Étape 2 — Permissions
# -----------------------------------------------------------------------------
step_permissions() {
  step "2/5 — Durcissement des permissions (chmod / chown)"

  local home group
  home="$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6 || true)"
  [[ -n "$home" ]] || home="/home/$TARGET_USER"
  group="$(id -gn "$TARGET_USER" 2>/dev/null || echo "$TARGET_USER")"

  # Fichiers d'authentification par clé
  run chmod 750 "$home"
  run chmod 700 "$home/.ssh"
  [[ -f "$home/.ssh/authorized_keys" ]] && run chmod 600 "$home/.ssh/authorized_keys"
  run chown -R "$TARGET_USER:$group" "$home/.ssh"

  # Bases de comptes et fichiers système sensibles
  if [[ -f /etc/shadow ]]; then
    run chown root:shadow /etc/shadow
    run chmod 640 /etc/shadow
  fi
  if [[ -f /etc/gshadow ]]; then
    run chown root:shadow /etc/gshadow
    run chmod 640 /etc/gshadow
  fi
  run chown root:root /etc/passwd
  run chmod 644 /etc/passwd
  run chown root:root /etc/group
  run chmod 644 /etc/group

  # Configuration SSH
  if [[ -d /etc/ssh ]]; then
    run chmod 755 /etc/ssh
    if [[ -f /etc/ssh/sshd_config ]]; then
      run chown root:root /etc/ssh/sshd_config
      run chmod 600 /etc/ssh/sshd_config
    fi
    local key
    for key in /etc/ssh/ssh_host_*_key; do
      [[ -e "$key" ]] || continue
      run chown root:root "$key"
      run chmod 600 "$key"
    done
  fi

  # Sudo et journaux
  run chown root:root /etc/sudoers
  run chmod 440 /etc/sudoers
  run chmod 750 /etc/sudoers.d
  run chmod 750 /var/log

  # umask restrictif (027 → fichiers 640, répertoires 750)
  log_info "profil umask 027 : $UMASK_PROFILE"
  write_root_file "$UMASK_PROFILE" 644 <<'EOF'
# Lab 05 — umask restrictif : fichiers 640 (rw-r-----), répertoires 750 (rwxr-x---)
umask 027
EOF

  # Recherche de dérives (informatif)
  if (( CHECK_ONLY )); then
    log_info "fichiers inscriptibles par tous (hors /tmp, /proc, /sys) :"
    find / -xdev -type f -perm -0002 \
      ! -path "/tmp/*" ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null \
      | sed 's/^/      /' || true
  fi

  # Contrôle final
  if (( ! DRY_RUN )); then
    local mode
    mode="$(stat -c '%a' "$home/.ssh" 2>/dev/null || echo "?")"
    [[ "$mode" == "700" ]] && log_ok "~/.ssh = 700 (attendu)" || log_warn "~/.ssh = $mode (attendu 700)"
  fi
}

# -----------------------------------------------------------------------------
# Étape 3 — OpenSSH
# -----------------------------------------------------------------------------
step_ssh() {
  step "3/5 — OpenSSH : $SSHD_DROPIN"

  # Prérequis : serveur SSH installé et clés d'hôte présentes
  if ! command -v sshd >/dev/null 2>&1; then
    log_warn "openssh-server absent : installation"
    run apt-get update -qq
    run apt-get install -y openssh-server
  fi
  if ! compgen -G "/etc/ssh/ssh_host_*_key" >/dev/null; then
    log_warn "aucune clé d'hôte : génération (ssh-keygen -A)"
    run ssh-keygen -A
  fi

  # Garde-fou : ne jamais couper l'accès sans clé déjà en place
  local ak="/home/$TARGET_USER/.ssh/authorized_keys"
  if [[ -s "$ak" ]]; then
    HAVE_KEYS=1
  fi
  if (( ! HAVE_KEYS )) && (( ! FORCE )) && (( ! DRY_RUN )); then
    die "aucune clé publique dans $ak : désactiver les mots de passe couperait l'accès SSH.
     → installer une clé (ssh-copy-id) puis relancer, ou utiliser --force si vous avez un accès console."
  fi

  # Sauvegarde de la configuration existante
  backup_file /etc/ssh/sshd_config

  # Drop-in prioritaire (première valeur rencontrée = celle-ci)
  local allow_line=""
  [[ -n "$ALLOW_USERS" ]] && allow_line="AllowUsers $ALLOW_USERS"

  log_info "écriture de la configuration durcie"
  write_root_file "$SSHD_DROPIN" 600 <<EOF
# =============================================================================
# Lab 05 — OpenSSH hardening (généré par $SCRIPT_NAME $(date +%F))
# Inclus par /etc/ssh/sshd_config : "Include /etc/ssh/sshd_config.d/*.conf"
# La PREMIÈRE valeur rencontrée gagne → ce fichier prime sur la config par défaut.
# =============================================================================

# --- Authentification : clés uniquement, jamais root -------------------------
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthenticationMethods publickey
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30

# --- Restriction nominative --------------------------------------------------
$allow_line

# --- Réduction de la surface fonctionnelle -----------------------------------
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no

# --- Robustesse des sessions -------------------------------------------------
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
LogLevel VERBOSE
Banner /etc/issue.net
EOF

  # Directive conditionnée à la version d'OpenSSH (>= 9.8)
  if ssh_version_ge_98; then
    if (( DRY_RUN )); then
      log_dry "ajouterait 'PerSourceMaxStartups 3' (OpenSSH >= 9.8 détecté)"
    else
      printf '\n# OpenSSH >= 9.8 : limitation par IP source\nPerSourceMaxStartups 3\n' >>"$SSHD_DROPIN"
      log_ok "PerSourceMaxStartups 3 ajouté (OpenSSH >= 9.8)"
    fi
  else
    log_info "OpenSSH < 9.8 : PerSourceMaxStartups non supporté, directive omise"
  fi

  if (( DRY_RUN )); then
    log_dry "sshd -t && systemctl reload ssh"
    return 0
  fi

  # S'assurer que le fichier principal inclut bien le répertoire de drop-ins
  if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config 2>/dev/null; then
    log_warn "Include sshd_config.d absent : ajout en tête de /etc/ssh/sshd_config"
    run sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
  fi

  # Validation OBLIGATOIRE avant rechargement
  # sshd exige /run/sshd (créé normalement par systemd) — présent aussi en conteneur/WSL
  if [[ ! -d /run/sshd ]]; then
    log_warn "/run/sshd absent : création (nécessaire à sshd -t)"
    run install -d -m 0755 -o root -g root /run/sshd
  fi

  if ! sshd -t; then
    log_err "configuration sshd invalide — restauration"
    if [[ -f "$BACKUP_DIR/etc_ssh_sshd_config" ]]; then
      cp -a "$BACKUP_DIR/etc_ssh_sshd_config" /etc/ssh/sshd_config
    fi
    local dropin_backup="$BACKUP_DIR/etc_ssh_sshd_config.d_$(basename "$SSHD_DROPIN")"
    if [[ -f "$dropin_backup" ]]; then
      cp -a "$dropin_backup" "$SSHD_DROPIN"
      log_warn "drop-in précédent restauré"
    else
      rm -f "$SSHD_DROPIN"
    fi
    die "configuration sshd rejetée : aucune modification appliquée"
  fi
  log_ok "sshd -t : configuration valide"

  if have_systemd; then
    run systemctl reload ssh 2>/dev/null || run systemctl reload sshd 2>/dev/null || run systemctl restart ssh
    run systemctl enable ssh >/dev/null 2>&1 || true
  else
    log_warn "systemd indisponible : redémarrage via 'service ssh restart'"
    run service ssh restart || log_warn "échec du redémarrage de ssh (vérifier manuellement)"
  fi
  log_ok "démon SSH rechargé (sessions existantes préservées)"

  # Port effectif pour l'étape UFW
  SSH_PORT="$(ssh_port)"
  if [[ "$SSH_PORT" != "22" ]]; then
    log_warn "port SSH effectif : $SSH_PORT (penser à adapter les règles UFW)"
  fi
}

# -----------------------------------------------------------------------------
# Étape 4 — UFW
# -----------------------------------------------------------------------------
step_ufw() {
  step "4/5 — Pare-feu UFW"

  if ! command -v ufw >/dev/null 2>&1; then
    log_warn "ufw absent : installation"
    run apt-get update -qq
    run apt-get install -y ufw
  fi

  SSH_PORT="$(ssh_port)"
  log_info "port SSH effectif : $SSH_PORT"

  if (( RESET_UFW )); then
    confirm "Réinitialiser toutes les règles UFW existantes ?" || die "réinitialisation annulée"
    run ufw --force reset
  fi

  # Politique par défaut : tout refuser en entrée
  run ufw --force default deny incoming
  run ufw --force default allow outgoing
  run ufw --force default deny routed

  # Ouvrir SSH AVANT activation (sinon perte d'accès)
  log_info "autorisation du port $SSH_PORT/tcp (rate-limited)"
  if (( DRY_RUN )); then
    log_dry "ufw limit $SSH_PORT/tcp comment 'SSH admin (rate-limited)'"
  elif ! ufw limit "$SSH_PORT/tcp" comment 'SSH admin (rate-limited)' 2>/dev/null; then
    log_warn "syntaxe 'comment' non supportée par cette version d'UFW → règle simple"
    run ufw limit "$SSH_PORT/tcp"
  else
    log_ok "règle SSH en place (limit)"
  fi

  run ufw logging low

  # Activation
  log_info "activation du pare-feu (le port $SSH_PORT/tcp est déjà autorisé)"
  run ufw --force enable

  if have_systemd; then
    run systemctl enable ufw >/dev/null 2>&1 || log_warn "impossible d'activer ufw.service au démarrage"
  else
    log_warn "systemd indisponible : activer ufw au démarrage manuellement"
  fi

  if (( ! DRY_RUN )); then
    log_info "état UFW :"
    ufw status verbose | sed 's/^/      /'
  fi
}

# -----------------------------------------------------------------------------
# Étape 5 — Services systemd
# -----------------------------------------------------------------------------
step_services() {
  step "5/5 — Audit systemd et désactivation des services inutiles"

  if ! have_systemd; then
    log_warn "systemd n'est pas PID 1 (WSL ?) : étape ignorée"
    log_warn "activer systemd via [boot] systemd=true dans /etc/wsl.conf, puis 'wsl --shutdown'"
    return 0
  fi

  local svc unit state
  for svc in "${UNNEEDED_SERVICES[@]}"; do
    unit="$svc.service"
    if ! systemctl list-unit-files "$unit" >/dev/null 2>&1; then
      continue
    fi
    state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    if [[ "$state" == "masked" ]]; then
      log_ok "$unit déjà masqué"
      continue
    fi
    log_info "désactivation + masquage : $unit"
    run systemctl disable --now "$unit" || log_warn "échec disable sur $unit"
    run systemctl mask "$unit" || log_warn "échec mask sur $unit"
  done

  # snapd uniquement si aucun paquet snap n'est installé
  if command -v snap >/dev/null 2>&1; then
    if ! snap list 2>/dev/null | tail -n +2 | grep -q .; then
      log_info "aucun paquet snap : désactivation de snapd"
      run systemctl disable --now snapd.socket snapd.service 2>/dev/null || true
      run systemctl mask snapd.service 2>/dev/null || true
    else
      log_ok "des paquets snap sont installés : snapd conservé"
    fi
  fi

  # Mises à jour de sécurité automatiques
  if dpkg -s unattended-upgrades >/dev/null 2>&1; then
    if [[ "$(systemctl is-enabled unattended-upgrades 2>/dev/null || true)" == "enabled" ]]; then
      log_ok "unattended-upgrades déjà activé"
    else
      run systemctl enable --now unattended-upgrades
      log_ok "unattended-upgrades activé"
    fi
  else
    log_warn "unattended-upgrades absent : sudo apt install unattended-upgrades"
  fi

  if (( ! DRY_RUN )); then
    local failed
    failed="$(systemctl --failed --no-legend 2>/dev/null | wc -l)"
    if [[ "$failed" -eq 0 ]]; then
      log_ok "aucune unité en échec"
    else
      log_warn "$failed unité(s) en échec : systemctl --failed"
    fi
  fi
}

# -----------------------------------------------------------------------------
# Vérification finale (lecture seule)
# -----------------------------------------------------------------------------
verify() {
  step "Vérification — état de sécurité"

  local ak="/home/$TARGET_USER/.ssh/authorized_keys"

  printf '\n%s[Comptes]%s\n' "$C_BOLD" "$C_RESET"
  printf '  root          : %s\n' "$(passwd -S root 2>/dev/null || echo '?')"
  printf '  UID 0         : %s\n' "$(awk -F: '$3==0 {printf "%s ", $1}' /etc/passwd)"
  printf '  %-13s : %s\n' "$TARGET_USER" "$(id "$TARGET_USER" 2>/dev/null || echo 'absent')"
  printf '  groupes sudo  : %s\n' "$(getent group sudo | cut -d: -f4)"

  printf '\n%s[SSH effectif]%s\n' "$C_BOLD" "$C_RESET"
  if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null \
      | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|allowusers|maxauthtries|authenticationmethods) ' \
      | sed 's/^/  /' || true
  else
    printf '  sshd absent\n'
  fi

  printf '\n%s[Permissions]%s\n' "$C_BOLD" "$C_RESET"
  local p
  for p in "/home/$TARGET_USER" "/home/$TARGET_USER/.ssh" "$ak" \
           /etc/ssh/sshd_config "$SSHD_DROPIN" "$SUDOERS_DROPIN"; do
    [[ -e "$p" ]] && stat -c '  %A %U:%G %n' "$p" || printf '  (absent) %s\n' "$p"
  done

  printf '\n%s[Pare-feu]%s\n' "$C_BOLD" "$C_RESET"
  ufw status verbose 2>/dev/null | sed 's/^/  /' || printf '  ufw non disponible\n'

  printf '\n%s[Services]%s\n' "$C_BOLD" "$C_RESET"
  if have_systemd; then
    systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null \
      | awk '{print "  " $1}' | head -n 20 || true
  else
    printf '  systemd indisponible\n'
  fi
}

# -----------------------------------------------------------------------------
# Arguments
# -----------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n|--dry-run) DRY_RUN=1 ;;
      -y|--yes)     ASSUME_YES=1 ;;
      -f|--force)   FORCE=1 ;;
      --check)      CHECK_ONLY=1 ;;
      --reset-ufw)  RESET_UFW=1 ;;
      --user)       TARGET_USER="${2:?--user requiert une valeur}"; shift ;;
      --user=*)     TARGET_USER="${1#*=}" ;;
      --only)       STEPS="${2:?--only requiert une liste}"; shift ;;
      --only=*)     STEPS="${1#*=}" ;;
      --skip)       local skip="${2:?--skip requiert une liste}"; shift
                    local s
                    for s in ${skip//,/ }; do STEPS="${STEPS//$s,/}"; STEPS="${STEPS//,$s/}"; done ;;
      -h|--help)    usage; exit 0 ;;
      -V|--version) printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
      *)            die "option inconnue : $1 (voir --help)" ;;
    esac
    shift
  done

  if (( CHECK_ONLY )); then
    STEPS=""
  fi

  STEPS=",$STEPS,"
  STEPS="${STEPS//,,/,}"
  # normalise en liste simple pour is_step_enabled
  STEPS="${STEPS#,}"
  STEPS="${STEPS%,}"

  # AllowUsers par défaut = compte cible (après prise en compte de --user)
  if [[ -z "$ALLOW_USERS" ]]; then
    ALLOW_USERS="$TARGET_USER"
  fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"

  printf '%s\n' "=============================================================="
  printf ' %s v%s — Lab 05 : Linux Server Hardening\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
  printf '%s\n' "=============================================================="

  if (( ! CHECK_ONLY )); then
    ensure_root "$@"
    setup_logging
    setup_backups
  else
    (( EUID == 0 )) || log_warn "mode --check sans root : certaines lectures seront incomplètes"
  fi

  printf '  cible        : %s\n' "$TARGET_USER"
  printf '  drop-in SSH  : %s\n' "$SSHD_DROPIN"
  printf '  étapes       : %s\n' "${STEPS:-aucune (audit uniquement)}"
  (( DRY_RUN )) && printf '  mode         : SIMULATION (aucune modification)\n'

  if (( CHECK_ONLY )); then
    verify
    exit 0
  fi

  if ! confirm "Appliquer le durcissement sur cette machine ?"; then
    log_info "annulé — aucune modification"
    exit 0
  fi

  if is_step_enabled users;       then step_users;       fi
  if is_step_enabled permissions; then step_permissions; fi
  if is_step_enabled ssh;         then step_ssh;         fi
  if is_step_enabled ufw;         then step_ufw;         fi
  if is_step_enabled services;    then step_services;    fi
  if [[ -z "$STEPS" ]]; then log_warn "aucune étape sélectionnée"; fi

  if (( DRY_RUN )); then
    step "Simulation terminée — aucune modification appliquée"
    exit 0
  fi

  verify

  step "Terminé"
  log_ok "durcissement appliqué. Journal : $LOG_FILE"
  log_warn "testez une NOUVELLE connexion SSH avant de fermer cette session."
  log_warn "retour arrière : sauvegardes dans $BACKUP_DIR"
}

main "$@"
