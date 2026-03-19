#!/usr/bin/env bash
# =============================================================================
#  server_setup.sh — Server hardening script (no Telegram)
#  - Creates a sudo user with fish shell
#  - Moves SSHD to port 8678
#  - SSH honeypot on port 22 (via socat)
#  - Configures fail2ban
#  - All events logged to /var/log/ssh-events.log
# =============================================================================

set -euo pipefail

# ─── CONFIG ──────────────────────────────────────────────────────────────────
NEW_USER="${NEW_USER:-}"
SSH_PORT=8678
HONEYPOT_PORT=22
EVENT_LOG="/var/log/ssh-events.log"
# ─────────────────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root"

if [[ -z "$NEW_USER" ]]; then
    read -rp "New username: " NEW_USER
fi
[[ -z "$NEW_USER" ]] && die "Username required"

# ─── 1. Install dependencies ──────────────────────────────────────────────────
info "Installing packages..."
apt-get update -qq
apt-get install -y -qq \
    fish sudo openssh-server fail2ban \
    socat geoip-bin geoip-database \
    2>/dev/null

# Determine correct sshd service name (Ubuntu uses 'ssh', others use 'sshd')
if systemctl list-units --full --all | grep -q 'sshd.service'; then
    SSHD_SVC="sshd"
else
    SSHD_SVC="ssh"
fi

# ─── 2. Create user with fish shell ───────────────────────────────────────────
info "Creating user '$NEW_USER'..."
if id "$NEW_USER" &>/dev/null; then
    warn "User '$NEW_USER' already exists, skipping creation"
else
    useradd -m -s "$(command -v fish)" "$NEW_USER"
    passwd "$NEW_USER"
fi

info "Adding '$NEW_USER' to sudo group..."
usermod -aG sudo "$NEW_USER"

# ─── 3. Move SSHD to port 8678 ───────────────────────────────────────────────
info "Configuring SSHD on port $SSH_PORT..."
SSHD_CONF="/etc/ssh/sshd_config"

cp "$SSHD_CONF" "${SSHD_CONF}.bak.$(date +%s)"

sed -i "s/^#\?Port .*/Port $SSH_PORT/" "$SSHD_CONF"
grep -q "^Port " "$SSHD_CONF" || echo "Port $SSH_PORT" >> "$SSHD_CONF"

cat >> "$SSHD_CONF" <<EOF

# === Hardening added by server_setup.sh ===
PermitRootLogin no
PasswordAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
AllowUsers $NEW_USER
EOF

systemctl restart "$SSHD_SVC"
info "SSHD restarted on port $SSH_PORT (service: $SSHD_SVC)"

if command -v ufw &>/dev/null; then
    ufw allow "$SSH_PORT"/tcp comment "SSH real" 2>/dev/null || true
    info "ufw: allowed port $SSH_PORT"
fi

# ─── 4. Event log helper ──────────────────────────────────────────────────────
LOG_SCRIPT="/usr/local/bin/ssh_log_event.sh"
info "Installing event logger → $LOG_SCRIPT"

cat > "$LOG_SCRIPT" <<LOGEOF
#!/usr/bin/env bash
# Usage: ssh_log_event.sh <ip> <event_type> [extra_info]
IP="\${1:-unknown}"
EVENT="\${2:-unknown}"
EXTRA="\${3:-}"

LOG_FILE="$EVENT_LOG"
TIMESTAMP=\$(date '+%Y-%m-%d %H:%M:%S')

# GeoIP lookup
GEO=""
if command -v geoiplookup &>/dev/null; then
    GEO=\$(geoiplookup "\$IP" 2>/dev/null | head -1 | sed 's/GeoIP Country Edition: //')
fi
if [[ -z "\$GEO" || "\$GEO" == *"IP Address not found"* ]]; then
    GEO=\$(curl -sf --max-time 5 "http://ip-api.com/line/\$IP?fields=country,regionName,city,isp" \
          | paste -sd ', ' 2>/dev/null || echo "unknown")
fi

LINE="\$TIMESTAMP | \$EVENT | ip=\$IP | geo=\$GEO\${EXTRA:+ | \$EXTRA}"
echo "\$LINE" >> "\$LOG_FILE"
logger -t ssh-monitor "\$LINE"
LOGEOF

chmod +x "$LOG_SCRIPT"
touch "$EVENT_LOG"
chmod 640 "$EVENT_LOG"

# ─── 5. SSH Honeypot on port 22 ───────────────────────────────────────────────
info "Setting up SSH honeypot on port $HONEYPOT_PORT..."

HONEYPOT_SCRIPT="/usr/local/bin/ssh_honeypot.sh"
cat > "$HONEYPOT_SCRIPT" <<'HPEOF'
#!/usr/bin/env bash
HONEYPOT_PORT=22

socat TCP-LISTEN:${HONEYPOT_PORT},reuseaddr,fork \
    SYSTEM:'IP=$SOCAT_PEERADDR; \
    /usr/local/bin/ssh_log_event.sh "$IP" "HONEYPOT_HIT" "port=22"; \
    printf "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"; \
    sleep 5' 2>/dev/null
HPEOF
chmod +x "$HONEYPOT_SCRIPT"

cat > /etc/systemd/system/ssh-honeypot.service <<EOF
[Unit]
Description=SSH Honeypot on port $HONEYPOT_PORT
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssh_honeypot.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ssh-honeypot
info "Honeypot service started"

# ─── 6. Configure fail2ban ───────────────────────────────────────────────────
info "Configuring fail2ban..."

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
port     = $SSH_PORT
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
bantime  = 24h
maxretry = 3
action   = %(action_mwl)s
           ssh-log-notify

[ssh-honeypot]
enabled  = true
port     = $HONEYPOT_PORT
filter   = ssh-honeypot
logpath  = /var/log/syslog
bantime  = 7d
maxretry = 1
action   = iptables-multiport[name=honeypot, port="$HONEYPOT_PORT"]
           ssh-log-notify
EOF

cat > /etc/fail2ban/filter.d/ssh-honeypot.conf <<'EOF'
[Definition]
failregex = ssh-monitor: .* ip=<HOST>
ignoreregex =
EOF

cat > /etc/fail2ban/action.d/ssh-log-notify.conf <<'EOF'
[Definition]
actionban   = /usr/local/bin/ssh_log_event.sh "<ip>" "F2B_BANNED"   "jail=<name> attempts=<failures>"
actionunban = /usr/local/bin/ssh_log_event.sh "<ip>" "F2B_UNBANNED" "jail=<name>"
EOF

systemctl restart fail2ban
info "fail2ban configured and restarted"

# ─── 7. Auth log watcher ─────────────────────────────────────────────────────
info "Installing auth log watcher service..."

WATCHER_SCRIPT="/usr/local/bin/ssh_auth_watch.sh"
cat > "$WATCHER_SCRIPT" <<'WEOF'
#!/usr/bin/env bash
AUTH_LOG="/var/log/auth.log"
[[ -f /var/log/secure ]] && AUTH_LOG="/var/log/secure"

tail -Fn0 "$AUTH_LOG" | while read -r LINE; do
    if echo "$LINE" | grep -qE "Failed (password|publickey)"; then
        IP=$(echo "$LINE" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
        USR=$(echo "$LINE" | grep -oP 'for \K\S+')
        [[ -n "$IP" ]] && /usr/local/bin/ssh_log_event.sh "$IP" "FAILED_LOGIN" "user=${USR:-?}"
    elif echo "$LINE" | grep -qE "Accepted (password|publickey)"; then
        IP=$(echo "$LINE" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
        USR=$(echo "$LINE" | grep -oP 'for \K\S+')
        [[ -n "$IP" ]] && /usr/local/bin/ssh_log_event.sh "$IP" "ACCEPTED_LOGIN" "user=${USR:-?}"
    fi
done
WEOF
chmod +x "$WATCHER_SCRIPT"

cat > /etc/systemd/system/ssh-auth-watch.service <<EOF
[Unit]
Description=SSH Auth Log Watcher
After=network.target rsyslog.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ssh_auth_watch.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ssh-auth-watch
info "Auth log watcher started"

# ─── 8. Summary ──────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup complete!${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo "  User        : $NEW_USER  (shell: fish, group: sudo)"
echo "  Real SSH    : port $SSH_PORT"
echo "  Honeypot    : port $HONEYPOT_PORT  (service: ssh-honeypot)"
echo "  fail2ban    : active (bans after 3 attempts, 24h)"
echo "  Event log   : $EVENT_LOG"
echo ""
warn "⚠ Open port $SSH_PORT in your firewall BEFORE closing this session!"
warn "⚠ Test SSH login as $NEW_USER on port $SSH_PORT before logging out!"
echo ""
echo "  View events : tail -f $EVENT_LOG"
echo ""
