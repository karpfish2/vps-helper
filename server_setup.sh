#!/usr/bin/env bash
# =============================================================================
#  server_setup.sh — Server hardening script
#  - Creates a sudo user with fish shell
#  - Moves SSHD to port 8678
#  - SSH honeypot on port 22 (via netcat / socat)
#  - Configures fail2ban
#  - Telegram alerts with GeoIP for all 22/sshd login attempts
# =============================================================================

set -euo pipefail

# ─── CONFIG ──────────────────────────────────────────────────────────────────
NEW_USER="${NEW_USER:-}"
TG_BOT_TOKEN="${TG_BOT_TOKEN:-}"
TG_CHAT_ID="${TG_CHAT_ID:-}"
SSH_PORT=8678
HONEYPOT_PORT=22
# ─────────────────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root"

# ─── Prompt for missing vars ──────────────────────────────────────────────────
if [[ -z "$NEW_USER" ]]; then
    read -rp "New username: " NEW_USER
fi
if [[ -z "$TG_BOT_TOKEN" ]]; then
    read -rp "Telegram Bot Token: " TG_BOT_TOKEN
fi
if [[ -z "$TG_CHAT_ID" ]]; then
    read -rp "Telegram Chat ID: " TG_CHAT_ID
fi
[[ -z "$NEW_USER" || -z "$TG_BOT_TOKEN" || -z "$TG_CHAT_ID" ]] && die "All three vars required"

# ─── 1. Install dependencies ──────────────────────────────────────────────────
info "Installing packages..."
apt-get update -qq
apt-get install -y -qq \
    fish sudo openssh-server fail2ban \
    socat curl jq geoip-bin geoip-database \
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
    passwd "$NEW_USER"        # interactive — sets password
fi

info "Adding '$NEW_USER' to sudo group..."
usermod -aG sudo "$NEW_USER"

# ─── 3. Move SSHD to port 8678 ───────────────────────────────────────────────
info "Configuring SSHD on port $SSH_PORT..."
SSHD_CONF="/etc/ssh/sshd_config"

# Backup
cp "$SSHD_CONF" "${SSHD_CONF}.bak.$(date +%s)"

# Replace/add Port directive
sed -i "s/^#\?Port .*/Port $SSH_PORT/" "$SSHD_CONF"
grep -q "^Port " "$SSHD_CONF" || echo "Port $SSH_PORT" >> "$SSHD_CONF"

# Harden while we're here
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

# Firewall (ufw if available)
if command -v ufw &>/dev/null; then
    ufw allow "$SSH_PORT"/tcp comment "SSH real" 2>/dev/null || true
    ufw deny  "$HONEYPOT_PORT"/tcp 2>/dev/null || true   # socat handles it before ufw sees it
    info "ufw rules updated"
fi

# ─── 4. Telegram helper ──────────────────────────────────────────────────────
TG_SCRIPT="/usr/local/bin/tg_alert.sh"
info "Installing Telegram alert script → $TG_SCRIPT"

cat > "$TG_SCRIPT" <<'TGEOF'
#!/usr/bin/env bash
# Usage: tg_alert.sh <ip> <event_type> [extra_info]
IP="${1:-unknown}"
EVENT="${2:-unknown}"
EXTRA="${3:-}"

BOT_TOKEN="__BOT_TOKEN__"
CHAT_ID="__CHAT_ID__"

# GeoIP lookup (geoiplookup, fallback to ip-api.com)
GEO=""
if command -v geoiplookup &>/dev/null; then
    GEO=$(geoiplookup "$IP" 2>/dev/null | head -1 | sed 's/GeoIP Country Edition: //')
fi
if [[ -z "$GEO" || "$GEO" == *"IP Address not found"* ]]; then
    GEO=$(curl -sf --max-time 5 "http://ip-api.com/line/$IP?fields=country,regionName,city,isp" \
          | paste -sd ', ' || echo "unknown")
fi

HOSTNAME=$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S %Z')

MSG="🚨 *SSH Alert* on \`${HOSTNAME}\`
Event: *${EVENT}*
IP: \`${IP}\`
Geo: ${GEO}
Time: ${TIMESTAMP}"
[[ -n "$EXTRA" ]] && MSG+="
Info: ${EXTRA}"

curl -sf --max-time 10 \
    -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d chat_id="${CHAT_ID}" \
    -d parse_mode="Markdown" \
    -d text="${MSG}" \
    > /dev/null 2>&1 || true
TGEOF

sed -i "s|__BOT_TOKEN__|${TG_BOT_TOKEN}|g; s|__CHAT_ID__|${TG_CHAT_ID}|g" "$TG_SCRIPT"
chmod +x "$TG_SCRIPT"

# ─── 5. SSH Honeypot on port 22 ───────────────────────────────────────────────
info "Setting up SSH honeypot on port $HONEYPOT_PORT..."

HONEYPOT_SCRIPT="/usr/local/bin/ssh_honeypot.sh"
cat > "$HONEYPOT_SCRIPT" <<'HPEOF'
#!/usr/bin/env bash
# Accepts TCP connections on port 22, logs the source IP, sends TG alert,
# then replies with a fake SSH banner and closes.
HONEYPOT_PORT=22

while true; do
    CLIENT=$(socat -u TCP-LISTEN:${HONEYPOT_PORT},reuseaddr,fork \
        SYSTEM:'IP=$SOCAT_PEERADDR; \
        logger -t ssh-honeypot "Connection from $IP"; \
        /usr/local/bin/tg_alert.sh "$IP" "🍯 Honeypot hit (port 22)"; \
        printf "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"; \
        sleep 5' 2>/dev/null) || true
done
HPEOF
chmod +x "$HONEYPOT_SCRIPT"

# systemd unit for the honeypot
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

# ── Real SSH (port $SSH_PORT) ──────────────────────────────────────────────
[sshd]
enabled  = true
port     = $SSH_PORT
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
bantime  = 24h
maxretry = 3
action   = %(action_mwl)s
           ssh-tg-notify

# ── Honeypot bans (port $HONEYPOT_PORT) ────────────────────────────────────
[ssh-honeypot]
enabled  = true
port     = $HONEYPOT_PORT
filter   = ssh-honeypot
logpath  = /var/log/syslog
bantime  = 7d
maxretry = 1
action   = iptables-multiport[name=honeypot, port="$HONEYPOT_PORT"]
           ssh-tg-notify
EOF

# fail2ban filter for honeypot syslog lines
cat > /etc/fail2ban/filter.d/ssh-honeypot.conf <<'EOF'
[Definition]
failregex = ssh-honeypot: Connection from <HOST>$
ignoreregex =
EOF

# Custom action: Telegram notification on ban
cat > /etc/fail2ban/action.d/ssh-tg-notify.conf <<'EOF'
[Definition]
actionban   = /usr/local/bin/tg_alert.sh "<ip>" "🔨 fail2ban BANNED" "jail=<name> attempts=<failures>"
actionunban = /usr/local/bin/tg_alert.sh "<ip>" "✅ fail2ban UNBANNED" "jail=<name>"
EOF

systemctl restart fail2ban
info "fail2ban configured and restarted"

# ─── 7. Auth log watcher (sshd real port alerts) ────────────────────────────
info "Installing auth log watcher service..."

WATCHER_SCRIPT="/usr/local/bin/ssh_auth_watch.sh"
cat > "$WATCHER_SCRIPT" <<'WEOF'
#!/usr/bin/env bash
# Tails /var/log/auth.log and fires Telegram alerts for failed/accepted logins.
AUTH_LOG="/var/log/auth.log"
[[ -f /var/log/secure ]] && AUTH_LOG="/var/log/secure"  # RHEL/CentOS

tail -Fn0 "$AUTH_LOG" | while read -r LINE; do
    if echo "$LINE" | grep -qE "Failed (password|publickey)"; then
        IP=$(echo "$LINE" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
        USER=$(echo "$LINE" | grep -oP 'for \K\S+')
        [[ -n "$IP" ]] && /usr/local/bin/tg_alert.sh "$IP" "❌ Failed login" "user=${USER:-?}"
    elif echo "$LINE" | grep -qE "Accepted (password|publickey)"; then
        IP=$(echo "$LINE" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
        USER=$(echo "$LINE" | grep -oP 'for \K\S+')
        [[ -n "$IP" ]] && /usr/local/bin/tg_alert.sh "$IP" "✅ Successful login" "user=${USER:-?}"
    fi
done
WEOF
chmod +x "$WATCHER_SCRIPT"

cat > /etc/systemd/system/ssh-auth-watch.service <<EOF
[Unit]
Description=SSH Auth Log → Telegram
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
echo "  TG alerts   : enabled (honeypot + failed/success logins + bans)"
echo ""
warn "⚠ Open port $SSH_PORT in your firewall BEFORE closing this session!"
warn "⚠ Test SSH login as $NEW_USER on port $SSH_PORT before logging out!"
echo ""
