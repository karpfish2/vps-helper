# server_setup.sh

Hardens a fresh Ubuntu/Debian server in one shot.

## What it does

| Step | Description |
|------|-------------|
| User | Creates a sudo user with **fish** shell |
| SSH | Moves SSHD to port **8678**, disables root login |
| Honeypot | Listens on port **22** via `socat`, fakes an SSH banner |
| fail2ban | Bans after 3 failed attempts (24 h); 1 honeypot hit = 7-day ban |
| Alerts | Telegram notifications with **GeoIP** for every login attempt, ban, and honeypot hit |

## Requirements

- Ubuntu 22.04+ / Debian 12+ (root access)
- A [Telegram bot token](https://core.telegram.org/bots#botfather) and chat ID

## Usage

```bash
chmod +x server_setup.sh

# Interactive
sudo ./server_setup.sh

# Non-interactive
sudo NEW_USER=alice TG_BOT_TOKEN=123:ABC TG_CHAT_ID=-100xyz ./server_setup.sh
```

## Telegram alerts

You'll receive a message for each of these events:

- `❌ Failed login` — wrong password / key on real SSH
- `✅ Successful login` — accepted connection
- `🍯 Honeypot hit` — anything touching port 22
- `🔨 fail2ban BANNED / ✅ UNBANNED` — ban lifecycle

Each alert includes the source IP, country, city, ISP, and timestamp.

## ⚠️ Before you disconnect

1. Make sure port `8678` is open in your firewall / cloud security group
2. Verify you can SSH in as the new user on port 8678
3. Only then close your current session

## Installed services

| Service | Description |
|---------|-------------|
| `ssh` / `sshd` | OpenSSH on port 8678 |
| `ssh-honeypot` | socat listener on port 22 |
| `ssh-auth-watch` | auth.log tailer → Telegram |
| `fail2ban` | brute-force protection |
