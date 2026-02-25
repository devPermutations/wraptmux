# wraptmux

Web-based tmux terminal — access your server from any browser.

<!-- ![screenshot](screenshot.png) -->

## Features

- **Mobile-optimized** — touch-friendly key bar, iOS dictation support, PWA installable
- **Session picker** — list, create, switch, and kill tmux sessions from the UI
- **Multi-user** — each user maps to a unix account with isolated tmux sessions
- **Two auth modes** — simple password auth or Cloudflare Access (zero-trust)
- **Secure** — runs as root only to setuid into target users; minimal capabilities, CSP headers, CSRF protection

## Quick Start (Docker)

```bash
git clone https://github.com/devPermutations/wraptmux.git
cd wraptmux
./setup.sh
```

The setup script will walk you through configuration and start the container.

**Or manually:**

```bash
# 1. Create config.toml (copy an example)
cp config.example-password.toml config.toml

# 2. Hash a password
docker compose run --rm wraptmux /opt/wraptmux/wraptmux hash-password

# 3. Edit config.toml with your hash and user details

# 4. Start
docker compose up -d
```

Open http://localhost:7681

## Quick Start (Bare Metal)

Requires: Rust 1.75+, tmux, sudo

```bash
git clone https://github.com/devPermutations/wraptmux.git
cd wraptmux
./setup.sh
```

**Or manually:**

```bash
cargo build --release

# Hash a password
./target/release/wraptmux hash-password

# Create and edit config.toml
cp config.example-password.toml config.toml
# Edit config.toml with your hash, unix_user, etc.

# Run (needs root for setuid)
sudo ./target/release/wraptmux config.toml
```

See `wraptmux.service` for a systemd unit file.

## TLS / HTTPS

**wraptmux does not include a built-in TLS server.** If you use password authentication, you need to understand the implications and choose one of the options below.

### Why this matters

Without TLS, all traffic between your browser and wraptmux is **plaintext**. Anyone on the network path — your ISP, anyone on the same Wi-Fi, a compromised router — can:

- **Capture your password** as you type it on the login page
- **Steal your session cookie** and hijack your terminal session without needing your password
- **Read everything you type and every command output** in real time — including secrets, tokens, and file contents displayed on screen

This is not a theoretical risk. On any shared or untrusted network, unencrypted HTTP traffic is trivially interceptable with standard tools like Wireshark or tcpdump.

> **Cloudflare Access users:** TLS is handled by Cloudflare's edge network. You don't need any of the options below.

---

### Option 1: Caddy sidecar (recommended for Docker)

A ready-to-use `docker-compose.tls.yml` is included that runs [Caddy](https://caddyserver.com/) alongside wraptmux. Caddy automatically obtains and renews [Let's Encrypt](https://letsencrypt.org/) TLS certificates with zero configuration beyond your domain name.

**Requirements:**
- A domain name with DNS pointing to your server (e.g. `terminal.example.com`)
- Ports 80 and 443 open and not used by another service

**Setup:**

```bash
# 1. Edit the Caddyfile — replace terminal.example.com with your domain
nano Caddyfile

# 2. Create your config.toml (same as Quick Start above)

# 3. Start with TLS
docker compose -f docker-compose.tls.yml up -d
```

Caddy will automatically:
- Obtain a Let's Encrypt certificate for your domain
- Renew it before expiry
- Redirect HTTP to HTTPS
- Proxy WebSocket connections to wraptmux

Your terminal is now available at `https://your-domain.com`.

---

### Option 2: Bring your own reverse proxy

If you already run nginx, Caddy, Traefik, HAProxy, or another reverse proxy, point it at wraptmux on port 7681. wraptmux stays on HTTP internally; the proxy handles TLS termination.

**nginx:**

```nginx
server {
    listen 443 ssl;
    server_name terminal.example.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:7681;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Caddy (standalone):**

```
terminal.example.com {
    reverse_proxy 127.0.0.1:7681
}
```

Key requirements for any reverse proxy:
- **WebSocket support** — the `Upgrade` and `Connection` headers must be forwarded
- **No aggressive timeouts** — terminal sessions are long-lived connections

---

### Option 3: No TLS (localhost / trusted network only)

Running without TLS is acceptable **only** when:
- You access wraptmux exclusively over `localhost` (same machine)
- You are on a fully trusted private network (e.g. home LAN with no untrusted devices)
- You connect through an SSH tunnel or VPN that already encrypts the traffic

**What you are accepting by running without TLS:**
- Passwords are sent as plaintext over HTTP
- Session cookies can be intercepted and replayed by any network observer
- All terminal I/O — every command, every output, every secret displayed on screen — is visible to anyone who can see your network traffic
- If the network is ever compromised, an attacker gets immediate, authenticated shell access to your server

wraptmux prints a warning at startup when running password auth without TLS:

```
WARN password auth on 0.0.0.0 without TLS — credentials will be sent in plaintext.
     Use a reverse proxy (nginx, caddy) with TLS in production.
```

---

## Configuration

### Top-level

| Field | Description | Default |
|-------|-------------|---------|
| `listen` | Bind address | `0.0.0.0:7681` |
| `static_dir` | Path to static files | `./static` |
| `auth_mode` | `password` or `cloudflare` | `cloudflare` |

### `[terminal]`

| Field | Description | Default |
|-------|-------------|---------|
| `ping_interval_secs` | WebSocket keepalive interval | `30` |
| `session_duration_secs` | Session cookie lifetime in seconds (password mode) | `86400` (24h) |

### `[cloudflare]` (required when `auth_mode = "cloudflare"`)

| Field | Description |
|-------|-------------|
| `team_domain` | Your Cloudflare Access team domain (e.g. `myteam`) |
| `audience` | Application Audience (AUD) tag from CF Access |
| `jwks_refresh_secs` | How often to refresh JWKS keys |

### `[[users]]`

| Field | Required in | Description |
|-------|-------------|-------------|
| `email` | cloudflare | Email matching Cloudflare Access identity |
| `username` | password | Login username |
| `password_hash` | password | bcrypt hash (generate with `wraptmux hash-password`) |
| `unix_user` | both | Linux user to run tmux as |
| `tmux_session` | both | Default tmux session name |

## Auth Modes

### Password

Simple username/password authentication. Passwords are bcrypt-hashed. Sessions use HMAC-signed cookies (HttpOnly, SameSite=Strict, 24h expiry).

Generate a password hash:
```bash
wraptmux hash-password
# Or in Docker:
docker compose run --rm wraptmux /opt/wraptmux/wraptmux hash-password
```

### Cloudflare Access

Zero-trust authentication via [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/applications/). wraptmux validates the JWT from Cloudflare's `Cf-Access-Jwt-Assertion` header. No passwords stored — user identity comes from Cloudflare.

Requires:
1. A Cloudflare Access application configured for your domain
2. The application's audience (AUD) tag
3. User emails in config must match Cloudflare identity emails

## Security

- **Privilege separation**: wraptmux runs as root solely to `setuid`/`setgid` into target unix users. Each tmux process runs as the configured unix user. The privilege drop follows the correct order (initgroups → setgid → setuid) and is verified — if the drop fails, the child process aborts immediately.
- **Root blocked as target**: `unix_user = "root"` is rejected in config validation. There is no code path that runs a terminal session as root.
- **Minimal capabilities** (Docker): `SETUID`, `SETGID`, `DAC_OVERRIDE`, `FOWNER`, `CHOWN`, `FSETID` — all others dropped.
- **Headers**: Content-Security-Policy (`frame-ancestors 'none'`), X-Content-Type-Options (`nosniff`), Referrer-Policy, Permissions-Policy.
- **CSRF**: SameSite=Strict cookies (password mode); origin validation (Cloudflare mode).
- **Input validation**: unix_user, tmux_session, and session names are restricted to `[a-zA-Z0-9_-]`. No shell injection vectors.
- **No TLS built-in**: See [TLS / HTTPS](#tls--https) above. Password auth over plain HTTP exposes credentials to network observers.

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

## License

[MIT](LICENSE)
