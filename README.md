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

- **Privilege separation**: wraptmux runs as root solely to `setuid`/`setgid` into target unix users. Each tmux process runs as the configured unix user.
- **Minimal capabilities** (Docker): `SETUID`, `SETGID`, `DAC_OVERRIDE`, `FOWNER` — all others dropped.
- **Headers**: Content-Security-Policy (frame-ancestors 'none'), X-Content-Type-Options (nosniff), Referrer-Policy, Permissions-Policy.
- **CSRF**: SameSite=Strict cookies (password mode); origin validation (Cloudflare mode).
- **Input validation**: unix_user, tmux_session, and session names are restricted to `[a-zA-Z0-9_-]`. No shell injection vectors.

## Reverse Proxy

wraptmux should sit behind a reverse proxy with TLS in production.

### nginx

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

### Caddy

```
terminal.example.com {
    reverse_proxy 127.0.0.1:7681
}
```

Caddy handles TLS and WebSocket upgrades automatically.

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

## License

[MIT](LICENSE)
