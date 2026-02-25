#!/bin/bash
set -e

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}==>${NC} ${BOLD}$1${NC}"; }
warn()  { echo -e "${YELLOW}warning:${NC} $1"; }
error() { echo -e "${RED}error:${NC} $1"; exit 1; }
ask()   { echo -en "${BOLD}$1${NC} "; read -r "$2"; }

# --- Prerequisites ---
info "wraptmux setup"
echo

HAS_DOCKER=false
HAS_CARGO=false

if command -v docker &>/dev/null && command -v docker compose &>/dev/null; then
    HAS_DOCKER=true
fi
if command -v cargo &>/dev/null; then
    HAS_CARGO=true
fi

if ! $HAS_DOCKER && ! $HAS_CARGO; then
    error "Neither docker nor cargo found. Install Docker (https://docs.docker.com/get-docker/) or Rust (https://rustup.rs/)."
fi

# --- Deployment mode ---
if $HAS_DOCKER && $HAS_CARGO; then
    echo "Deployment options:"
    echo "  1) Docker (recommended)"
    echo "  2) Bare metal"
    ask "Choose [1/2]:" DEPLOY_CHOICE
    case "$DEPLOY_CHOICE" in
        2) DEPLOY="bare" ;;
        *) DEPLOY="docker" ;;
    esac
elif $HAS_DOCKER; then
    DEPLOY="docker"
else
    DEPLOY="bare"
fi

info "Deployment: $DEPLOY"
echo

# --- Auth mode ---
echo "Authentication:"
echo "  1) Password (recommended — simple, no external dependencies)"
echo "  2) Cloudflare Access (zero-trust, requires Cloudflare setup)"
ask "Choose [1/2]:" AUTH_CHOICE
case "$AUTH_CHOICE" in
    2) AUTH="cloudflare" ;;
    *) AUTH="password" ;;
esac

info "Auth mode: $AUTH"
echo

# --- Listen address ---
ask "Listen address [0.0.0.0:7681]:" LISTEN
LISTEN="${LISTEN:-0.0.0.0:7681}"

# --- Static dir ---
if [ "$DEPLOY" = "docker" ]; then
    STATIC_DIR="/opt/wraptmux/static"
else
    ask "Static files directory [./static]:" STATIC_DIR
    STATIC_DIR="${STATIC_DIR:-./static}"
fi

# --- Generate config ---
CONFIG_FILE="config.toml"

generate_password_config() {
    local users=""
    local user_num=1

    while true; do
        info "User #$user_num"
        ask "  Username:" USERNAME
        [ -z "$USERNAME" ] && break

        ask "  Unix user (login shell user) [$USERNAME]:" UNIX_USER
        UNIX_USER="${UNIX_USER:-$USERNAME}"

        ask "  tmux session name [main]:" TMUX_SESSION
        TMUX_SESSION="${TMUX_SESSION:-main}"

        # Hash password
        echo -n "  Password: "
        read -rs PASSWORD
        echo

        if [ -z "$PASSWORD" ]; then
            warn "Empty password, skipping user"
            continue
        fi

        if [ "$DEPLOY" = "docker" ]; then
            # Build image first (if not already built), then use it to hash
            if ! docker image inspect wraptmux-wraptmux &>/dev/null && \
               ! docker image inspect tmuxwrapper-wraptmux &>/dev/null; then
                info "Building wraptmux image (first time only)..."
                docker compose build --quiet
            fi
            HASH=$(echo "$PASSWORD" | docker compose run --rm -T wraptmux /opt/wraptmux/wraptmux hash-password 2>/dev/null)
        else
            # Bare metal — build if needed, then hash
            if [ ! -f "target/release/wraptmux" ]; then
                info "Building wraptmux..."
                cargo build --release
            fi
            HASH=$(echo "$PASSWORD" | ./target/release/wraptmux hash-password)
        fi

        if [ -z "$HASH" ] || [[ ! "$HASH" == \$2* ]]; then
            error "Failed to hash password. Make sure bcrypt is working."
        fi

        users+="
[[users]]
username = \"$USERNAME\"
password_hash = \"$HASH\"
unix_user = \"$UNIX_USER\"
tmux_session = \"$TMUX_SESSION\"
"
        info "User '$USERNAME' added"
        echo
        user_num=$((user_num + 1))
        ask "Add another user? [y/N]:" MORE
        [[ "$MORE" =~ ^[Yy] ]] || break
    done

    if [ -z "$users" ]; then
        error "No users configured. At least one user is required."
    fi

    cat > "$CONFIG_FILE" <<EOF
listen = "$LISTEN"
static_dir = "$STATIC_DIR"
auth_mode = "password"

[terminal]
ping_interval_secs = 30
$users
EOF
}

generate_cloudflare_config() {
    ask "Cloudflare team domain (e.g. 'myteam' from myteam.cloudflareaccess.com):" CF_TEAM
    [ -z "$CF_TEAM" ] && error "Team domain is required"

    ask "Cloudflare Access audience tag (AUD):" CF_AUD
    [ -z "$CF_AUD" ] && error "Audience tag is required"

    local users=""
    local user_num=1

    while true; do
        info "User #$user_num"
        ask "  Email (must match Cloudflare Access identity):" EMAIL
        [ -z "$EMAIL" ] && break

        ask "  Unix user:" UNIX_USER
        [ -z "$UNIX_USER" ] && error "Unix user is required"

        ask "  tmux session name [main]:" TMUX_SESSION
        TMUX_SESSION="${TMUX_SESSION:-main}"

        users+="
[[users]]
email = \"$EMAIL\"
unix_user = \"$UNIX_USER\"
tmux_session = \"$TMUX_SESSION\"
"
        info "User '$EMAIL' added"
        echo
        user_num=$((user_num + 1))
        ask "Add another user? [y/N]:" MORE
        [[ "$MORE" =~ ^[Yy] ]] || break
    done

    if [ -z "$users" ]; then
        error "No users configured. At least one user is required."
    fi

    cat > "$CONFIG_FILE" <<EOF
listen = "$LISTEN"
static_dir = "$STATIC_DIR"
auth_mode = "cloudflare"

[cloudflare]
team_domain = "$CF_TEAM"
audience = "$CF_AUD"
jwks_refresh_secs = 3600

[terminal]
ping_interval_secs = 30
$users
EOF
}

case "$AUTH" in
    password)   generate_password_config ;;
    cloudflare) generate_cloudflare_config ;;
esac

info "Config written to $CONFIG_FILE"
echo

# --- Deploy ---
if [ "$DEPLOY" = "docker" ]; then
    info "Building and starting with Docker..."
    docker compose up -d --build
    echo
    info "wraptmux is running!"
    echo -e "  Open ${BOLD}http://localhost:${LISTEN##*:}${NC} in your browser"
    echo -e "  Logs: ${DIM}docker compose logs -f${NC}"
    echo -e "  Stop: ${DIM}docker compose down${NC}"
else
    info "Building wraptmux..."
    cargo build --release

    INSTALL_DIR="/opt/wraptmux"
    info "Installing to $INSTALL_DIR..."
    sudo mkdir -p "$INSTALL_DIR/static"
    sudo cp target/release/wraptmux "$INSTALL_DIR/wraptmux"
    sudo chmod +x "$INSTALL_DIR/wraptmux"
    sudo cp -r static/* "$INSTALL_DIR/static/"
    sudo cp "$CONFIG_FILE" "$INSTALL_DIR/config.toml"

    # Create unix users if they don't exist
    grep -E '^\s*unix_user\s*=' "$CONFIG_FILE" | sed 's/.*=\s*"\?\([^"]*\)"\?.*/\1/' | while read -r user; do
        user=$(echo "$user" | xargs)
        [ -z "$user" ] && continue
        if ! id "$user" &>/dev/null; then
            info "Creating unix user: $user"
            sudo useradd -m -s /bin/bash "$user"
        fi
    done

    # Sudoers
    sudo tee /etc/sudoers.d/wraptmux > /dev/null <<'SUDOERS'
root ALL=(ALL) NOPASSWD: /usr/bin/tmux
SUDOERS
    sudo chmod 440 /etc/sudoers.d/wraptmux

    # Systemd service
    sudo cp wraptmux.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable wraptmux
    sudo systemctl start wraptmux

    echo
    info "wraptmux is running!"
    echo -e "  Open ${BOLD}http://localhost:${LISTEN##*:}${NC} in your browser"
    echo -e "  Logs:    ${DIM}journalctl -u wraptmux -f${NC}"
    echo -e "  Restart: ${DIM}sudo systemctl restart wraptmux${NC}"
    echo -e "  Stop:    ${DIM}sudo systemctl stop wraptmux${NC}"
fi
