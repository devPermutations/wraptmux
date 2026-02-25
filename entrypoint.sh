#!/bin/bash
set -e

CONFIG="${1:-/data/config.toml}"

if [ ! -f "$CONFIG" ]; then
    echo "ERROR: config file not found at $CONFIG"
    echo "Mount your config.toml to /data/config.toml"
    exit 1
fi

# Extract unix_user values from config and create missing users
grep -E '^\s*unix_user\s*=' "$CONFIG" | sed 's/.*=\s*"\?\([^"]*\)"\?.*/\1/' | while read -r user; do
    user=$(echo "$user" | xargs)  # trim whitespace
    [ -z "$user" ] && continue
    if ! id "$user" &>/dev/null; then
        echo "Creating user: $user"
        useradd -m -s /bin/bash "$user"
    fi
done

# Set up sudoers so wraptmux can run tmux as any user
cat > /etc/sudoers.d/wraptmux <<'EOF'
# Allow root (wraptmux process) to run tmux as any user without password
root ALL=(ALL) NOPASSWD: /usr/bin/tmux
EOF
chmod 440 /etc/sudoers.d/wraptmux

cd /opt/wraptmux
exec /opt/wraptmux/wraptmux "$CONFIG"
