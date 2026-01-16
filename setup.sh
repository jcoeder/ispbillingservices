#!/bin/bash
# setup.sh - Production Setup Script for ISP Billing Services
# Assumptions:
# 1. Git clone this repo to /opt/ispbillingservices: git clone <repo> /opt/ispbillingservices
# 2. Run as root or with sudo: sudo ./setup.sh
# 3. Supports Debian/Ubuntu (apt), RHEL/Fedora (dnf/yum).
# 4. Sets up: venv, Nginx (reverse proxy), systemd service, self-signed SSL, firewall ports 80/443.
# 5. Creates system user 'ispbillingservices', admin user (admin/admin).

set -e  # Exit on error

PROJECT_PATH="/opt/ispbillingservices"
VENV_PATH="$PROJECT_PATH/venv"

# Function to generate a secure Flask secret key
generate_secret_key() {
    python3 -c "import secrets; print(secrets.token_urlsafe(50))" > /tmp/secret_key.txt
    if [ -s /tmp/secret_key.txt ]; then
        SECRET_KEY=$(cat /tmp/secret_key.txt)
        rm -f /tmp/secret_key.txt
        echo "✅ Generated Flask secret key."
    else
        echo "❌ Failed to generate Flask secret key."
        exit 1
    fi
}

# Function to update config.py with the generated secret key
update_config() {
    CONFIG_FILE="$PROJECT_PATH/config.py"
    if [ -f "$CONFIG_FILE" ]; then
        sudo sed -i "s|SECRET_KEY = .*|SECRET_KEY = '$SECRET_KEY'|" "$CONFIG_FILE" && echo "✅ Updated config.py with new secret key." || { echo "❌ Failed to update config.py."; exit 1; }
    else
        echo "❌ config.py not found at $CONFIG_FILE."
        exit 1
    fi
}

# Function to detect the package manager
detect_package_manager() {
    if command -v apt >/dev/null 2>&1; then
        PACKAGE_MANAGER="apt"
        SYSTEM_TYPE="debian"
        echo "✅ Detected apt (Debian/Ubuntu)."
    elif command -v dnf >/dev/null 2>&1; then
        PACKAGE_MANAGER="dnf"
        SYSTEM_TYPE="rhel"
        echo "✅ Detected dnf (RHEL/Fedora)."
    elif command -v yum >/dev/null 2>&1; then
        PACKAGE_MANAGER="yum"
        SYSTEM_TYPE="rhel"
        echo "✅ Detected yum (RHEL/CentOS)."
    else
        echo "❌ Unsupported package manager. Install deps manually."
        exit 1
    fi
}

# Function to install system dependencies
install_dependencies() {
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt update
            sudo apt install -y python3 python3-venv python3-dev python3-pip nginx supervisor
            sudo systemctl enable nginx supervisor
            sudo systemctl start nginx supervisor
            ;;
        "dnf")
            sudo dnf install -y python3 python3-pip python3-devel nginx
            sudo dnf install -y python3-virtualenv || echo "Virtualenv optional."
            sudo dnf install -y epel-release
            sudo systemctl enable nginx
            sudo systemctl start nginx
            sudo setsebool -P httpd_can_network_connect 1 2>/dev/null || true
            ;;
        "yum")
            sudo yum install -y python3 python3-pip python3-devel nginx
            sudo yum install -y python3-virtualenv || echo "Virtualenv optional."
            sudo yum install -y epel-release
            sudo systemctl enable nginx
            sudo systemctl start nginx
            sudo setsebool -P httpd_can_network_connect 1 2>/dev/null || true
            ;;
    esac
    echo "✅ System dependencies installed."
}

# Function to setup venv and pip requirements
setup_venv() {
    cd "$PROJECT_PATH"
    python3 -m venv "$VENV_PATH"
    source "$VENV_PATH/bin/activate"
    pip install --upgrade pip
    pip install -r requirements.txt
    deactivate
    echo "✅ Virtualenv and requirements installed."
}

# Create system user and set permissions
setup_user() {
    id ispbillingservices >/dev/null 2>&1 || sudo adduser --system --group --shell /bin/bash ispbillingservices
    sudo chown -R ispbillingservices:ispbillingservices "$PROJECT_PATH"
    echo "✅ User 'ispbillingservices' setup."
}

# Create systemd service file
create_systemd_service() {
    cat > "$PROJECT_PATH/system_files/ispbillingservices.service" << EOF
[Unit]
Description=ISP Billing Services Flask App
After=network.target

[Service]
User=ispbillingservices
Group=ispbillingservices
WorkingDirectory=$PROJECT_PATH
Environment=PATH=$VENV_PATH/bin
ExecStart=$VENV_PATH/bin/gunicorn -b 127.0.0.1:5000 run:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    sudo cp "$PROJECT_PATH/system_files/ispbillingservices.service" /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable ispbillingservices
    sudo systemctl start ispbillingservices
    echo "✅ Systemd service created and started."
}

# Create Nginx config
create_nginx_config() {
    sudo mkdir -p /etc/nginx/{sites-available,sites-enabled,conf.d}
    cat > "$PROJECT_PATH/system_files/nginx/ispbillingservices.conf" << 'EOF'
server {
    listen 80;
    server_name _;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate /etc/ssl/certs/ispbillingservices.crt;
    ssl_certificate_key /etc/ssl/private/ispbillingservices.key;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
    if [ "$SYSTEM_TYPE" = "debian" ]; then
        sudo ln -sf "$PROJECT_PATH/system_files/nginx/ispbillingservices.conf" /etc/nginx/sites-available/ispbillingservices
        sudo ln -sf /etc/nginx/sites-available/ispbillingservices /etc/nginx/sites-enabled/
        sudo rm -f /etc/nginx/sites-enabled/default
    else
        sudo cp "$PROJECT_PATH/system_files/nginx/ispbillingservices.conf" /etc/nginx/conf.d/ispbillingservices.conf
    fi
    sudo nginx -t && sudo systemctl reload nginx
    echo "✅ Nginx configured and reloaded."
}

# Generate self-signed SSL certs
setup_ssl() {
    sudo mkdir -p /etc/ssl/private /etc/ssl/certs
    sudo chmod 700 /etc/ssl/private
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ispbillingservices.key \
        -out /etc/ssl/certs/ispbillingservices.crt \
        -subj "/C=US/ST=State/L=City/O=ISP Billing Services/CN=ispbillingservices.local"
    echo "✅ SSL self-signed certs generated (valid 1 year)."
}

# Detect and configure firewall
detect_firewall() {
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        FIREWALL="firewalld"
    elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        FIREWALL="ufw"
    elif command -v iptables >/dev/null 2>&1; then
        FIREWALL="iptables"
    else
        FIREWALL="none"
    fi
    echo "✅ Detected firewall: $FIREWALL"
}

open_firewall_ports() {
    if [ "$FIREWALL" = "none" ]; then
        echo "ℹ️ No firewall detected. Ensure ports 80/443 open manually."
        return
    fi
    case $FIREWALL in
        "firewalld")
            sudo firewall-cmd --permanent --add-service=http --add-service=https
            sudo firewall-cmd --reload
            ;;
        "ufw")
            sudo ufw allow 'Nginx Full'
            ;;
        "iptables")
            sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
            sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
            sudo iptables-save > /etc/iptables.rules || true
            ;;
    esac
    echo "✅ Firewall ports 80/443 opened."
}

# Init Flask DB and create admin user
init_app() {
    cd "$PROJECT_PATH"
    sudo -u ispbillingservices "$VENV_PATH/bin/flask" db init || true
    sudo -u ispbillingservices "$VENV_PATH/bin/flask" db migrate -m "Initial" || true
    sudo -u ispbillingservices "$VENV_PATH/bin/flask" db upgrade
    sudo -u ispbillingservices "$VENV_PATH/bin/python" << EOF
from app import create_app, db
from models import User
app = create_app()
with app.app_context():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@ispbillingservices.com')
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin created: admin / admin")
EOF
    echo "✅ Flask app DB initialized."
}

# Main execution
echo "🚀 ISP Billing Services Production Setup"
cd "$PROJECT_PATH" || { echo "❌ Change to $PROJECT_PATH failed. Clone repo there first."; exit 1; }
mkdir -p system_files/nginx

generate_secret_key
update_config
detect_package_manager
install_dependencies
setup_venv
setup_user
init_app
setup_ssl
create_systemd_service
create_nginx_config
detect_firewall
open_firewall_ports

echo "🎉 Setup COMPLETE!"
echo "🌐 Access: https://your-server-ip (self-signed SSL warning OK)"
echo "👤 Admin: httpS://your-server-ip/login → admin/admin"
echo "📊 Services: sudo systemctl status ispbillingservices nginx"
echo "🔄 Logs: sudo journalctl -u ispbillingservices -f"