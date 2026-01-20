#!/bin/bash
# setup.sh - Production Setup Script for ISP Billing Services (PostgreSQL 16)
# Assumptions:
# 1. Git clone this repo to /opt/ispbillingservices
# 2. Run as root: sudo ./setup.sh
# 3. Supports Debian 12+/Ubuntu 22.04+, RHEL 8+/Rocky/AlmaLinux, Fedora 38+.
# 4. Installs PostgreSQL 16, creates DB/user, .env secrets, Nginx, systemd, SSL.
# 5. Admin user: admin/admin after setup.

set -e  # Exit on error

PROJECT_PATH="/opt/ispbillingservices"
VENV_PATH="$PROJECT_PATH/venv"
DB_NAME="ispbillingservices"
DB_USER="ispbillingservices"
PG_PORT="5432"

# Function to generate secure random string
generate_secret() {
    python3 -c "import secrets; print(secrets.token_urlsafe(50))"
}

# Function to detect the package manager and system
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
        echo "❌ Unsupported package manager."
        exit 1
    fi
}

# Install PostgreSQL 16
install_postgres() {
    case $PACKAGE_MANAGER in
        "apt")
            echo "📦 Installing PostgreSQL 16 repo and packages..."
            sudo apt install -y curl ca-certificates gnupg lsb-release
            curl https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor | sudo tee /usr/share/keyrings/pgdg.gpg >/dev/null
            echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" | sudo tee /etc/apt/sources.list.d/pgdg.list >/dev/null
            sudo apt update
            sudo apt install -y postgresql-16 postgresql-contrib-16
            ;;
        "dnf")
            echo "📦 Enabling PostgreSQL 16 module..."
            sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-$(rpm -E %rhel)-x86_64/pgdg-redhat-repo-latest.noarch.rpm || sudo dnf install -y epel-release
            sudo dnf -qy module enable postgresql:16
            sudo dnf install -y @postgresql:16 postgresql-contrib
            sudo postgresql-setup --initdb || echo "DB already initialized."
            ;;
        "yum")
            echo "📦 Installing PostgreSQL 16 (RHEL/CentOS)..."
            sudo yum install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-$(rpm -E %rhel)-x86_64/pgdg-redhat-repo-latest.noarch.rpm || sudo yum install -y epel-release
            sudo yum install -y postgresql16-server postgresql16-contrib
            sudo /usr/pgsql-16/bin/postgresql-16-setup initdb || echo "DB already initialized."
            ;;
    esac
    sudo systemctl enable postgresql --now || sudo systemctl enable postgresql-16 --now
    echo "✅ PostgreSQL 16 installed and started."
}

# Setup PostgreSQL DB and user
setup_postgres() {
    DB_PASS=$(generate_secret)
    echo "🔐 Generated DB password for $DB_USER."

    # Wait for Postgres to be ready
    until sudo -u postgres pg_isready -d template1; do
        echo "⏳ Waiting for PostgreSQL..."
        sleep 2
    done

    sudo -u postgres createuser --createdb --no-createrole --no-superuser "$DB_USER" || echo "User exists."
    sudo -u postgres psql -c "ALTER USER \"$DB_USER\" PASSWORD '$DB_PASS';" || true
    sudo -u postgres createdb -O "$DB_USER" "$DB_NAME" || echo "DB exists."
    echo "✅ PostgreSQL DB '$DB_NAME' and user '$DB_USER' setup."
    echo "DATABASE_URL=postgresql://$DB_USER:$DB_PASS@localhost/$DB_NAME" > "$PROJECT_PATH/.env"
}

# Generate Flask SECRET_KEY
generate_secret_key() {
    SECRET_KEY=$(generate_secret)
    echo "🔐 Generated SECRET_KEY."
}

# Install system dependencies (Python, Nginx)
install_dependencies() {
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt install -y python3 python3-venv python3-dev python3-pip nginx
            sudo systemctl enable nginx --now
            ;;
        "dnf")
            sudo dnf install -y python3 python3-pip python3-devel python3-virtualenv nginx
            sudo dnf install -y epel-release
            sudo systemctl enable nginx --now
            sudo setsebool -P httpd_can_network_connect 1 2>/dev/null || true
            ;;
        "yum")
            sudo yum install -y python3 python3-pip python3-devel python3-virtualenv nginx
            sudo yum install -y epel-release
            sudo systemctl enable nginx --now
            sudo setsebool -P httpd_can_network_connect 1 2>/dev/null || true
            ;;
    esac
    echo "✅ System deps installed."
}

# Setup venv and pip
setup_venv() {
    cd "$PROJECT_PATH"
    python3 -m venv "$VENV_PATH"
    source "$VENV_PATH/bin/activate"
    pip install --upgrade pip
    pip install -r requirements.txt
    deactivate
    echo "✅ Venv & Python deps installed."
}

# Create system user
setup_user() {
    id "$DB_USER" >/dev/null 2>&1 || sudo useradd --system --shell /bin/bash --create-home "$DB_USER"
    sudo chown -R "$DB_USER:$DB_USER" "$PROJECT_PATH"
    echo "✅ User '$DB_USER' created."
}

# Update .env with SECRET_KEY
update_env() {
    echo "SECRET_KEY=$SECRET_KEY" >> "$PROJECT_PATH/.env"
    sudo chown "$DB_USER:$DB_USER" "$PROJECT_PATH/.env"
    sudo chmod 600 "$PROJECT_PATH/.env"
    echo "✅ .env created with secrets."
}

# Init Flask app (DB migrations, admin user)
init_app() {
    cd "$PROJECT_PATH"
    source "$VENV_PATH/bin/activate"
    export FLASK_APP=run.py
    flask db init || echo "Migrations dir exists."
    flask db migrate -m "Initial migration with Postgres"
    flask db upgrade
    deactivate

    sudo -u "$DB_USER" "$VENV_PATH/bin/python" << EOF
from app import create_app, db
from models import User
from werkzeug.security import generate_password_hash
app = create_app()
with app.app_context():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@ispbillingservices.com')
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created: username='admin', password='admin'")
    else:
        print("ℹ️ Admin user already exists.")
EOF
    echo "✅ App DB initialized & admin created."
}

# Create systemd service (loads .env via app.py)
create_systemd_service() {
    sudo mkdir -p "$PROJECT_PATH/system_files"
    cat > "$PROJECT_PATH/system_files/ispbillingservices.service" << EOF
[Unit]
Description=ISP Billing Services
After=network.target postgresql.service

[Service]
User=$DB_USER
Group=$DB_USER
WorkingDirectory=$PROJECT_PATH
Environment=PATH=$VENV_PATH/bin
Environment=FLASK_ENV=production
ExecStart=$VENV_PATH/bin/gunicorn -w 4 -b 127.0.0.1:5000 --access-logfile - --error-logfile - run:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    sudo cp "$PROJECT_PATH/system_files/ispbillingservices.service" /etc/systemd/system/
    sudo chown "$DB_USER:$DB_USER" "$PROJECT_PATH/system_files/ispbillingservices.service"
    sudo systemctl daemon-reload
    sudo systemctl enable ispbillingservices
    sudo systemctl start ispbillingservices
    echo "✅ Systemd service setup."
}

# Nginx config (same as before)
create_nginx_config() {
    sudo mkdir -p /etc/nginx/{sites-available,sites-enabled,conf.d} "$PROJECT_PATH/system_files/nginx"
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
        proxy_read_timeout 3600;
        proxy_connect_timeout 3600;
    }
}
EOF
    sudo chown -R "$DB_USER:$DB_USER" "$PROJECT_PATH/system_files/nginx"
    if [ "$SYSTEM_TYPE" = "debian" ]; then
        sudo ln -sf "$PROJECT_PATH/system_files/nginx/ispbillingservices.conf" /etc/nginx/sites-available/ispbillingservices
        sudo ln -sf /etc/nginx/sites-available/ispbillingservices /etc/nginx/sites-enabled/
        sudo rm -f /etc/nginx/sites-enabled/default
    else
        sudo cp "$PROJECT_PATH/system_files/nginx/ispbillingservices.conf" /etc/nginx/conf.d/ispbillingservices.conf
    fi
    sudo nginx -t && sudo systemctl reload nginx || sudo systemctl restart nginx
    echo "✅ Nginx configured."
}

# SSL certs
setup_ssl() {
    sudo mkdir -p /etc/ssl/{private,certs}
    sudo chmod 700 /etc/ssl/private
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ispbillingservices.key \
        -out /etc/ssl/certs/ispbillingservices.crt \
        -subj "/C=US/ST=State/L=City/O=ISP Billing Services/CN=$(hostname)"
    echo "✅ Self-signed SSL certs generated."
}

# Firewall (updated for Postgres if needed, but app uses localhost)
detect_firewall() {
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        FIREWALL="firewalld"
    elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        FIREWALL="ufw"
    else
        FIREWALL="none"
    fi
    echo "✅ Firewall: $FIREWALL"
}

open_firewall_ports() {
    [ "$FIREWALL" = "none" ] && { echo "ℹ️ No firewall."; return; }
    case $FIREWALL in
        "firewalld") sudo firewall-cmd --permanent --add-service={http,https} && sudo firewall-cmd --reload ;;
        "ufw") sudo ufw allow 'Nginx Full' ;;
    esac
    echo "✅ Ports 80/443 opened."
}

# Main
echo "🚀 ISP Billing Services + Postgres 16 Setup"
cd "$PROJECT_PATH" || { echo "❌ Not in $PROJECT_PATH. Clone first."; exit 1; }

detect_package_manager
install_postgres
setup_postgres
generate_secret_key
install_dependencies
setup_venv
setup_user
update_env
init_app
setup_ssl
create_systemd_service
create_nginx_config
detect_firewall
open_firewall_ports

echo "🎉 COMPLETE!"
echo "🌐 https://$(hostname -I | awk '{print $1}')/ (ignore SSL warning)"
echo "👤 Admin: /login → admin/admin"
echo "📋 DB: psql -U $DB_USER -d $DB_NAME -h localhost"
echo "🔍 Logs: journalctl -u ispbillingservices -f"
echo "⚙️ .env secured (backup it!)"