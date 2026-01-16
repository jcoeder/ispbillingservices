#!/bin/bash
# Function to generate a secure Flask secret key
generate_secret_key() {
    python3 -c "import secrets; print(secrets.token_urlsafe(32))" > /tmp/secret_key.txt
    if [ -s /tmp/secret_key.txt ]; then
        SECRET_KEY=$(cat /tmp/secret_key.txt)
        echo "Generated Flask secret key successfully."
    else
        echo "Failed to generate Flask secret key."
        exit 1
    fi
}
# Function to create .env file with secret key and DB URI
create_env_file() {
    ENV_FILE="/opt/isp-invoice-tracker/.env"
    DB_USER="isptracker"
    DB_PASS="changeme"  # Change this to a secure password
    DB_NAME="isptracker_db"
    DB_URI="postgresql://$DB_USER:$DB_PASS@localhost/$DB_NAME"
    echo "SECRET_KEY=$SECRET_KEY" > "$ENV_FILE"
    echo "SQLALCHEMY_DATABASE_URI=$DB_URI" >> "$ENV_FILE"
    echo ".env file created successfully at $ENV_FILE."
}
# Function to create system_files directory and necessary files
create_system_files() {
    SYSTEM_DIR="/opt/isp-invoice-tracker/system_files"
    mkdir -p "$SYSTEM_DIR" && echo "system_files directory created." || { echo "Failed to create system_files directory."; exit 1; }

    # Create isp-invoice-tracker.service
    cat > "$SYSTEM_DIR/isp-invoice-tracker.service" << EOF
[Unit]
Description=ISP Invoice Tracker Flask App
After=network.target

[Service]
User=isptracker
Group=isptracker
WorkingDirectory=/opt/isp-invoice-tracker
Environment="PATH=/opt/isp-invoice-tracker/venv/bin"
ExecStart=/opt/isp-invoice-tracker/venv/bin/gunicorn --workers 3 --bind unix:/tmp/isp-invoice-tracker.sock -m 007 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    echo "Systemd service file created."

    # Create isp-invoice-tracker.conf for Nginx
    cat > "$SYSTEM_DIR/isp-invoice-tracker.conf" << EOF
server {
    listen 80;
    server_name localhost;  # Change to your domain if needed

    location = /favicon.ico { access_log off; log_not_found off; }
    location /static {
        alias /opt/isp-invoice-tracker/static;  # Adjust if you have static files
    }

    location / {
        include proxy_params;
        proxy_pass http://unix:/tmp/isp-invoice-tracker.sock;
    }
}
EOF
    echo "Nginx config file created."

    # Create nginx.conf for RHEL (optional, only if needed)
    cat > "$SYSTEM_DIR/nginx.conf" << EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    include /etc/nginx/conf.d/*.conf;
}
EOF
    echo "Nginx main config file created for RHEL."
}
# Function to check and copy configuration files (if any, e.g., sample configs)
copy_config_files() {
    # Assuming no specific config files like in BGP example; add if needed
    echo "No config files to copy for this app."
}
# Function to detect the package manager
detect_package_manager() {
    if command -v apt >/dev/null 2>&1; then
        PACKAGE_MANAGER="apt"
        SYSTEM_TYPE="debian"
        echo "Detected apt package manager (Debian/Ubuntu-based system)."
    elif command -v dnf >/dev/null 2>&1; then
        PACKAGE_MANAGER="dnf"
        SYSTEM_TYPE="rhel"
        echo "Detected dnf package manager (RHEL/Fedora-based system)."
    elif command -v yum >/dev/null 2>&1; then
        PACKAGE_MANAGER="yum"
        SYSTEM_TYPE="rhel"
        echo "Detected yum package manager (Older RHEL/CentOS-based system)."
    else
        echo "Cannot detect a supported package manager (apt, dnf, or yum). Please install dependencies manually."
        exit 1
    fi
}
# Function to install dependencies based on package manager, including PostgreSQL
install_dependencies() {
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt update && echo "Apt update completed." || { echo "Apt update failed."; exit 1; }
            sudo apt install -y python3 python3-venv python3-dev git nginx postgresql postgresql-contrib && echo "Apt package installation completed." || { echo "Apt package installation failed."; exit 1; }
            sudo systemctl enable postgresql nginx && echo "PostgreSQL and Nginx enabled at startup." || { echo "Failed to enable services."; exit 1; }
            sudo systemctl start postgresql nginx && echo "PostgreSQL and Nginx started successfully." || { echo "Failed to start services."; exit 1; }
            ;;
        "dnf")
            sudo dnf install -y python3 python3-devel git nginx postgresql-server postgresql-contrib && echo "Dnf package installation completed." || { echo "Dnf package installation failed."; exit 1; }
            sudo dnf install -y python3-pip python3-virtualenv && echo "Dnf python3-pip and virtualenv installation completed." || echo "python3-pip or virtualenv not available, assuming virtualenv is included in python3."
            sudo postgresql-setup --initdb && echo "PostgreSQL initialized." || { echo "Failed to initialize PostgreSQL."; exit 1; }
            sudo systemctl enable postgresql nginx && echo "PostgreSQL and Nginx enabled at startup." || { echo "Failed to enable services."; exit 1; }
            sudo systemctl start postgresql nginx && echo "PostgreSQL and Nginx started successfully." || { echo "Failed to start services."; exit 1; }
            ;;
        "yum")
            sudo yum install -y python3 python3-devel git nginx postgresql-server postgresql-contrib && echo "Yum package installation completed." || { echo "Yum package installation failed."; exit 1; }
            sudo yum install -y python3-pip python3-virtualenv && echo "Yum python3-pip and virtualenv installation completed." || echo "python3-pip or virtualenv not available, assuming virtualenv is included in python3."
            sudo postgresql-setup initdb && echo "PostgreSQL initialized." || { echo "Failed to initialize PostgreSQL."; exit 1; }
            sudo systemctl enable postgresql nginx && echo "PostgreSQL and Nginx enabled at startup." || { echo "Failed to enable services."; exit 1; }
            sudo systemctl start postgresql nginx && echo "PostgreSQL and Nginx started successfully." || { echo "Failed to start services."; exit 1; }
            ;;
        *)
            echo "Unsupported package manager. Please install dependencies manually."
            exit 1
            ;;
    esac
}
# Function to setup PostgreSQL database and user
setup_postgres() {
    DB_USER="isptracker"
    DB_PASS="changeme"  # Change this
    DB_NAME="isptracker_db"
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" 2>/dev/null && echo "PostgreSQL user created." || echo "PostgreSQL user may already exist."
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" 2>/dev/null && echo "PostgreSQL database created." || echo "PostgreSQL database may already exist."
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" && echo "Privileges granted." || { echo "Failed to grant privileges."; exit 1; }
}
# Function to detect the active firewall system and check if it's running
detect_firewall() {
    echo "Detecting active firewall system..."
    if command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active --quiet firewalld; then
            FIREWALL="firewalld"
            FIREWALL_RUNNING="yes"
            echo "Detected firewalld as the active firewall and it is running."
        else
            FIREWALL="firewalld"
            FIREWALL_RUNNING="no"
            echo "Detected firewalld installed, but it is not running."
        fi
    elif command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -q "active"; then
            FIREWALL="ufw"
            FIREWALL_RUNNING="yes"
            echo "Detected ufw as the active firewall and it is running."
        else
            FIREWALL="ufw"
            FIREWALL_RUNNING="no"
            echo "Detected ufw installed, but it is not running or inactive."
        fi
    elif command -v iptables >/dev/null 2>&1; then
        if iptables -L -n 2>/dev/null | grep -q "Chain"; then
            FIREWALL="iptables"
            FIREWALL_RUNNING="yes"
            echo "Detected iptables as the active firewall and it appears to be in use."
        else
            FIREWALL="iptables"
            FIREWALL_RUNNING="no"
            echo "Detected iptables installed, but no active rules or chains found."
        fi
    else
        FIREWALL="none"
        FIREWALL_RUNNING="no"
        echo "No supported firewall (firewalld, ufw, or iptables) detected. Assuming no firewall is configured or running."
    fi
}
# Function to open ports 80 and 443 based on the detected firewall and if it's running
open_ports() {
    if [ "$FIREWALL_RUNNING" == "no" ]; then
        echo "Firewall $FIREWALL is not running. Skipping port opening. Ensure ports 80 and 443 are accessible if a firewall is enabled later."
        return
    fi
    case $FIREWALL in
        "firewalld")
            echo "Opening ports 80 and 443 using firewalld..."
            sudo firewall-cmd --permanent --add-port=80/tcp && sudo firewall-cmd --permanent --add-port=443/tcp && sudo firewall-cmd --reload && echo "Ports 80 and 443 opened successfully with firewalld." || { echo "Failed to open ports with firewalld."; exit 1; }
            ;;
        "ufw")
            echo "Opening ports 80 and 443 using ufw..."
            sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && echo "Ports 80 and 443 opened successfully with ufw." || { echo "Failed to open ports with ufw."; exit 1; }
            ;;
        "iptables")
            echo "Opening ports 80 and 443 using iptables..."
            sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT && sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT && echo "Ports 80 and 443 opened successfully with iptables." || { echo "Failed to open ports with iptables."; exit 1; }
            if command -v iptables-save >/dev/null 2>&1; then
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null && echo "Iptables rules saved successfully." || echo "Warning: Could not save iptables rules automatically. Save manually if needed."
            fi
            ;;
        "none")
            echo "No firewall detected or configured. Skipping port opening. Ensure ports 80 and 443 are accessible if a firewall is later enabled."
            ;;
        *)
            echo "Unsupported firewall system. Please open ports 80 and 443 manually."
            exit 1
            ;;
    esac
}
# Function to verify if ports are open (optional check)
verify_ports() {
    if [ "$FIREWALL_RUNNING" == "no" ]; then
        echo "Firewall is not running, unable to verify port status. Check manually if needed."
        return
    fi
    echo "Verifying if ports 80 and 443 are open..."
    if [ "$FIREWALL" == "firewalld" ]; then
        firewall-cmd --list-ports | grep -E '80/tcp|443/tcp' && echo "Ports are open." || echo "Ports may not be open. Check firewall settings."
    elif [ "$FIREWALL" == "ufw" ]; then
        ufw status | grep -E '80|443' && echo "Ports are open." || echo "Ports may not be open. Check firewall settings."
    elif [ "$FIREWALL" == "iptables" ]; then
        iptables -L -n | grep -E '80|443' && echo "Ports are open." || echo "Ports may not be open. Check firewall settings."
    else
        echo "No firewall detected, unable to verify port status. Check manually if needed."
    fi
}
# Generate Flask secret key and create .env
generate_secret_key
create_env_file
# Create system_files and necessary files
create_system_files
# Detect the package manager
detect_package_manager
# Install dependencies
install_dependencies
# Setup PostgreSQL
setup_postgres
# Set up virtual environment and install requirements
python3 -m venv venv && echo "Virtual environment created successfully." || { echo "Failed to create virtual environment."; exit 1; }
source venv/bin/activate && echo "Virtual environment activated successfully." || { echo "Failed to activate virtual environment."; exit 1; }
pip install --upgrade pip && echo "Pip upgraded successfully." || echo "Failed to upgrade pip, continuing with current version."
pip install -r requirements.txt && echo "Requirements installation completed." || { echo "Requirements installation failed."; exit 1; }
# Run Flask migrations to set up DB schema
export FLASK_APP=app.py
flask db init 2>/dev/null || echo "DB init skipped (may already exist)."
flask db migrate -m "Initial migration" && flask db upgrade && echo "Database migrations completed." || { echo "Database migration failed."; exit 1; }
# Create user and set permissions
id isptracker >/dev/null 2>&1 || sudo adduser -r -s /bin/false isptracker && echo "User isptracker created successfully." || echo "User isptracker already exists."
sudo usermod -s /bin/bash isptracker && echo "User isptracker shell updated successfully." || { echo "Failed to update user isptracker shell."; exit 1; }
sudo chown -R isptracker:isptracker /opt/isp-invoice-tracker && echo "Permissions set for /opt/isp-invoice-tracker successfully." || { echo "Failed to set permissions for /opt/isp-invoice-tracker."; exit 1; }
# Copy configuration files before starting the service
copy_config_files
# Create symlink for systemd service
sudo ln -s /opt/isp-invoice-tracker/system_files/isp-invoice-tracker.service /etc/systemd/system/isp-invoice-tracker.service && echo "Systemd service symlink created successfully." || { echo "Failed to create systemd service symlink."; exit 1; }
sudo systemctl daemon-reload && echo "Systemd daemon reloaded successfully." || { echo "Failed to reload systemd daemon."; exit 1; }
sudo systemctl enable --now isp-invoice-tracker && echo "Systemd service enabled and started successfully." || { echo "Failed to enable and start systemd service."; exit 1; }
sudo systemctl status isp-invoice-tracker >/dev/null 2>&1 & wait $! && echo "Systemd service status checked successfully in background." || echo "Failed to check systemd service status in background."
# Set up SSL certificates
sudo mkdir -p /etc/ssl/private && echo "SSL private directory created successfully." || { echo "Failed to create SSL private directory."; exit 1; }
sudo chmod 700 /etc/ssl/private && echo "SSL private directory permissions set successfully." || { echo "Failed to set SSL private directory permissions."; exit 1; }
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/isp-invoice-tracker.key -out /etc/ssl/certs/isp-invoice-tracker.crt -batch && echo "SSL certificates generated successfully." || { echo "Failed to generate SSL certificates."; exit 1; }
# Configure Nginx based on system type
case $SYSTEM_TYPE in
    "debian")
        sudo ln -s /opt/isp-invoice-tracker/system_files/isp-invoice-tracker.conf /etc/nginx/sites-available/isp-invoice-tracker && echo "Nginx config symlink created in sites-available successfully." || { echo "Failed to create Nginx config symlink in sites-available."; exit 1; }
        sudo ln -s /etc/nginx/sites-available/isp-invoice-tracker /etc/nginx/sites-enabled/ && echo "Nginx config symlink enabled in sites-enabled successfully." || { echo "Failed to enable Nginx config symlink in sites-enabled."; exit 1; }
        ;;
    "rhel")
        sudo ln -s /opt/isp-invoice-tracker/system_files/isp-invoice-tracker.conf /etc/nginx/conf.d/isp-invoice-tracker.conf && echo "Nginx config symlink created in conf.d successfully." || { echo "Failed to create Nginx config symlink in conf.d."; exit 1; }
        sudo cp system_files/nginx.conf /etc/nginx/nginx.conf && echo "Nginx main config copied successfully." || { echo "Failed to copy Nginx main config."; exit 1; }
        sudo setsebool -P httpd_can_network_connect 1 && echo "SELinux boolean set successfully." || { echo "Failed to set SELinux boolean."; exit 1; }
        ;;
    *)
        echo "Unsupported system type. Please configure Nginx manually."
        exit 1
        ;;
esac
# Test and apply Nginx configuration
sudo nginx -t && echo "Nginx configuration test passed." || { echo "Nginx configuration test failed."; exit 1; }
sudo systemctl reload nginx && echo "Nginx reloaded successfully." || { echo "Failed to reload Nginx."; exit 1; }
# Firewall configuration
echo "Starting firewall configuration for ISP Invoice Tracker..."
detect_firewall
open_ports
verify_ports
echo "Firewall setup complete."
echo "Setup complete. Log in with admin/adminpassword and change the password."