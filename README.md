# ISP Invoice Tracker

A modern Flask-based web application for tracking ISP invoices, vendors, accounts, and services. This tool provides a beautiful, user-friendly interface for managing circuit and phone line attributes, including service types, locations, and descriptions. It supports hierarchical data (vendors > accounts > services) and includes user authentication with role-based access control.

The application uses SQLAlchemy with support for both SQLite (development) and PostgreSQL (production) as the backend database. It supports creating vendors (e.g., Alta Fiber, Lumen, Cogent), accounts under each vendor, and editable services with fields like type (phone, SIP, internet, WAN), service ID, phone number, A/Z locations, account number, and description.

## Features

- 🎨 Modern, responsive UI with gradient backgrounds and icons
- 🔐 User authentication with admin/user roles
- 🏢 Hierarchical vendor > account > service management
- 📊 Comprehensive service tracking with multiple attributes
- 🔍 Filterable service views
- ✏️ Full CRUD operations for all entities
- 📱 Mobile-friendly design

## Recent Improvements

- ✅ Fixed security issues (hardcoded passwords, missing CSRF protection)
- ✅ Added proper HTML structure with base template
- ✅ Implemented modern CSS styling with Font Awesome icons
- ✅ Changed DELETE operations to use POST method
- ✅ Added environment variable configuration
- ✅ Improved error handling and user feedback
- ✅ Added responsive design elements

## Prerequisites

For Production:
- A Linux-based system (RHEL 8/9 or Ubuntu 20.04/22.04 or later)
- Python 3.8 or higher
- Git
- Nginx
- PostgreSQL (installed via the setup script)
- Access to a user with sudo privileges for initial setup

For Development:
- Python 3.8 or higher
- Git
- Internet connection for dependencies

## Quick Start (Development)

1. Clone the repository:
```bash
git clone https://github.com/jcoeder/isp-circuit-invoice-tracker.git
cd isp-circuit-invoice-tracker
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open http://localhost:5000 in your browser

5. Login with username: `admin`, password: `adminpassword`

## Setup Instructions

This guide will walk you through setting up the ISP Invoice Tracker app as a non-root user named isptracker, installing it in /opt/isp-invoice-tracker, and configuring it to run as a systemd service with Nginx as a reverse proxy. Instructions are provided for both RHEL and Ubuntu systems.

### Step 1 and 2: Clone the repository and Install dependencies and setup the environment
```bash
cd /opt
sudo git clone https://github.com/jcoeder/isp-circuit-invoice-tracker.git

cd isp-circuit-invoice-tracker
sudo chmod +x setup.sh
sudo ./setup.sh
``` 
 
### Step 3: Configure environment variables
Create a `.env` file in the project root:
```bash
SECRET_KEY=your-secret-key-here
SQLALCHEMY_DATABASE_URI=postgresql://username:password@localhost/dbname
ADMIN_PASSWORD=your-admin-password
```

### Step 4: Check to see if the app, PostgreSQL, and Nginx are running
```bash
sudo systemctl status postgresql
sudo systemctl status nginx
sudo systemctl status isp-invoice-tracker
```


sudo ./setup.sh --clear-database
cd /opt
sudo rm -rf isp-circuit-invoice-tracker
sudo git clone https://github.com/jcoeder/isp-circuit-invoice-tracker.git

cd isp-circuit-invoice-tracker
sudo chmod +x setup.sh
sudo ./setup.sh
sudo systemctl restart isp-circuit-invoice-tracker