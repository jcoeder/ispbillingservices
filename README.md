# ISP Invoice Tracker

A Flask-based web application for tracking ISP invoices, vendors, accounts, and services. This tool provides a user-friendly interface for managing circuit and phone line attributes, including service types, locations, and descriptions. It supports hierarchical data (vendors > accounts > services) and includes user authentication with an initial admin account for adding other users.

The application uses PostgreSQL as the backend database for robust data storage and retrieval. It supports creating vendors (e.g., Alta Fiber, Lumen, Cogent), accounts under each vendor, and editable services with fields like type (phone, SIP, internet, WAN), service ID, phone number, A/Z locations, account number, and description.

## Prerequisites

    A Linux-based system (RHEL 8/9 or Ubuntu 20.04/22.04 or later)
    Python 3.8 or higher
    Git
    Nginx
    PostgreSQL (installed via the setup script)
    Access to a user with sudo privileges for initial setup

## Setup Instructions

This guide will walk you through setting up the ISP Invoice Tracker app as a non-root user named isptracker, installing it in /opt/isp-invoice-tracker, and configuring it to run as a systemd service with Nginx as a reverse proxy. Instructions are provided for both RHEL and Ubuntu systems.

###Step 1: Clone the repository
```bash
cd /opt
git clone https://github.com/jcoeder/isp-invoice-tracker.git
``` 
 
###Step 2: Install dependencies and setup the environment
```bash
cd isp-invoice-tracker
sudo ./setup.sh
``` 
 
###Step 3: Check to see if the app, PostgreSQL, and Nginx are running
```bash
sudo systemctl status postgresql
sudo systemctl status nginx
sudo systemctl status isp-invoice-tracker
```