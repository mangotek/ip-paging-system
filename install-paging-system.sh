#!/bin/bash
# Full-Featured IP Paging System for x86
# Tested on Ubuntu 22.04

# Configuration
ADMIN_USER="pagingadmin"
INSTALL_DIR="/opt/paging"
DB_DIR="/var/lib/paging"
LOG_DIR="/var/log/paging"
NGINX_DIR="/etc/nginx/sites-available"
SERVICE_FILE="/etc/systemd/system/paging-web.service"

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Verify architecture
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    echo "This installer is only for x86_64 systems"
    echo "Detected architecture: $ARCH"
    exit 1
fi

# Setup logging
LOG_FILE="/tmp/paging-install.log"
exec > >(tee -a ${LOG_FILE} )
exec 2> >(tee -a ${LOG_FILE} >&2)

echo "Starting full-featured installation at $(date)"
echo "System architecture: $ARCH"

# Install essential tools
apt update
apt install -y net-tools curl sqlite3

# Create directories
echo "Creating directories..."
mkdir -p $INSTALL_DIR $DB_DIR $LOG_DIR
chmod 755 $INSTALL_DIR $DB_DIR $LOG_DIR

# Create system user
if ! id "$ADMIN_USER" &>/dev/null; then
    echo "Creating system user: $ADMIN_USER"
    useradd -r -s /usr/sbin/nologin $ADMIN_USER
fi
chown -R $ADMIN_USER:$ADMIN_USER $INSTALL_DIR $DB_DIR $LOG_DIR

# Install dependencies
echo "Installing dependencies..."
apt install -y python3-pip python3-venv git nginx \
    gstreamer1.0-plugins-good gstreamer1.0-tools alsa-utils sox \
    build-essential libssl-dev libffi-dev ufw asterisk espeak

# Install Python dependencies
echo "Setting up Python environment..."
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate
pip install flask werkzeug configparser requests pyopenssl

# Create full-featured application
echo "Creating application files..."
cat > $INSTALL_DIR/app.py << 'EOL'
import os
import sys
import platform
import subprocess
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, flash
import configparser
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import json
import requests
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['CONFIG_DIR'] = '/etc/voip'
app.config['DB_FILE'] = '/var/lib/paging/paging_config.db'
app.config['AUDIT_LOG'] = '/var/log/paging/audit.log'

# Setup logging
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(app.config['AUDIT_LOG'])
audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
audit_logger.addHandler(audit_handler)

# Detect architecture
ARCH = platform.machine()

def log_audit_event(user, action, details, status="success"):
    try:
        ip_address = request.remote_addr if request else 'system'
        log_entry = f"{user} | {action} | {details} | {status} | {ip_address}"
        audit_logger.info(log_entry)
        
        # Store in SQLite for web UI
        conn = sqlite3.connect(app.config['DB_FILE'])
        c = conn.cursor()
        c.execute('''INSERT INTO audit_log 
                    (timestamp, username, action, details, status, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                 (datetime.utcnow().isoformat(), user, action, details, status, ip_address))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Audit logging failed: {str(e)}")

# Initialize system
def init_system():
    os.makedirs(app.config['CONFIG_DIR'], exist_ok=True)
    
    conn = sqlite3.connect(app.config['DB_FILE'])
    c = conn.cursor()
    
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS paging_groups
                 (id INTEGER PRIMARY KEY, name TEXT, extension TEXT, multicast_ip TEXT, port INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sip_settings
                 (id INTEGER PRIMARY KEY, host TEXT, port INTEGER, username TEXT, password TEXT, transport TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS relay_settings
                 (id INTEGER PRIMARY KEY, name TEXT, gpio_pin INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS integrations
                 (id INTEGER PRIMARY KEY, platform TEXT, api_url TEXT, api_key TEXT, config TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS webhooks
                 (id INTEGER PRIMARY KEY, name TEXT, url TEXT, event_type TEXT, payload_template TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log
                 (id INTEGER PRIMARY KEY,
                  timestamp TEXT,
                  username TEXT,
                  action TEXT,
                  details TEXT,
                  status TEXT,
                  ip_address TEXT)''')
    
    # Create default admin
    if not c.execute("SELECT * FROM users").fetchone():
        hashed_pw = generate_password_hash('admin')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                 ('admin', hashed_pw, 'admin'))
        log_audit_event('system', 'INIT', 'Created default admin user')
    
    # Create default Asterisk config
    if not os.path.exists("/etc/asterisk/pjsip.conf"):
        with open("/etc/asterisk/pjsip.conf", "w") as f:
            f.write("[transport-udp]\ntype=transport\nprotocol=udp\nbind=0.0.0.0\n")
    
    if not os.path.exists("/etc/asterisk/extensions.conf"):
        with open("/etc/asterisk/extensions.conf", "w") as f:
            f.write("[paging]\nexten => *73,1,Answer()\nsame => n,Playback(hello-world)\nsame => n,Hangup()\n")
    
    conn.commit()
    conn.close()

# Authentication decorator
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            log_audit_event('anonymous', 'ACCESS_DENIED', request.path, "unauthorized")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize the system
init_system()

# Application routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(app.config['DB_FILE'])
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = username
            log_audit_event(username, 'LOGIN', 'Successful login')
            return redirect(url_for('dashboard'))
        else:
            log_audit_event(username, 'LOGIN_FAIL', 'Invalid credentials')
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit_event(session['username'], 'LOGOUT', 'User logged out')
        session.pop('user_id', None)
        session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect(app.config['DB_FILE'])
    c = conn.cursor()
    
    # Get counts for dashboard
    c.execute("SELECT COUNT(*) FROM paging_groups")
    zone_count = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM relay_settings")
    relay_count = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM integrations")
    integration_count = c.fetchone()[0]
    
    # Get recent audit logs
    c.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 5")
    recent_logs = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                          zone_count=zone_count,
                          relay_count=relay_count,
                          integration_count=integration_count,
                          recent_logs=recent_logs,
                          arch=ARCH)

# SIP Settings Management
@app.route('/sip_settings', methods=['GET', 'POST'])
@login_required
def sip_settings():
    conn = sqlite3.connect(app.config['DB_FILE'])
    c = conn.cursor()
    
    if request.method == 'POST':
        host = request.form['host']
        port = request.form['port']
        username = request.form['username']
        password = request.form['password']
        transport = request.form['transport']
        
        # Update or create SIP settings
        c.execute("DELETE FROM sip_settings")
        c.execute('''INSERT INTO sip_settings (host, port, username, password, transport)
                     VALUES (?, ?, ?, ?, ?)''', 
                 (host, port, username, password, transport))
        conn.commit()
        
        # Update Asterisk configuration
        update_asterisk_config()
        
        log_audit_event(session['username'], 'SIP_UPDATE', f"Updated SIP settings for {host}")
        flash('SIP settings updated successfully!', 'success')
        return redirect(url_for('sip_settings'))
    
    settings = c.execute("SELECT * FROM sip_settings").fetchone()
    conn.close()
    
    return render_template('sip_settings.html', settings=settings)

def update_asterisk_config():
    # Get SIP settings
    conn = sqlite3.connect(app.config['DB_FILE'])
    c = conn.cursor()
    sip_settings = c.execute("SELECT * FROM sip_settings").fetchone()
    
    # Update pjsip.conf
    if sip_settings:
        with open("/etc/asterisk/pjsip.conf", "w") as f:
            f.write(f"[transport-udp]\ntype=transport\nprotocol=udp\nbind=0.0.0.0\n\n")
            f.write(f"[{sip_settings[3]}]\n")
            f.write(f"type=endpoint\n")
            f.write(f"context=paging\n")
            f.write(f"auth={sip_settings[3]}\n")
            f.write(f"aors={sip_settings[3]}\n\n")
            f.write(f"[{sip_settings[3]}]\n")
            f.write(f"type=auth\n")
            f.write(f"auth_type=userpass\n")
            f.write(f"username={sip_settings[3]}\n")
            f.write(f"password={sip_settings[4]}\n\n")
            f.write(f"[{sip_settings[3]}]\n")
            f.write(f"type=aor\n")
            f.write(f"max_contacts=1\n\n")
    
    # Update extensions.conf with paging groups
    with open("/etc/asterisk/extensions.conf", "w") as f:
        f.write("[paging]\n")
        
        # Add paging groups
        groups = c.execute("SELECT * FROM paging_groups").fetchall()
        for group in groups:
            f.write(f"exten => {group[2]},1,Answer()\n")
            f.write(f"same => n,Page(SIP/{group[1]},,30)\n")
            f.write(f"same => n,Hangup()\n\n")
    
    conn.close()
    
    # Reload Asterisk configuration
    subprocess.run(['asterisk', '-rx', 'core reload'], check=True)
    log_audit_event('system', 'ASTERISK_RELOAD', 'Reloaded Asterisk configuration')

# Paging Groups Management
@app.route('/paging_groups', methods=['GET', 'POST'])
@login_required
def paging_groups():
    conn = sqlite3.connect(app.config['DB_FILE'])
    c = conn.cursor()
    
    if request.method == 'POST':
        if 'delete' in request.form:
            group_id = request.form['id']
            c.execute("DELETE FROM paging_groups WHERE id = ?", (group_id,))
            conn.commit()
            update_asterisk_config()
            log_audit_event(session['username'], 'PAGING_DELETE', f"Deleted paging group {group_id}")
            flash('Paging group deleted!', 'success')
        else:
            name = request.form['name']
            extension = request.form['extension']
            multicast_ip = request.form['multicast_ip']
            port = request.form['port']
            
            if 'id' in request.form and request.form['id']:
                # Update existing group
                group_id = request.form['id']
                c.execute('''UPDATE paging_groups 
                            SET name=?, extension=?, multicast_ip=?, port=?
                            WHERE id=?''', 
                         (name, extension, multicast_ip, port, group_id))
                action = 'updated'
            else:
                # Create new group
                c.execute('''INSERT INTO paging_groups (name, extension, multicast_ip, port)
                            VALUES (?, ?, ?, ?)''', 
                         (name, extension, multicast_ip, port))
                action = 'created'
            
            conn.commit()
            update_asterisk_config()
            log_audit_event(session['username'], 'PAGING_UPDATE', f"{action} paging group: {name}")
            flash(f'Paging group {action} successfully!', 'success')
        
        return redirect(url_for('paging_groups'))
    
    groups = c.execute("SELECT * FROM paging_groups").fetchall()
    conn.close()
    
    return render_template('paging_groups.html', groups=groups)

# Relay Controls Management
@app.route('/relay_controls', methods=['GET', 'POST'])
@login_required
def relay_controls():
    conn = sqlite3.connect(app.config['DB_FILE'])
    c = conn.cursor()
    
    if request.method == 'POST':
        if 'delete' in request.form:
            relay_id = request.form['id']
            c.execute("DELETE FROM relay_settings WHERE id = ?", (relay_id,))
            conn.commit()
            log_audit_event(session['username'], 'RELAY_DELETE', f"Deleted relay {relay_id}")
            flash('Relay deleted!', 'success')
        elif 'trigger' in request.form:
            relay_id = request.form['id']
            # Simulate relay triggering
            log_audit_event(session['username'], 'RELAY_TRIGGER', f"Triggered relay {relay_id}")
            flash('Relay triggered successfully!', 'success')
        else:
            name = request.form['name']
            gpio_pin = request.form['gpio_pin']
            
            if 'id' in request.form and request.form['id']:
                # Update existing relay
                relay_id = request.form['id']
                c.execute('''UPDATE relay_settings 
                            SET name=?, gpio_pin=?
                            WHERE id=?''', 
                         (name, gpio_pin, relay_id))
                action = 'updated'
            else:
                # Create new relay
                c.execute('''INSERT INTO relay_settings (name, gpio_pin)
                            VALUES (?, ?)''', 
                         (name, gpio_pin))
                action = 'created'
            
            conn.commit()
            log_audit_event(session['username'], 'RELAY_UPDATE', f"{action} relay: {name}")
            flash(f'Relay {action} successfully!', 'success')
        
        return redirect(url_for('relay_controls'))
    
    relays = c.execute("SELECT * FROM relay_settings").fetchall()
    conn.close()
    
    return render_template('relay_controls.html', relays=relays)

# Audit Log Viewer
@app.route('/audit_log')
@login_required
def audit_log():
    conn = sqlite3.connect(app.config['DB_FILE'])
    c = conn.cursor()
    
    # Get parameters for filtering
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    
    # Get total count
    c.execute("SELECT COUNT(*) FROM audit_log")
    total = c.fetchone()[0]
    
    # Get log entries
    c.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?", 
             (per_page, offset))
    logs = c.fetchall()
    
    conn.close()
    
    return render_template('audit_log.html', 
                           logs=logs, 
                           page=page,
                           per_page=per_page,
                           total=total)

# System Information
@app.route('/system_info')
@login_required
def system_info():
    # Get system information
    cpu_info = "Unknown"
    mem_info = "Unknown"
    disk_info = "Unknown"
    
    try:
        # CPU info
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if 'model name' in line:
                    cpu_info = line.split(':')[1].strip()
                    break
        
        # Memory info
        with open('/proc/meminfo', 'r') as f:
            total_mem = f.readline().split()[1]
            mem_info = f"{int(total_mem) / 1024:.1f} MB"
        
        # Disk info
        disk_result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True)
        disk_info = disk_result.stdout.split('\n')[1].split()[1:5]
        
    except Exception as e:
        print(f"Error getting system info: {e}")
    
    return render_template('system_info.html',
                           cpu_info=cpu_info,
                           mem_info=mem_info,
                           disk_info=disk_info,
                           arch=ARCH)

# API Endpoint for Paging
@app.route('/api/page', methods=['POST'])
@login_required
def api_page():
    data = request.json
    zone = data.get('zone', 'default')
    
    # Trigger page through Asterisk
    try:
        subprocess.run(['asterisk', '-rx', f'originate SIP/{zone} extension *73{zone}@paging'], check=True)
        log_audit_event(session['username'], 'API_PAGE', f"Paged zone: {zone}")
        return jsonify({'status': 'success', 'zone': zone})
    except subprocess.CalledProcessError as e:
        log_audit_event(session['username'], 'API_PAGE_FAIL', f"Failed to page zone: {zone}", "error")
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
EOL

# Create templates directory
echo "Creating templates..."
mkdir -p $INSTALL_DIR/templates

# Create login template
cat > $INSTALL_DIR/templates/login.html << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Paging Control - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #0a4f9e, #083a76);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
            padding: 2rem;
        }
        .logo {
            text-align: center;
            margin-bottom: 2rem;
        }
        .logo img {
            width: 80px;
            margin-bottom: 1rem;
        }
        .logo h2 {
            font-weight: 700;
            color: #0a4f9e;
        }
        .alert {
            margin-bottom: 1.5rem;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo">
            <img src="https://cdn-icons-png.flaticon.com/512/1946/1946433.png" alt="Paging System">
            <h2>Paging Control</h2>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST" action="/login">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Sign In</button>
        </form>
        <div class="mt-3 text-center text-muted">
            <small>Default: admin/admin</small>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOL

# Create dashboard template
cat > $INSTALL_DIR/templates/dashboard.html << 'EOL'
{% extends "base.html" %}

{% block title %}Dashboard{% endblock %}

{% block content %}
<div class="container-fluid">
    <h1 class="mt-4">Dashboard</h1>
    
    <!-- Status Cards -->
    <div class="row mt-4">
        <div class="col-xl-3 col-md-6 mb-4">
            <div class="card border-left-primary shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                Paging Zones
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800">{{ zone_count }}</div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-bullhorn fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-xl-3 col-md-6 mb-4">
            <div class="card border-left-success shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-success text-uppercase mb-1">
                                Relay Controls
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800">{{ relay_count }}</div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-plug fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-xl-3 col-md-6 mb-4">
            <div class="card border-left-info shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-info text-uppercase mb-1">
                                System Integrations
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800">{{ integration_count }}</div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-puzzle-piece fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-xl-3 col-md-6 mb-4">
            <div class="card border-left-warning shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">
                                System Architecture
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800">{{ arch }}</div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-server fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Activity -->
    <div class="row">
        <div class="col-lg-6">
            <div class="card shadow mb-4">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-primary">Quick Actions</h6>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <a href="/paging_groups" class="btn btn-primary btn-block">
                                <i class="fas fa-plus mr-2"></i> Add Zone
                            </a>
                        </div>
                        <div class="col-md-6 mb-3">
                            <a href="/relay_controls" class="btn btn-success btn-block">
                                <i class="fas fa-plug mr-2"></i> Manage Relays
                            </a>
                        </div>
                        <div class="col-md-6 mb-3">
                            <a href="/sip_settings" class="btn btn-info btn-block">
                                <i class="fas fa-phone-alt mr-2"></i> SIP Settings
                            </a>
                        </div>
                        <div class="col-md-6 mb-3">
                            <a href="/system_info" class="btn btn-warning btn-block">
                                <i class="fas fa-server mr-2"></i> System Info
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-lg-6">
            <div class="card shadow mb-4">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-primary">Recent Activity</h6>
                </div>
                <div class="card-body">
                    <div class="list-group">
                        {% for log in recent_logs %}
                        <a href="#" class="list-group-item list-group-item-action">
                            <div class="d-flex w-100 justify-content-between">
                                <h6 class="mb-1">{{ log[3] }}</h6>
                                <small>{{ log[1]|datetimeformat }}</small>
                            </div>
                            <p class="mb-1">{{ log[4] }}</p>
                            <small>Status: 
                                <span class="badge bg-{% if log[5] == 'success' %}success{% else %}danger{% endif %}">
                                    {{ log[5] }}
                                </span>
                            </small>
                        </a>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOL

# Create base template
cat > $INSTALL_DIR/templates/base.html << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Paging Control - {% block title %}{% endblock %}</title>
    
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css?family=Nunito:200,200i,300,300i,400,400i,600,600i,700,700i,800,800i,900,900i" rel="stylesheet">
    <!-- Bootstrap -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Custom Styles -->
    <style>
        :root {
            --primary: #0a4f9e;
            --primary-dark: #083a76;
            --secondary: #1a1f2c;
        }
        
        body {
            background-color: #f8f9fc;
        }
        
        #wrapper {
            display: flex;
        }
        
        #content-wrapper {
            width: 100%;
            overflow-x: hidden;
        }
        
        .sidebar {
            width: 250px;
            background: var(--secondary);
            color: white;
            height: 100vh;
            position: fixed;
            transition: all 0.3s;
            z-index: 1000;
        }
        
        .sidebar .sidebar-header {
            padding: 20px;
            background: var(--primary-dark);
        }
        
        .sidebar ul.components {
            padding: 20px 0;
        }
        
        .sidebar ul li a {
            padding: 10px 20px;
            display: block;
            color: #ccc;
            text-decoration: none;
            transition: all 0.3s;
        }
        
        .sidebar ul li a:hover {
            color: #fff;
            background: var(--primary);
        }
        
        .sidebar ul li.active > a {
            color: #fff;
            background: var(--primary);
        }
        
        .sidebar ul li a i {
            margin-right: 10px;
        }
        
        #content {
            margin-left: 250px;
            width: calc(100% - 250px);
            padding: 20px;
            min-height: 100vh;
        }
        
        .navbar {
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .page-header {
            border-bottom: 1px solid #e3e6f0;
            padding-bottom: 15px;
            margin-bottom: 20px;
        }
        
        .card {
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 20px;
            border: none;
        }
        
        .card-header {
            background: white;
            border-bottom: 1px solid #e3e6f0;
            padding: 15px 20px;
            border-radius: 8px 8px 0 0 !important;
        }
        
        .table th {
            font-weight: 600;
            color: var(--secondary);
        }
        
        .badge-success {
            background-color: #28a745;
        }
        
        .badge-danger {
            background-color: #dc3545;
        }
        
        .btn-primary {
            background-color: var(--primary);
            border-color: var(--primary);
        }
        
        .btn-primary:hover {
            background-color: var(--primary-dark);
            border-color: var(--primary-dark);
        }
    </style>
    {% block styles %}{% endblock %}
</head>
<body>
    <div id="wrapper">
        <!-- Sidebar -->
        <nav class="sidebar">
            <div class="sidebar-header">
                <h3>Paging Control</h3>
            </div>
            
            <ul class="list-unstyled components">
                <li class="active">
                    <a href="/dashboard">
                        <i class="fas fa-tachometer-alt"></i> Dashboard
                    </a>
                </li>
                <li>
                    <a href="/paging_groups">
                        <i class="fas fa-bullhorn"></i> Paging Zones
                    </a>
                </li>
                <li>
                    <a href="/relay_controls">
                        <i class="fas fa-plug"></i> Relay Controls
                    </a>
                </li>
                <li>
                    <a href="/sip_settings">
                        <i class="fas fa-phone-alt"></i> SIP Settings
                    </a>
                </li>
                <li>
                    <a href="#">
                        <i class="fas fa-puzzle-piece"></i> Integrations
                    </a>
                </li>
                <li>
                    <a href="/audit_log">
                        <i class="fas fa-clipboard-list"></i> Audit Log
                    </a>
                </li>
                <li>
                    <a href="/system_info">
                        <i class="fas fa-server"></i> System Info
                    </a>
                </li>
                <li>
                    <a href="/logout">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </li>
            </ul>
        </nav>
        
        <!-- Content Wrapper -->
        <div id="content-wrapper">
            <!-- Topbar -->
            <nav class="navbar navbar-expand navbar-light bg-white topbar mb-4 static-top shadow">
                <button id="sidebarToggle" class="btn btn-link d-md-none mr-3">
                    <i class="fa fa-bars"></i>
                </button>
                
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item dropdown no-arrow">
                        <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button"
                            data-bs-toggle="dropdown" aria-expanded="false">
                            <span class="mr-2 d-none d-lg-inline text-gray-600 small">{{ session.username }}</span>
                            <i class="fas fa-user-circle fa-fw"></i>
                        </a>
                        <div class="dropdown-menu dropdown-menu-right shadow animated--grow-in"
                            aria-labelledby="userDropdown">
                            <a class="dropdown-item" href="#">
                                <i class="fas fa-user fa-sm fa-fw mr-2 text-gray-400"></i>
                                Profile
                            </a>
                            <a class="dropdown-item" href="#">
                                <i class="fas fa-cogs fa-sm fa-fw mr-2 text-gray-400"></i>
                                Settings
                            </a>
                            <div class="dropdown-divider"></div>
                            <a class="dropdown-item" href="/logout">
                                <i class="fas fa-sign-out-alt fa-sm fa-fw mr-2 text-gray-400"></i>
                                Logout
                            </a>
                        </div>
                    </li>
                </ul>
            </nav>
            
            <!-- Main Content -->
            <div id="content">
                <div class="container-fluid">
                    {% with messages = get_flashed_messages(with_categories=true) %}
                        {% if messages %}
                            {% for category, message in messages %}
                                <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                                    {{ message }}
                                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                                </div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    
                    {% block content %}{% endblock %}
                </div>
            </div>
        </div>
    </div>
    
    <!-- Scripts -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Toggle sidebar on mobile
        $('#sidebarToggle').click(function() {
            $('.sidebar').toggleClass('active');
            $('#content').toggleClass('full-width');
        });
        
        // Mark active menu item
        $(document).ready(function() {
            const current = location.pathname;
            $('.sidebar li a').each(function() {
                const $this = $(this);
                if ($this.attr('href') === current) {
                    $this.parent().addClass('active');
                }
            });
        });
    </script>
    {% block scripts %}{% endblock %}
</body>
</html>
EOL

# Create SIP settings template
cat > $INSTALL_DIR/templates/sip_settings.html << 'EOL'
{% extends "base.html" %}

{% block title %}SIP Settings{% endblock %}

{% block content %}
<div class="container-fluid">
    <div class="page-header">
        <h1 class="h3 mb-0 text-gray-800">SIP Settings</h1>
        <p class="mb-4">Configure your SIP server connection settings</p>
    </div>
    
    <div class="card shadow mb-4">
        <div class="card-header py-3">
            <h6 class="m-0 font-weight-bold text-primary">SIP Configuration</h6>
        </div>
        <div class="card-body">
            <form method="POST" action="/sip_settings">
                <div class="row mb-3">
                    <div class="col-md-6">
                        <label class="form-label">SIP Host</label>
                        <input type="text" class="form-control" name="host" 
                               value="{{ settings[1] if settings else '' }}" required>
                    </div>
                    <div class="col-md-6">
                        <label class="form-label">SIP Port</label>
                        <input type="number" class="form-control" name="port" 
                               value="{{ settings[2] if settings else 5060 }}" required>
                    </div>
                </div>
                
                <div class="row mb-3">
                    <div class="col-md-6">
                        <label class="form-label">Username</label>
                        <input type="text" class="form-control" name="username" 
                               value="{{ settings[3] if settings else '' }}" required>
                    </div>
                    <div class="col-md-6">
                        <label class="form-label">Password</label>
                        <input type="password" class="form-control" name="password" 
                               value="{{ settings[4] if settings else '' }}" required>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-md-6">
                        <label class="form-label">Transport Protocol</label>
                        <select class="form-select" name="transport" required>
                            <option value="udp" {% if settings and settings[5] == 'udp' %}selected{% endif %}>UDP</option>
                            <option value="tcp" {% if settings and settings[5] == 'tcp' %}selected{% endif %}>TCP</option>
                            <option value="tls" {% if settings and settings[5] == 'tls' %}selected{% endif %}>TLS</option>
                        </select>
                    </div>
                </div>
                
                <button type="submit" class="btn btn-primary">Save Settings</button>
                <a href="/dashboard" class="btn btn-secondary">Cancel</a>
            </form>
        </div>
    </div>
    
    <div class="card shadow mb-4">
        <div class="card-header py-3">
            <h6 class="m-0 font-weight-bold text-primary">Test Connection</h6>
        </div>
        <div class="card-body">
            <p>Test your SIP configuration before saving:</p>
            <button class="btn btn-info" id="testSip">Test SIP Connection</button>
            <div id="testResult" class="mt-3"></div>
        </div>
    </div>
</div>

<script>
    $(document).ready(function() {
        $('#testSip').click(function() {
            const formData = {
                host: $('input[name="host"]').val(),
                port: $('input[name="port"]').val(),
                username: $('input[name="username"]').val(),
                password: $('input[name="password"]').val(),
                transport: $('select[name="transport"]').val()
            };
            
            $('#testResult').html('<div class="alert alert-info">Testing connection...</div>');
            
            $.post('/api/test_sip', formData, function(response) {
                if (response.status === 'success') {
                    $('#testResult').html('<div class="alert alert-success">Connection successful! ' + response.message + '</div>');
                } else {
                    $('#testResult').html('<div class="alert alert-danger">Connection failed: ' + response.message + '</div>');
                }
            }).fail(function() {
                $('#testResult').html('<div class="alert alert-danger">Connection test failed. Please check your settings.</div>');
            });
        });
    });
</script>
{% endblock %}
EOL

# Create paging groups template
cat > $INSTALL_DIR/templates/paging_groups.html << 'EOL'
{% extends "base.html" %}

{% block title %}Paging Zones{% endblock %}

{% block content %}
<div class="container-fluid">
    <div class="page-header">
        <h1 class="h3 mb-0 text-gray-800">Paging Zones</h1>
        <p class="mb-4">Manage your paging zones and configurations</p>
    </div>
    
    <div class="card shadow mb-4">
        <div class="card-header py-3 d-flex justify-content-between align-items-center">
            <h6 class="m-0 font-weight-bold text-primary">Paging Zones</h6>
            <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addZoneModal">
                <i class="fas fa-plus"></i> Add Zone
            </button>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-bordered" id="dataTable" width="100%" cellspacing="0">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Extension</th>
                            <th>Multicast IP</th>
                            <th>Port</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for group in groups %}
                        <tr>
                            <td>{{ group[1] }}</td>
                            <td>{{ group[2] }}</td>
                            <td>{{ group[3] }}</td>
                            <td>{{ group[4] }}</td>
                            <td>
                                <button class="btn btn-sm btn-warning edit-zone" 
                                        data-id="{{ group[0] }}"
                                        data-name="{{ group[1] }}"
                                        data-extension="{{ group[2] }}"
                                        data-ip="{{ group[3] }}"
                                        data-port="{{ group[4] }}">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <form action="/paging_groups" method="POST" style="display:inline;">
                                    <input type="hidden" name="id" value="{{ group[0] }}">
                                    <button type="submit" name="delete" class="btn btn-sm btn-danger">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </form>
                                <button class="btn btn-sm btn-info test-zone" data-zone="{{ group[0] }}">
                                    <i class="fas fa-play"></i> Test
                                </button>
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="5" class="text-center">No paging zones configured</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- Add Zone Modal -->
<div class="modal fade" id="addZoneModal" tabindex="-1" aria-labelledby="addZoneModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="addZoneModalLabel">Add Paging Zone</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="POST" action="/paging_groups">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Zone Name</label>
                        <input type="text" class="form-control" name="name" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Extension</label>
                        <input type="text" class="form-control" name="extension" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Multicast IP</label>
                        <input type="text" class="form-control" name="multicast_ip" placeholder="239.1.1.1" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Port</label>
                        <input type="number" class="form-control" name="port" value="1234" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Zone</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Edit Zone Modal -->
<div class="modal fade" id="editZoneModal" tabindex="-1" aria-labelledby="editZoneModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="editZoneModalLabel">Edit Paging Zone</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="POST" action="/paging_groups">
                <input type="hidden" name="id" id="editZoneId">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Zone Name</label>
                        <input type="text" class="form-control" name="name" id="editZoneName" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Extension</label>
                        <input type="text" class="form-control" name="extension" id="editZoneExtension" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Multicast IP</label>
                        <input type="text" class="form-control" name="multicast_ip" id="editZoneIp" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Port</label>
                        <input type="number" class="form-control" name="port" id="editZonePort" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Update Zone</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
    $(document).ready(function() {
        // Handle edit button clicks
        $('.edit-zone').click(function() {
            const id = $(this).data('id');
            const name = $(this).data('name');
            const extension = $(this).data('extension');
            const ip = $(this).data('ip');
            const port = $(this).data('port');
            
            $('#editZoneId').val(id);
            $('#editZoneName').val(name);
            $('#editZoneExtension').val(extension);
            $('#editZoneIp').val(ip);
            $('#editZonePort').val(port);
            
            $('#editZoneModal').modal('show');
        });
        
        // Handle test button clicks
        $('.test-zone').click(function() {
            const zoneId = $(this).data('zone');
            
            $.post('/api/test_zone', {zone_id: zoneId}, function(response) {
                if (response.status === 'success') {
                    alert('Test page sent successfully!');
                } else {
                    alert('Error sending test page: ' + response.message);
                }
            }).fail(function() {
                alert('Error sending test page. Please try again.');
            });
        });
    });
</script>
{% endblock %}
EOL

# Create relay controls template
cat > $INSTALL_DIR/templates/relay_controls.html << 'EOL'
{% extends "base.html" %}

{% block title %}Relay Controls{% endblock %}

{% block content %}
<div class="container-fluid">
    <div class="page-header">
        <h1 class="h3 mb-0 text-gray-800">Relay Controls</h1>
        <p class="mb-4">Manage door relays and access controls</p>
    </div>
    
    <div class="card shadow mb-4">
        <div class="card-header py-3 d-flex justify-content-between align-items-center">
            <h6 class="m-0 font-weight-bold text-primary">Relay Devices</h6>
            <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addRelayModal">
                <i class="fas fa-plus"></i> Add Relay
            </button>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-bordered" width="100%" cellspacing="0">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>GPIO Pin</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for relay in relays %}
                        <tr>
                            <td>{{ relay[1] }}</td>
                            <td>{{ relay[2] }}</td>
                            <td>
                                <button class="btn btn-sm btn-warning edit-relay" 
                                        data-id="{{ relay[0] }}"
                                        data-name="{{ relay[1] }}"
                                        data-pin="{{ relay[2] }}">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <form action="/relay_controls" method="POST" style="display:inline;">
                                    <input type="hidden" name="id" value="{{ relay[0] }}">
                                    <button type="submit" name="delete" class="btn btn-sm btn-danger">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </form>
                                <form action="/relay_controls" method="POST" style="display:inline;">
                                    <input type="hidden" name="id" value="{{ relay[0] }}">
                                    <button type="submit" name="trigger" class="btn btn-sm btn-success">
                                        <i class="fas fa-bolt"></i> Trigger
                                    </button>
                                </form>
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="3" class="text-center">No relay devices configured</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- Add Relay Modal -->
<div class="modal fade" id="addRelayModal" tabindex="-1" aria-labelledby="addRelayModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="addRelayModalLabel">Add Relay Device</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="POST" action="/relay_controls">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Relay Name</label>
                        <input type="text" class="form-control" name="name" placeholder="Front Door" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">GPIO Pin</label>
                        <input type="number" class="form-control" name="gpio_pin" placeholder="17" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Relay</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Edit Relay Modal -->
<div class="modal fade" id="editRelayModal" tabindex="-1" aria-labelledby="editRelayModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="editRelayModalLabel">Edit Relay Device</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="POST" action="/relay_controls">
                <input type="hidden" name="id" id="editRelayId">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Relay Name</label>
                        <input type="text" class="form-control" name="name" id="editRelayName" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">GPIO Pin</label>
                        <input type="number" class="form-control" name="gpio_pin" id="editRelayPin" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Update Relay</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
    $(document).ready(function() {
        // Handle edit button clicks
        $('.edit-relay').click(function() {
            const id = $(this).data('id');
            const name = $(this).data('name');
            const pin = $(this).data('pin');
            
            $('#editRelayId').val(id);
            $('#editRelayName').val(name);
            $('#editRelayPin').val(pin);
            
            $('#editRelayModal').modal('show');
        });
    });
</script>
{% endblock %}
EOL

# Create audit log template
cat > $INSTALL_DIR/templates/audit_log.html << 'EOL'
{% extends "base.html" %}

{% block title %}Audit Log{% endblock %}

{% block content %}
<div class="container-fluid">
    <div class="page-header">
        <h1 class="h3 mb-0 text-gray-800">Audit Log</h1>
        <p class="mb-4">System activity and event history</p>
    </div>
    
    <div class="card shadow mb-4">
        <div class="card-header py-3">
            <h6 class="m-0 font-weight-bold text-primary">Recent Events</h6>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-bordered" width="100%" cellspacing="0">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>Details</th>
                            <th>Status</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for log in logs %}
                        <tr>
                            <td>{{ log[1] }}</td>
                            <td>{{ log[2] }}</td>
                            <td>{{ log[3] }}</td>
                            <td>{{ log[4] }}</td>
                            <td>
                                <span class="badge bg-{% if log[5] == 'success' %}success{% else %}danger{% endif %}">
                                    {{ log[5] }}
                                </span>
                            </td>
                            <td>{{ log[6] }}</td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="6" class="text-center">No audit records found</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination -->
            <nav aria-label="Page navigation">
                <ul class="pagination justify-content-center">
                    {% if page > 1 %}
                    <li class="page-item">
                        <a class="page-link" href="?page={{ page - 1 }}">Previous</a>
                    </li>
                    {% endif %}
                    
                    {% for p in range(1, (total // per_page) + 2) %}
                    <li class="page-item {% if p == page %}active{% endif %}">
                        <a class="page-link" href="?page={{ p }}">{{ p }}</a>
                    </li>
                    {% endfor %}
                    
                    {% if page < (total // per_page) + 1 %}
                    <li class="page-item">
                        <a class="page-link" href="?page={{ page + 1 }}">Next</a>
                    </li>
                    {% endif %}
                </ul>
            </nav>
        </div>
    </div>
</div>
{% endblock %}
EOL

# Create system info template
cat > $INSTALL_DIR/templates/system_info.html << 'EOL'
{% extends "base.html" %}

{% block title %}System Information{% endblock %}

{% block content %}
<div class="container-fluid">
    <div class="page-header">
        <h1 class="h3 mb-0 text-gray-800">System Information</h1>
        <p class="mb-4">Hardware and software configuration details</p>
    </div>
    
    <div class="row">
        <div class="col-lg-6">
            <div class="card shadow mb-4">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-primary">System Overview</h6>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-bordered" width="100%" cellspacing="0">
                            <tbody>
                                <tr>
                                    <th>Architecture</th>
                                    <td>{{ arch }}</td>
                                </tr>
                                <tr>
                                    <th>CPU Model</th>
                                    <td>{{ cpu_info }}</td>
                                </tr>
                                <tr>
                                    <th>Total Memory</th>
                                    <td>{{ mem_info }}</td>
                                </tr>
                                <tr>
                                    <th>Disk Space</th>
                                    <td>{{ disk_info[0] }} used of {{ disk_info[1] }} ({{ disk_info[4] }})</td>
                                </tr>
                                <tr>
                                    <th>System Uptime</th>
                                    <td id="systemUptime">Loading...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-lg-6">
            <div class="card shadow mb-4">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-primary">Services Status</h6>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-bordered" width="100%" cellspacing="0">
                            <thead>
                                <tr>
                                    <th>Service</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>Web Interface</td>
                                    <td id="webStatus">Checking...</td>
                                    <td>
                                        <button class="btn btn-sm btn-primary" id="restartWeb">Restart</button>
                                    </td>
                                </tr>
                                <tr>
                                    <td>Asterisk (SIP Server)</td>
                                    <td id="asteriskStatus">Checking...</td>
                                    <td>
                                        <button class="btn btn-sm btn-primary" id="restartAsterisk">Restart</button>
                                    </td>
                                </tr>
                                <tr>
                                    <td>Nginx (Web Server)</td>
                                    <td id="nginxStatus">Checking...</td>
                                    <td>
                                        <button class="btn btn-sm btn-primary" id="restartNginx">Restart</button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="card shadow mb-4">
        <div class="card-header py-3">
            <h6 class="m-0 font-weight-bold text-primary">System Actions</h6>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-3 mb-3">
                    <button class="btn btn-warning w-100" id="rebootSystem">
                        <i class="fas fa-sync-alt mr-2"></i> Reboot System
                    </button>
                </div>
                <div class="col-md-3 mb-3">
                    <button class="btn btn-danger w-100" id="shutdownSystem">
                        <i class="fas fa-power-off mr-2"></i> Shutdown
                    </button>
                </div>
                <div class="col-md-3 mb-3">
                    <button class="btn btn-info w-100" id="backupSystem">
                        <i class="fas fa-download mr-2"></i> Backup Config
                    </button>
                </div>
                <div class="col-md-3 mb-3">
                    <button class="btn btn-success w-100" id="updateSystem">
                        <i class="fas fa-cloud-download-alt mr-2"></i> Update
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    $(document).ready(function() {
        // Get system uptime
        function updateUptime() {
            $.get('/api/system_uptime', function(data) {
                $('#systemUptime').text(data.uptime);
            });
        }
        updateUptime();
        setInterval(updateUptime, 60000);
        
        // Check service statuses
        function checkServices() {
            $.get('/api/service_status', function(data) {
                $('#webStatus').html(data.web_status);
                $('#asteriskStatus').html(data.asterisk_status);
                $('#nginxStatus').html(data.nginx_status);
            });
        }
        checkServices();
        setInterval(checkServices, 30000);
        
        // Service restart buttons
        $('#restartWeb').click(function() {
            $.post('/api/restart_service', {service: 'paging-web'}, function() {
                alert('Web service restarted successfully');
                checkServices();
            });
        });
        
        $('#restartAsterisk').click(function() {
            $.post('/api/restart_service', {service: 'asterisk'}, function() {
                alert('Asterisk service restarted successfully');
                checkServices();
            });
        });
        
        $('#restartNginx').click(function() {
            $.post('/api/restart_service', {service: 'nginx'}, function() {
                alert('Nginx service restarted successfully');
                checkServices();
            });
        });
        
        // System actions
        $('#rebootSystem').click(function() {
            if (confirm('Are you sure you want to reboot the system?')) {
                $.post('/api/reboot_system');
                alert('System rebooting...');
            }
        });
        
        $('#shutdownSystem').click(function() {
            if (confirm('Are you sure you want to shutdown the system?')) {
                $.post('/api/shutdown_system');
                alert('System shutting down...');
            }
        });
    });
</script>
{% endblock %}
EOL

# Create systemd service file
echo "Creating systemd service..."
cat > $SERVICE_FILE << EOL
[Unit]
Description=IP Paging Web Interface
After=network.target asterisk.service

[Service]
User=$ADMIN_USER
Group=$ADMIN_USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/bin"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/app.log
StandardError=append:$LOG_DIR/error.log

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
EOL

# Create Nginx configuration
echo "Configuring Nginx..."
cat > $NGINX_DIR/paging << EOL
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    # Access and error logs
    access_log $LOG_DIR/nginx-access.log;
    error_log $LOG_DIR/nginx-error.log;
    
    # Proxy configuration
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        send_timeout 60s;
    }
    
    # Block access to sensitive files
    location ~ /\.(?!well-known).* {
        deny all;
    }
}
EOL

# Remove default site
echo "Removing default Nginx site..."
rm -f /etc/nginx/sites-enabled/default

# Enable configuration
echo "Enabling Nginx site..."
ln -sf $NGINX_DIR/paging /etc/nginx/sites-enabled/

# Configure firewall
echo "Configuring firewall..."
ufw allow 80/tcp
ufw allow 5060/udp
ufw --force enable

# Set permissions for Asterisk
usermod -a -G dialout $ADMIN_USER
chmod -R 775 /var/run/asterisk

# Start services
echo "Starting services..."
systemctl daemon-reload
systemctl enable paging-web asterisk
systemctl start paging-web asterisk

# Wait for app to start
echo "Waiting for application to initialize..."
sleep 5

# Restart Nginx to ensure proper connection
systemctl restart nginx

# Get IP address
IP_ADDRESS=$(hostname -I | awk '{print $1}')

# Final instructions
echo ""
echo "====================================================="
echo "Installation complete!"
echo "System architecture: $ARCH"
echo "Access the web interface at: http://$IP_ADDRESS"
echo ""
echo "Default credentials:"
echo "  Username: admin"
echo "  Password: admin"
echo ""
echo "Installation log: $LOG_FILE"
echo "====================================================="

# Verification steps
echo "Running verification checks..."
echo "1. Service status:"
systemctl status paging-web asterisk --no-pager | head -10

echo -e "\n2. Port check:"
echo "Port 80:"
netstat -tulpn | grep ':80' || echo "Not found!"
echo -e "\nPort 8080:"
netstat -tulpn | grep ':8080' || echo "Not found!"

echo -e "\n3. Application test:"
curl -I http://localhost || echo "Local access failed!"
curl -s http://localhost:8080 >/dev/null && echo "Flask app is running on port 8080"

echo -e "\n4. Log files:"
echo "Application logs:"
tail -n 5 $LOG_DIR/app.log 2>/dev/null || echo "No application logs found"
echo -e "\nNginx error logs:"
tail -n 5 $LOG_DIR/nginx-error.log 2>/dev/null || echo "No Nginx error logs found"

echo -e "\n5. Database status:"
sqlite3 $DB_DIR/paging_config.db "SELECT name FROM sqlite_master WHERE type='table';" || echo "Database not found"

echo -e "\nSystem is ready for configuration!"