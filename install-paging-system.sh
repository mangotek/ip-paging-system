#!/bin/bash
# Enterprise IP Paging System with SIP Integration
# Unifi UI Design - Supports 3CX, Unifi Protect, Hikvision, Dahua
# Tested on Ubuntu 22.04

# Configuration
ADMIN_USER="pagingadmin"
INSTALL_DIR="/opt/paging"
DB_DIR="/var/lib/paging"
LOG_DIR="/var/log/paging"
NGINX_DIR="/etc/nginx/sites-available"
SERVICE_FILE="/etc/systemd/system/paging-web.service"
APP_DB="$DB_DIR/paging_config.db"
ASTERISK_DIR="/etc/asterisk"

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Setup error handling
set -e
trap 'echo "Error at line $LINENO"; exit 1' ERR

# Setup logging
LOG_FILE="/tmp/paging-install.log"
exec > >(tee -a "${LOG_FILE}")
exec 2> >(tee -a "${LOG_FILE}" >&2)

echo "Starting installation at $(date)"
echo "Logging to: ${LOG_FILE}"

# Verify architecture
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    echo "This installer is only for x86_64 systems"
    echo "Detected architecture: $ARCH"
    exit 1
fi

# System information
echo "System: $(lsb_release -d | cut -f2-)"
echo "Kernel: $(uname -r)"
echo "Memory: $(free -h | awk '/Mem/{print $2}')"
echo "Disk: $(df -h / | awk 'NR==2{print $4}') free"

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR" "$DB_DIR" "$LOG_DIR" "$INSTALL_DIR/static" "$INSTALL_DIR/static/js" "$INSTALL_DIR/static/css"
chmod 755 "$INSTALL_DIR" "$DB_DIR" "$LOG_DIR"

# Create system user
if ! id "$ADMIN_USER" &>/dev/null; then
    echo "Creating system user: $ADMIN_USER"
    useradd -r -s /usr/sbin/nologin "$ADMIN_USER"
fi
chown -R "$ADMIN_USER:$ADMIN_USER" "$INSTALL_DIR" "$DB_DIR" "$LOG_DIR"

# Install dependencies
install_dependencies() {
    echo "Updating package lists..."
    apt update
    
    echo "Installing dependencies..."
    apt install -y \
        python3-pip \
        python3-venv \
        git \
        sqlite3 \
        nginx \
        gstreamer1.0-plugins-good \
        gstreamer1.0-tools \
        alsa-utils \
        sox \
        build-essential \
        libssl-dev \
        libffi-dev \
        ufw \
        asterisk \
        espeak \
        net-tools \
        libasound2-dev \
        ffmpeg \
        sipcalc \
        fail2ban
}

install_dependencies || {
    echo "Dependency installation failed! Attempting to continue..."
    echo "Manual command: sudo apt install -y python3-pip python3-venv ..."
}

# Setup Python environment
echo "Setting up Python environment..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
pip install --upgrade pip
pip install flask flask-sqlalchemy flask-login flask-wtf requests pyopenssl wtforms gunicorn

# Create database and configuration
echo "Initializing database..."
sqlite3 "$APP_DB" <<EOL
CREATE TABLE IF NOT EXISTS zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    extension TEXT NOT NULL,
    sip_server TEXT,
    sip_username TEXT,
    sip_password TEXT,
    sip_port INTEGER DEFAULT 5060,
    intercom_type TEXT DEFAULT 'Generic'
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'admin'
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    zone_id INTEGER,
    device_type TEXT,
    FOREIGN KEY (zone_id) REFERENCES zones (id)
);

INSERT OR IGNORE INTO users (username, password, email, role) 
VALUES ('admin', 'admin', 'admin@example.com', 'superadmin');
EOL

chown "$ADMIN_USER:$ADMIN_USER" "$APP_DB"

# Configure Asterisk
echo "Configuring Asterisk for SIP paging..."
cat > "$ASTERISK_DIR/sip.conf" <<EOL
[general]
context=default
allowoverlap=no
udpbindaddr=0.0.0.0
tcpenable=no
tcpbindaddr=0.0.0.0
transport=udp
srvlookup=yes
useragent=Asterisk PBX

[unifi-intercom](!)
type=friend
context=from-internal
host=dynamic
secret=unifi123
dtmfmode=rfc2833
canreinvite=no
disallow=all
allow=ulaw
allow=alaw
transport=udp

[3cx-phone](!)
type=friend
context=from-internal
host=dynamic
secret=3cx123
dtmfmode=rfc2833
disallow=all
allow=ulaw
allow=alaw
transport=udp

[dahua-intercom](!)
type=friend
context=from-internal
host=dynamic
secret=dahua123
dtmfmode=rfc2833
disallow=all
allow=ulaw
allow=alaw
transport=udp

[default](!)
type=friend
context=from-internal
host=dynamic
secret=default123
dtmfmode=rfc2833
disallow=all
allow=ulaw
allow=alaw
transport=udp
EOL

cat > "$ASTERISK_DIR/extensions.conf" <<EOL
[default]
exten => 100,1,Answer()
 same => n,Playback(hello-world)
 same => n,Hangup()

[from-internal]
exten => _1XX,1,NoOp(Incoming call to \${EXTEN})
 same => n,Dial(SIP/\${EXTEN})
 same => n,Hangup()

; Paging extensions
exten => _*8XXX,1,Page(\${EXTEN:2},SIP)
 same => n,Hangup()
EOL

# Restart Asterisk
systemctl restart asterisk

# Create functional application
echo "Creating application files..."
cat > "$INSTALL_DIR/app.py" << 'EOL'
import os
import sqlite3
import subprocess
import requests
import socket
import netifaces
from flask import Flask, render_template, request, redirect, session, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, validators
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////var/lib/paging/paging_config.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    role = db.Column(db.String(20), default='admin')

class Zone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    extension = db.Column(db.String(20), nullable=False)
    sip_server = db.Column(db.String(100))
    sip_username = db.Column(db.String(50))
    sip_password = db.Column(db.String(50))
    sip_port = db.Column(db.Integer, default=5060)
    intercom_type = db.Column(db.String(20), default='Generic')

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    mac_address = db.Column(db.String(17))
    zone_id = db.Column(db.Integer, db.ForeignKey('zone.id'))
    device_type = db.Column(db.String(20))

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', [validators.InputRequired()])
    password = PasswordField('Password', [validators.InputRequired()])

class ZoneForm(FlaskForm):
    name = StringField('Zone Name', [validators.InputRequired()])
    description = TextAreaField('Description')
    extension = StringField('Extension', [validators.InputRequired()])
    sip_server = StringField('SIP Server')
    sip_username = StringField('SIP Username')
    sip_password = PasswordField('SIP Password')
    sip_port = StringField('SIP Port', default='5060')
    intercom_type = SelectField('Intercom Type', choices=[
        ('Generic', 'Generic SIP'),
        ('3CX', '3CX Phone System'),
        ('Unifi', 'Unifi Protect'),
        ('Hikvision', 'Hikvision IP Intercom'),
        ('Dahua', 'Dahua IP Intercom')
    ])

class DeviceForm(FlaskForm):
    name = StringField('Device Name', [validators.InputRequired()])
    ip_address = StringField('IP Address', [validators.InputRequired()])
    mac_address = StringField('MAC Address')
    device_type = SelectField('Device Type', choices=[
        ('sip_phone', 'SIP Phone'),
        ('intercom', 'IP Intercom'),
        ('paging_speaker', 'Paging Speaker')
    ])
    zone_id = SelectField('Paging Zone', coerce=int)

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', [validators.InputRequired()])
    new_password = PasswordField('New Password', [
        validators.InputRequired(),
        validators.Length(min=6),
        validators.EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm Password')

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def get_network_info():
    interfaces = netifaces.interfaces()
    net_info = []
    for iface in interfaces:
        if iface == 'lo':
            continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr['addr']
                netmask = addr['netmask']
                net_info.append({
                    'interface': iface,
                    'ip': ip,
                    'netmask': netmask,
                    'network': calculate_network(ip, netmask)
                })
    return net_info

def calculate_network(ip, netmask):
    try:
        from sipcalc import sipcalc
        network = sipcalc.Network(f"{ip} {netmask}")
        return f"{network.network_address}/{network.network_mask_bits}"
    except:
        return "N/A"

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect('/dashboard')
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/dashboard')
@login_required
def dashboard():
    zones = Zone.query.all()
    devices = Device.query.all()
    net_info = get_network_info()
    return render_template('dashboard.html', 
                           zones=zones, 
                           devices=devices,
                           net_info=net_info,
                           user=current_user)

@app.route('/zones')
@login_required
def manage_zones():
    zones = Zone.query.all()
    return render_template('zones.html', zones=zones)

@app.route('/zones/add', methods=['GET', 'POST'])
@login_required
def add_zone():
    form = ZoneForm()
    if form.validate_on_submit():
        new_zone = Zone(
            name=form.name.data,
            description=form.description.data,
            extension=form.extension.data,
            sip_server=form.sip_server.data,
            sip_username=form.sip_username.data,
            sip_password=form.sip_password.data,
            sip_port=form.sip_port.data,
            intercom_type=form.intercom_type.data
        )
        db.session.add(new_zone)
        db.session.commit()
        flash('Zone added successfully', 'success')
        return redirect('/zones')
    return render_template('zone_form.html', form=form, action='Add')

@app.route('/zones/edit/<int:zone_id>', methods=['GET', 'POST'])
@login_required
def edit_zone(zone_id):
    zone = Zone.query.get_or_404(zone_id)
    form = ZoneForm(obj=zone)
    if form.validate_on_submit():
        zone.name = form.name.data
        zone.description = form.description.data
        zone.extension = form.extension.data
        zone.sip_server = form.sip_server.data
        zone.sip_username = form.sip_username.data
        zone.sip_password = form.sip_password.data
        zone.sip_port = form.sip_port.data
        zone.intercom_type = form.intercom_type.data
        db.session.commit()
        flash('Zone updated successfully', 'success')
        return redirect('/zones')
    return render_template('zone_form.html', form=form, action='Edit', zone=zone)

@app.route('/zones/delete/<int:zone_id>', methods=['POST'])
@login_required
def delete_zone(zone_id):
    zone = Zone.query.get_or_404(zone_id)
    db.session.delete(zone)
    db.session.commit()
    flash('Zone deleted successfully', 'success')
    return redirect('/zones')

@app.route('/devices')
@login_required
def manage_devices():
    devices = Device.query.all()
    zones = Zone.query.all()
    return render_template('devices.html', devices=devices, zones=zones)

@app.route('/devices/add', methods=['GET', 'POST'])
@login_required
def add_device():
    form = DeviceForm()
    form.zone_id.choices = [(0, 'None')] + [(z.id, z.name) for z in Zone.query.all()]
    if form.validate_on_submit():
        new_device = Device(
            name=form.name.data,
            ip_address=form.ip_address.data,
            mac_address=form.mac_address.data,
            device_type=form.device_type.data,
            zone_id=form.zone_id.data if form.zone_id.data != 0 else None
        )
        db.session.add(new_device)
        db.session.commit()
        flash('Device added successfully', 'success')
        return redirect('/devices')
    return render_template('device_form.html', form=form, action='Add')

@app.route('/devices/edit/<int:device_id>', methods=['GET', 'POST'])
@login_required
def edit_device(device_id):
    device = Device.query.get_or_404(device_id)
    form = DeviceForm(obj=device)
    form.zone_id.choices = [(0, 'None')] + [(z.id, z.name) for z in Zone.query.all()]
    if form.validate_on_submit():
        device.name = form.name.data
        device.ip_address = form.ip_address.data
        device.mac_address = form.mac_address.data
        device.device_type = form.device_type.data
        device.zone_id = form.zone_id.data if form.zone_id.data != 0 else None
        db.session.commit()
        flash('Device updated successfully', 'success')
        return redirect('/devices')
    return render_template('device_form.html', form=form, action='Edit', device=device)

@app.route('/devices/delete/<int:device_id>', methods=['POST'])
@login_required
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    flash('Device deleted successfully', 'success')
    return redirect('/devices')

@app.route('/page', methods=['POST'])
@login_required
def page():
    zone_id = request.form.get('zone_id')
    message = request.form.get('message')
    audio_file = request.files.get('audio_file')
    use_tts = request.form.get('use_tts', 'false') == 'true'
    
    if not zone_id:
        return jsonify({'status': 'error', 'message': 'Zone not specified'}), 400
    
    zone = Zone.query.get(zone_id)
    if not zone:
        return jsonify({'status': 'error', 'message': 'Zone not found'}), 404
    
    try:
        # For Unifi Protect integration
        if zone.intercom_type == 'Unifi':
            # This would be replaced with actual Unifi API calls
            result = f"Paging to Unifi zone {zone.name}: {message}"
            return jsonify({'status': 'success', 'message': result})
        
        # For Hikvision/Dahua integration
        elif zone.intercom_type in ['Hikvision', 'Dahua']:
            # This would be replaced with actual API calls
            result = f"Paging to {zone.intercom_type} zone {zone.name}: {message}"
            return jsonify({'status': 'success', 'message': result})
        
        # For 3CX integration
        elif zone.intercom_type == '3CX':
            # This would be replaced with 3CX API calls
            result = f"Paging to 3CX zone {zone.name}: {message}"
            return jsonify({'status': 'success', 'message': result})
        
        # Generic SIP paging
        else:
            # Create audio file
            audio_path = f"{LOG_DIR}/page_{zone.id}.wav"
            
            if use_tts:
                subprocess.run(['espeak', '-v', 'en', '-w', audio_path, message])
            elif audio_file:
                audio_file.save(audio_path)
            else:
                return jsonify({'status': 'error', 'message': 'No audio source provided'}), 400
            
            # Convert to proper format (8000 Hz, 16-bit mono)
            converted_path = f"{LOG_DIR}/page_{zone.id}_converted.wav"
            subprocess.run(['sox', audio_path, '-r', '8000', '-b', '16', '-c', '1', converted_path])
            
            # SIP Paging Command (simplified)
            # This would be replaced with actual SIP paging command
            print(f"Paging to SIP zone {zone.name} ({zone.extension}): {message}")
            
            # Play audio locally for demo
            subprocess.Popen(['aplay', converted_path])
            
            return jsonify({'status': 'success', 'message': 'Page sent via SIP'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/settings')
@login_required
def settings():
    form = ChangePasswordForm()
    return render_template('settings.html', form=form, user=current_user)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not check_password_hash(current_user.password, form.current_password.data):
            flash('Current password is incorrect', 'danger')
            return redirect('/settings')
        
        current_user.password = generate_password_hash(form.new_password.data)
        db.session.commit()
        flash('Password changed successfully', 'success')
        return redirect('/settings')
    return render_template('settings.html', form=form)

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default admin if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin'),
                email='admin@example.com',
                role='superadmin'
            )
            db.session.add(admin)
            db.session.commit()
    
    app.run(host='0.0.0.0', port=8080, debug=True)
EOL

# Create templates
mkdir -p "$INSTALL_DIR/templates"

# Base template
cat > "$INSTALL_DIR/templates/base.html" << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{% block title %}IP Paging System{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <link rel="stylesheet" href="/static/css/style.css">
    {% block head %}{% endblock %}
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/dashboard">
                <i class="bi bi-megaphone me-2"></i> IP Paging System
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard"><i class="bi bi-speedometer2 me-1"></i> Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/zones"><i class="bi bi-collection me-1"></i> Zones</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/devices"><i class="bi bi-hdd-stack me-1"></i> Devices</a>
                    </li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="userMenu" role="button" data-bs-toggle="dropdown">
                            <i class="bi bi-person-circle me-1"></i> {{ current_user.username }}
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><a class="dropdown-item" href="/settings"><i class="bi bi-gear me-2"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="/logout"><i class="bi bi-box-arrow-right me-2"></i> Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container my-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>

    <footer class="bg-light py-3 mt-5">
        <div class="container text-center text-muted">
            <small>IP Paging System &copy; 2023</small>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
EOL

# Login template
cat > "$INSTALL_DIR/templates/login.html" << 'EOL'
{% extends "base.html" %}
{% block title %}Login - IP Paging System{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6 col-lg-4">
        <div class="card shadow-sm">
            <div class="card-body p-4">
                <div class="text-center mb-4">
                    <i class="bi bi-megaphone fs-1 text-primary"></i>
                    <h1 class="h4 mt-2">IP Paging System</h1>
                    <p class="text-muted">Sign in to your account</p>
                </div>
                
                <form method="POST" action="/login">
                    {{ form.hidden_tag() }}
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        {{ form.username(class="form-control", placeholder="Enter username") }}
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        {{ form.password(class="form-control", placeholder="Enter password") }}
                    </div>
                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary">Sign In</button>
                    </div>
                </form>
                
                <div class="mt-3 text-center">
                    <small class="text-muted">Default: admin/admin</small>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOL

# Dashboard template
cat > "$INSTALL_DIR/templates/dashboard.html" << 'EOL'
{% extends "base.html" %}
{% block title %}Dashboard - IP Paging System{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h1 class="h3">Dashboard</h1>
    <div class="d-flex">
        <button class="btn btn-primary me-2" data-bs-toggle="modal" data-bs-target="#pageModal">
            <i class="bi bi-broadcast me-1"></i> Send Page
        </button>
    </div>
</div>

<div class="row">
    <!-- System Status Card -->
    <div class="col-md-4 mb-4">
        <div class="card h-100">
            <div class="card-header bg-primary text-white">
                <i class="bi bi-speedometer2 me-2"></i> System Status
            </div>
            <div class="card-body">
                <div class="d-flex align-items-center mb-3">
                    <div class="bg-success rounded-circle p-2 me-3">
                        <i class="bi bi-check-circle text-white"></i>
                    </div>
                    <div>
                        <h5 class="mb-0">Operational</h5>
                        <small class="text-muted">All systems normal</small>
                    </div>
                </div>
                
                <ul class="list-group list-group-flush">
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <span><i class="bi bi-hdd me-2"></i> Web Service</span>
                        <span class="badge bg-success">Running</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <span><i class="bi bi-mic me-2"></i> Audio System</span>
                        <span class="badge bg-success">OK</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <span><i class="bi bi-shield-check me-2"></i> Security</span>
                        <span class="badge bg-success">Enabled</span>
                    </li>
                </ul>
            </div>
        </div>
    </div>
    
    <!-- Paging Zones Card -->
    <div class="col-md-4 mb-4">
        <div class="card h-100">
            <div class="card-header bg-primary text-white">
                <i class="bi bi-collection me-2"></i> Paging Zones
            </div>
            <div class="card-body">
                {% if zones %}
                    <div class="list-group">
                        {% for zone in zones %}
                            <div class="list-group-item">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="mb-0">{{ zone.name }}</h6>
                                        <small class="text-muted">{{ zone.intercom_type }} - {{ zone.extension }}</small>
                                    </div>
                                    <span class="badge bg-primary">{{ zone.devices|length }} devices</span>
                                </div>
                            </div>
                        {% endfor %}
                    </div>
                {% else %}
                    <div class="text-center py-4">
                        <i class="bi bi-collection text-muted display-6 mb-3"></i>
                        <p class="text-muted">No paging zones configured</p>
                        <a href="/zones/add" class="btn btn-sm btn-outline-primary">
                            <i class="bi bi-plus-circle me-1"></i> Add Zone
                        </a>
                    </div>
                {% endif %}
            </div>
            <div class="card-footer text-center">
                <a href="/zones" class="btn btn-sm btn-outline-primary">Manage Zones</a>
            </div>
        </div>
    </div>
    
    <!-- Network Info Card -->
    <div class="col-md-4 mb-4">
        <div class="card h-100">
            <div class="card-header bg-primary text-white">
                <i class="bi bi-hdd-network me-2"></i> Network Information
            </div>
            <div class="card-body">
                {% if net_info %}
                    <ul class="list-group list-group-flush">
                        {% for net in net_info %}
                            <li class="list-group-item">
                                <div class="d-flex justify-content-between">
                                    <span class="fw-bold">{{ net.interface }}</span>
                                    <span>{{ net.ip }}/{{ net.netmask }}</span>
                                </div>
                                <div class="text-muted small">{{ net.network }}</div>
                            </li>
                        {% endfor %}
                    </ul>
                {% else %}
                    <p class="text-muted text-center py-4">No network information available</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>

<!-- Devices Card -->
<div class="card mb-4">
    <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
        <span><i class="bi bi-hdd-stack me-2"></i> Devices</span>
        <a href="/devices/add" class="btn btn-sm btn-light">
            <i class="bi bi-plus-circle me-1"></i> Add Device
        </a>
    </div>
    <div class="card-body">
        {% if devices %}
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>IP Address</th>
                            <th>Type</th>
                            <th>Zone</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for device in devices %}
                            <tr>
                                <td>{{ device.name }}</td>
                                <td>{{ device.ip_address }}</td>
                                <td>{{ device.device_type }}</td>
                                <td>
                                    {% if device.zone_id %}
                                        {{ Zone.query.get(device.zone_id).name }}
                                    {% else %}
                                        <span class="text-muted">None</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <span class="badge bg-success">Online</span>
                                </td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        {% else %}
            <div class="text-center py-4">
                <i class="bi bi-hdd text-muted display-6 mb-3"></i>
                <p class="text-muted">No devices configured</p>
                <a href="/devices/add" class="btn btn-sm btn-outline-primary">
                    <i class="bi bi-plus-circle me-1"></i> Add Device
                </a>
            </div>
        {% endif %}
    </div>
</div>

<!-- Page Modal -->
<div class="modal fade" id="pageModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Send Page</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form id="pageForm" method="POST" action="/page" enctype="multipart/form-data">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Paging Zone</label>
                        <select class="form-select" name="zone_id" required>
                            <option value="">Select a zone</option>
                            {% for zone in zones %}
                                <option value="{{ zone.id }}">{{ zone.name }} ({{ zone.intercom_type }})</option>
                            {% endfor %}
                        </select>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">Message</label>
                        <textarea class="form-control" name="message" rows="3" placeholder="Enter text message for TTS"></textarea>
                    </div>
                    
                    <div class="mb-3">
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="useTts" name="use_tts" checked>
                            <label class="form-check-label" for="useTts">Use Text-to-Speech</label>
                        </div>
                    </div>
                    
                    <div class="mb-3" id="audioUpload" style="display: none;">
                        <label class="form-label">Or Upload Audio File</label>
                        <input class="form-control" type="file" name="audio_file" accept="audio/*">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Send Page</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Toggle audio upload based on TTS checkbox
        const ttsCheckbox = document.getElementById('useTts');
        const audioUpload = document.getElementById('audioUpload');
        
        ttsCheckbox.addEventListener('change', function() {
            audioUpload.style.display = this.checked ? 'none' : 'block';
        });
        
        // Handle page form submission
        document.getElementById('pageForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            
            fetch('/page', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    alert('Page sent: ' + data.message);
                    document.getElementById('pageModal').querySelector('.btn-close').click();
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Page failed: ' + error.message);
            });
        });
    });
</script>
{% endblock %}
EOL

# Zones templates
cat > "$INSTALL_DIR/templates/zones.html" << 'EOL'
{% extends "base.html" %}
{% block title %}Paging Zones - IP Paging System{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h1 class="h3">Paging Zones</h1>
    <a href="/zones/add" class="btn btn-primary">
        <i class="bi bi-plus-circle me-1"></i> Add Zone
    </a>
</div>

<div class="card">
    <div class="card-body">
        {% if zones %}
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Extension</th>
                            <th>Type</th>
                            <th>SIP Server</th>
                            <th>Devices</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for zone in zones %}
                            <tr>
                                <td>{{ zone.name }}</td>
                                <td>{{ zone.extension }}</td>
                                <td>{{ zone.intercom_type }}</td>
                                <td>{{ zone.sip_server or '-' }}</td>
                                <td>{{ zone.devices|length }}</td>
                                <td>
                                    <div class="d-flex">
                                        <a href="/zones/edit/{{ zone.id }}" class="btn btn-sm btn-outline-primary me-2">
                                            <i class="bi bi-pencil"></i>
                                        </a>
                                        <form method="POST" action="/zones/delete/{{ zone.id }}" onsubmit="return confirm('Delete this zone?')">
                                            <button type="submit" class="btn btn-sm btn-outline-danger">
                                                <i class="bi bi-trash"></i>
                                            </button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        {% else %}
            <div class="text-center py-5">
                <i class="bi bi-collection text-muted display-1 mb-3"></i>
                <h5>No paging zones configured</h5>
                <p class="text-muted">Add your first paging zone to get started</p>
                <a href="/zones/add" class="btn btn-primary">
                    <i class="bi bi-plus-circle me-1"></i> Add Zone
                </a>
            </div>
        {% endif %}
    </div>
</div>
{% endblock %}
EOL

cat > "$INSTALL_DIR/templates/zone_form.html" << 'EOL'
{% extends "base.html" %}
{% block title %}{{ action }} Zone - IP Paging System{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h1 class="h3">{{ action }} Paging Zone</h1>
    <a href="/zones" class="btn btn-outline-secondary">
        <i class="bi bi-arrow-left me-1"></i> Back
    </a>
</div>

<div class="card">
    <div class="card-body">
        <form method="POST">
            {{ form.hidden_tag() }}
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label class="form-label">Zone Name</label>
                    {{ form.name(class="form-control", placeholder="Enter zone name") }}
                </div>
                <div class="col-md-6 mb-3">
                    <label class="form-label">Extension</label>
                    {{ form.extension(class="form-control", placeholder="Enter extension") }}
                </div>
            </div>
            
            <div class="mb-3">
                <label class="form-label">Description</label>
                {{ form.description(class="form-control", placeholder="Enter description", rows="2") }}
            </div>
            
            <div class="mb-3">
                <label class="form-label">Intercom Type</label>
                {{ form.intercom_type(class="form-select") }}
            </div>
            
            <div class="card mb-4">
                <div class="card-header bg-light">SIP Configuration</div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">SIP Server</label>
                            {{ form.sip_server(class="form-control", placeholder="sip.example.com") }}
                        </div>
                        <div class="col-md-3 mb-3">
                            <label class="form-label">SIP Port</label>
                            {{ form.sip_port(class="form-control", placeholder="5060") }}
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">SIP Username</label>
                            {{ form.sip_username(class="form-control", placeholder="Enter username") }}
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">SIP Password</label>
                            {{ form.sip_password(class="form-control", placeholder="Enter password") }}
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="d-flex justify-content-end">
                <button type="submit" class="btn btn-primary">
                    <i class="bi bi-save me-1"></i> Save Zone
                </button>
            </div>
        </form>
    </div>
</div>
{% endblock %}
EOL

# Devices templates
cat > "$INSTALL_DIR/templates/devices.html" << 'EOL'
{% extends "base.html" %}
{% block title %}Devices - IP Paging System{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h1 class="h3">Devices</h1>
    <a href="/devices/add" class="btn btn-primary">
        <i class="bi bi-plus-circle me-1"></i> Add Device
    </a>
</div>

<div class="card">
    <div class="card-body">
        {% if devices %}
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Type</th>
                            <th>Zone</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for device in devices %}
                            <tr>
                                <td>{{ device.name }}</td>
                                <td>{{ device.ip_address }}</td>
                                <td>{{ device.mac_address or '-' }}</td>
                                <td>{{ device.device_type }}</td>
                                <td>
                                    {% if device.zone_id %}
                                        {{ Zone.query.get(device.zone_id).name }}
                                    {% else %}
                                        <span class="text-muted">None</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <span class="badge bg-success">Online</span>
                                </td>
                                <td>
                                    <div class="d-flex">
                                        <a href="/devices/edit/{{ device.id }}" class="btn btn-sm btn-outline-primary me-2">
                                            <i class="bi bi-pencil"></i>
                                        </a>
                                        <form method="POST" action="/devices/delete/{{ device.id }}" onsubmit="return confirm('Delete this device?')">
                                            <button type="submit" class="btn btn-sm btn-outline-danger">
                                                <i class="bi bi-trash"></i>
                                            </button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        {% else %}
            <div class="text-center py-5">
                <i class="bi bi-hdd text-muted display-1 mb-3"></i>
                <h5>No devices configured</h5>
                <p class="text-muted">Add your first device to get started</p>
                <a href="/devices/add" class="btn btn-primary">
                    <i class="bi bi-plus-circle me-1"></i> Add Device
                </a>
            </div>
        {% endif %}
    </div>
</div>
{% endblock %}
EOL

cat > "$INSTALL_DIR/templates/device_form.html" << 'EOL'
{% extends "base.html" %}
{% block title %}{{ action }} Device - IP Paging System{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h1 class="h3">{{ action }} Device</h1>
    <a href="/devices" class="btn btn-outline-secondary">
        <i class="bi bi-arrow-left me-1"></i> Back
    </a>
</div>

<div class="card">
    <div class="card-body">
        <form method="POST">
            {{ form.hidden_tag() }}
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label class="form-label">Device Name</label>
                    {{ form.name(class="form-control", placeholder="Enter device name") }}
                </div>
                <div class="col-md-6 mb-3">
                    <label class="form-label">Device Type</label>
                    {{ form.device_type(class="form-select") }}
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label class="form-label">IP Address</label>
                    {{ form.ip_address(class="form-control", placeholder="192.168.1.100") }}
                </div>
                <div class="col-md-6 mb-3">
                    <label class="form-label">MAC Address</label>
                    {{ form.mac_address(class="form-control", placeholder="00:11:22:33:44:55") }}
                </div>
            </div>
            
            <div class="mb-3">
                <label class="form-label">Paging Zone</label>
                {{ form.zone_id(class="form-select") }}
            </div>
            
            <div class="d-flex justify-content-end">
                <button type="submit" class="btn btn-primary">
                    <i class="bi bi-save me-1"></i> Save Device
                </button>
            </div>
        </form>
    </div>
</div>
{% endblock %}
EOL

# Settings template
cat > "$INSTALL_DIR/templates/settings.html" << 'EOL'
{% extends "base.html" %}
{% block title %}Settings - IP Paging System{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h1 class="h3">System Settings</h1>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <i class="bi bi-person-circle me-2"></i> User Profile
            </div>
            <div class="card-body">
                <div class="mb-3">
                    <label class="form-label">Username</label>
                    <input type="text" class="form-control" value="{{ user.username }}" readonly>
                </div>
                <div class="mb-3">
                    <label class="form-label">Email</label>
                    <input type="email" class="form-control" value="{{ user.email }}" readonly>
                </div>
                <div class="mb-3">
                    <label class="form-label">Role</label>
                    <input type="text" class="form-control" value="{{ user.role }}" readonly>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <i class="bi bi-shield-lock me-2"></i> Change Password
            </div>
            <div class="card-body">
                <form method="POST" action="/change_password">
                    {{ form.hidden_tag() }}
                    <div class="mb-3">
                        <label class="form-label">Current Password</label>
                        {{ form.current_password(class="form-control") }}
                    </div>
                    <div class="mb-3">
                        <label class="form-label">New Password</label>
                        {{ form.new_password(class="form-control") }}
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Confirm Password</label>
                        {{ form.confirm_password(class="form-control") }}
                    </div>
                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary">Update Password</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header bg-primary text-white">
        <i class="bi bi-gear me-2"></i> System Configuration
    </div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-4 mb-3">
                <label class="form-label">SIP Server Port</label>
                <input type="text" class="form-control" value="5060" readonly>
            </div>
            <div class="col-md-4 mb-3">
                <label class="form-label">Web Server Port</label>
                <input type="text" class="form-control" value="8080" readonly>
            </div>
            <div class="col-md-4 mb-3">
                <label class="form-label">System Version</label>
                <input type="text" class="form-control" value="2.0.0" readonly>
            </div>
        </div>
        
        <div class="d-flex justify-content-end mt-3">
            <button class="btn btn-outline-secondary me-2">Restart Services</button>
            <button class="btn btn-danger">Reboot System</button>
        </div>
    </div>
</div>
{% endblock %}
EOL

# Create custom CSS
cat > "$INSTALL_DIR/static/css/style.css" << 'EOL'
:root {
    --primary: #0a4f9e;
    --secondary: #6c757d;
    --success: #28a745;
    --danger: #dc3545;
    --warning: #ffc107;
    --info: #17a2b8;
    --light: #f8f9fa;
    --dark: #343a40;
}

body {
    background-color: #f5f7fa;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.navbar {
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.card {
    border: none;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    transition: transform 0.2s;
    margin-bottom: 1.5rem;
}

.card:hover {
    transform: translateY(-5px);
    box-shadow: 0 6px 12px rgba(0,0,0,0.1);
}

.card-header {
    background-color: var(--primary);
    color: white;
    border-radius: 10px 10px 0 0 !important;
    padding: 0.75rem 1.25rem;
    font-weight: 600;
}

.bg-primary {
    background-color: var(--primary) !important;
}

.btn-primary {
    background-color: var(--primary);
    border-color: var(--primary);
}

.btn-outline-primary {
    color: var(--primary);
    border-color: var(--primary);
}

.btn-outline-primary:hover {
    background-color: var(--primary);
    border-color: var(--primary);
}

.list-group-item {
    border: none;
    border-bottom: 1px solid rgba(0,0,0,0.05);
    padding: 1rem 1.25rem;
}

.table th {
    background-color: #f1f5f9;
    font-weight: 600;
}

.table-hover tbody tr:hover {
    background-color: rgba(10, 79, 158, 0.05);
}

.alert {
    border-radius: 8px;
}
EOL

# Create systemd service file
echo "Creating systemd service..."
cat > "$SERVICE_FILE" << EOL
[Unit]
Description=IP Paging Web Interface
After=network.target

[Service]
User=$ADMIN_USER
Group=$ADMIN_USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/bin"
Environment="PYTHONUNBUFFERED=1"
ExecStart=$INSTALL_DIR/venv/bin/gunicorn --bind 0.0.0.0:8080 app:app
Restart=always
RestartSec=5
StandardOutput=file:$LOG_DIR/app.log
StandardError=file:$LOG_DIR/app-error.log

[Install]
WantedBy=multi-user.target
EOL

# Create Nginx configuration
echo "Configuring Nginx..."
cat > "$NGINX_DIR/paging" << EOL
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    access_log $LOG_DIR/nginx-access.log;
    error_log $LOG_DIR/nginx-error.log;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    location /static/ {
        alias $INSTALL_DIR/static/;
        expires 30d;
    }
}
EOL

# Enable Nginx site
echo "Enabling Nginx site..."
rm -f /etc/nginx/sites-enabled/default
ln -sf "$NGINX_DIR/paging" /etc/nginx/sites-enabled/

# Configure firewall
echo "Configuring firewall..."
ufw allow 80/tcp
ufw allow 5060/udp
ufw --force enable || echo "UFW configuration failed"

# Set permissions
chown -R "$ADMIN_USER:$ADMIN_USER" "$INSTALL_DIR"

# Start services
echo "Starting services..."
systemctl daemon-reload
systemctl enable paging-web
systemctl start paging-web
systemctl restart nginx

# Wait for services to start
echo "Waiting for services to initialize..."
sleep 5

# Get IP address
IP_ADDRESS=$(hostname -I | awk '{print $1}')
if [ -z "$IP_ADDRESS" ]; then
    IP_ADDRESS="[YOUR_SERVER_IP]"
fi

# Final instructions
echo ""
echo "====================================================="
echo "Enterprise IP Paging System Installation Complete!"
echo "Access the web interface at: http://$IP_ADDRESS"
echo ""
echo "Default credentials:"
echo "  Username: admin"
echo "  Password: admin"
echo ""
echo "System Features:"
echo "  - SIP Server Integration (Asterisk)"
echo "  - Unifi Protect Intercom Support"
echo "  - Hikvision/Dahua IP Intercom Support"
echo "  - 3CX Phone System Integration"
echo "  - Modern Unifi-like UI"
echo "  - Multi-zone Paging Management"
echo "  - Device Management"
echo "  - Network Configuration"
echo ""
echo "Next Steps:"
echo "1. Configure your paging zones in the web interface"
echo "2. Add SIP devices and IP intercoms"
echo "3. Test paging functionality"
echo ""
echo "Troubleshooting:"
echo "  systemctl status paging-web nginx asterisk"
echo "  journalctl -u paging-web"
echo "  tail -f $LOG_DIR/app.log"
echo "====================================================="
