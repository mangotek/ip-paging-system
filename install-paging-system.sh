#!/bin/bash
# Enhanced IP Paging System Installer with Password Change and Improved SIP Compatibility
# Tested on Ubuntu 22.04 (x86)

# Configuration
ADMIN_USER="pagingadmin"
INSTALL_DIR="/opt/paging"
DB_DIR="/var/lib/paging"
LOG_DIR="/var/log/paging"
NGINX_DIR="/etc/nginx/sites-available"
NGINX_ENABLED_DIR="/etc/nginx/sites-enabled"
SERVICE_FILE="/etc/systemd/system/paging-web.service"
AUDIO_TEST_FILE="$INSTALL_DIR/static/test_message.wav"
DB_FILE="$DB_DIR/paging.db"

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

echo "Starting x86 installation at $(date)"
echo "System architecture: $ARCH"

# Install essential tools
apt update
apt install -y net-tools curl

# Create directories
echo "Creating directories..."
mkdir -p $INSTALL_DIR $DB_DIR $LOG_DIR $INSTALL_DIR/static $INSTALL_DIR/templates
chmod 755 $INSTALL_DIR $DB_DIR $LOG_DIR $INSTALL_DIR/static
mkdir -p $NGINX_DIR $NGINX_ENABLED_DIR

# Create system user
if ! id "$ADMIN_USER" &>/dev/null; then
    echo "Creating system user: $ADMIN_USER"
    useradd -r -s /usr/sbin/nologin $ADMIN_USER
fi
chown -R $ADMIN_USER:$ADMIN_USER $INSTALL_DIR $DB_DIR $LOG_DIR

# Install dependencies
echo "Installing dependencies..."
apt install -y python3-pip python3-venv git sqlite3 nginx \
    gstreamer1.0-plugins-good gstreamer1.0-tools alsa-utils sox \
    build-essential libssl-dev libffi-dev ufw asterisk espeak netcat

# Install Python dependencies
echo "Setting up Python environment..."
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate
pip install flask werkzeug configparser requests pyopenssl flask-sqlalchemy bcrypt

# Create application files
cat > $INSTALL_DIR/app.py << 'EOL'
import os
import logging
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import socket

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////var/lib/paging/paging.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Zone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))
    sip_targets = db.Column(db.String(255), nullable=False)
    multicast_address = db.Column(db.String(50))  # New field for multicast
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SIPConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sip_user = db.Column(db.String(80), nullable=False)
    sip_password = db.Column(db.String(80), nullable=False)
    sip_server = db.Column(db.String(120), nullable=False)
    sip_port = db.Column(db.Integer, default=5060)
    extension = db.Column(db.String(20), default="1000")
    display_name = db.Column(db.String(80), default="Paging System")
    default_zone = db.Column(db.String(100))
    registered = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def log_audit(user_id, action, details=None):
    try:
        audit = AuditLog(user_id=user_id, action=action, details=details)
        db.session.add(audit)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Audit log failed: {str(e)}")

def get_sip_status():
    try:
        result = subprocess.run(["asterisk", "-rx", "sip show registry"], capture_output=True, text=True)
        return "Registered" if "Registered" in result.stdout else "Not Registered"
    except:
        return "Error"

def broadcast_page(zone_id, message, audio_file=None):
    try:
        zone = Zone.query.get(zone_id)
        if not zone:
            return False, "Zone not found"
        
        sip_config = SIPConfig.query.first()
        if not sip_config:
            return False, "SIP not configured"
        
        # If audio_file is provided, use it instead of generating new message
        wav_file = audio_file if audio_file else "/opt/paging/static/test_message.wav"
        
        # If multicast is configured
        if zone.multicast_address:
            multicast_ip, multicast_port = zone.multicast_address.split(':')
            multicast_port = int(multicast_port) if multicast_port else 5004
            try:
                # Send multicast audio
                subprocess.Popen(["gst-launch-1.0", "-q", "filesrc", f"location={wav_file}", "!",
                                  "wavparse", "!", "audioconvert", "!", "rtpL16pay", "!",
                                  "udpsink", f"host={multicast_ip}", f"port={multicast_port}"])
                app.logger.info(f"Multicast sent to {zone.multicast_address}")
            except Exception as e:
                app.logger.error(f"Multicast failed: {str(e)}")
        
        # If SIP targets are configured
        if zone.sip_targets:
            targets = zone.sip_targets.split(',')
            for target in targets:
                cmd = f"asterisk -rx 'originate SIP/{target} extension s@page'"
                subprocess.Popen(cmd, shell=True)
        
        # Log the page broadcast
        log_audit(session['user_id'], 'page_broadcast', 
                  f"Zone: {zone.name}, Message: {message}")
        return True, "Page broadcasted"
    except Exception as e:
        return False, str(e)

def generate_asterisk_config():
    try:
        sip_config = SIPConfig.query.first()
        if not sip_config:
            return False, "No SIP configuration"
        
        # FIX: Use sip_config.sip_password instead of undefined sip_password
        # Enhanced SIP configuration for compatibility
        config = f"""[general]
context=default
bindport=5060
bindaddr=0.0.0.0
allowguest=no
srvlookup=yes
useragent=Algo 8301 Compatible
transport=udp,tcp
t38pt_udptl=yes
t38pt_rtp=no
t38pt_tcp=no
rtcachefriends=yes
rtsavesysname=yes
rtautoclear=yes
; Compatibility settings for 3CX, Hikvision, Dahua
directmedia=no
encryption=no
insecure=port,invite
nat=force_rport,comedia
session-timers=refuse
canreinvite=no
dtmfmode=rfc2833

[page]
type=friend
host=dynamic
defaultuser={sip_config.extension}
username={sip_config.extension}
secret={sip_config.sip_password}
callerid="{sip_config.display_name}" <{sip_config.extension}>
context=page
dtmfmode=rfc2833
disallow=all
allow=ulaw
allow=alaw
directmedia=no
encryption=no
insecure=port,invite
nat=force_rport,comedia
session-timers=refuse
canreinvite=no
"""
        with open("/etc/asterisk/sip.conf", "w") as f:
            f.write(config)
        
        extensions = f"""[page]
exten => s,1,Answer()
same => n,Playback(/opt/paging/static/test_message.wav)
same => n,Hangup()
"""
        with open("/etc/asterisk/extensions.conf", "w") as f:
            f.write(extensions)
        
        subprocess.run(["asterisk", "-rx", "reload"])
        log_audit(1, 'asterisk_reconfigured')
        return True, "Asterisk config updated"
    except Exception as e:
        return False, str(e)

# Routes
@app.route('/')
def index():
    return redirect(url_for('dashboard'))  # Changed to dashboard

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            session['user_id'] = user.id
            session['username'] = username
            log_audit(user.id, 'login_success')
            return redirect(url_for('dashboard'))
        else:
            log_audit(0, 'login_failed', f"Username: {username}")
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit(session['user_id'], 'logout')
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    sip_config = SIPConfig.query.first()
    sip_status = get_sip_status()
    zones = Zone.query.all()
    zone_count = len(zones)
    
    # Get service statuses
    services = {
        'paging': subprocess.run(["systemctl", "is-active", "paging-web"], capture_output=True, text=True).stdout.strip(),
        'nginx': subprocess.run(["systemctl", "is-active", "nginx"], capture_output=True, text=True).stdout.strip(),
        'asterisk': subprocess.run(["systemctl", "is-active", "asterisk"], capture_output=True, text=True).stdout.strip()
    }
    
    return render_template('dashboard.html', 
                           sip_status=sip_status,
                           zone_count=zone_count,
                           zones=zones,
                           services=services)  # Added services

# ... [Other routes remain the same until test_audio] ...

@app.route('/test_audio', methods=['GET', 'POST'])
def test_audio():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    zones = Zone.query.all()
    
    if request.method == 'POST':
        try:
            # Generate test message
            message = request.form.get('message', 'This is a test of the paging system')
            test_type = request.form.get('test_type', 'local')
            zone_id = request.form.get('zone_id')
            
            # Generate audio file
            wav_file = "/opt/paging/static/test_message.wav"
            subprocess.run(["espeak", "-w", wav_file, message])
            
            # Perform the requested test
            if test_type == 'local':
                # Play local audio
                subprocess.Popen(["aplay", wav_file])
                flash('Local audio test completed', 'success')
                
            elif test_type == 'multicast' and zone_id:
                # Test multicast
                zone = Zone.query.get(zone_id)
                if zone and zone.multicast_address:
                    multicast_ip, multicast_port = zone.multicast_address.split(':')
                    multicast_port = int(multicast_port) if multicast_port else 5004
                    
                    # Send multicast
                    subprocess.Popen(["gst-launch-1.0", "-q", "filesrc", f"location={wav_file}", "!",
                                      "wavparse", "!", "audioconvert", "!", "rtpL16pay", "!",
                                      "udpsink", f"host={multicast_ip}", f"port={multicast_port}"])
                    flash(f'Multicast test sent to {zone.multicast_address}', 'success')
                else:
                    flash('Multicast not configured for this zone', 'danger')
                    
            elif test_type == 'sip' and zone_id:
                # Test SIP broadcast
                success, result = broadcast_page(zone_id, message, wav_file)
                if success:
                    flash(f'SIP test broadcasted: {result}', 'success')
                else:
                    flash(f'SIP test failed: {result}', 'danger')
                    
            elif test_type == 'both' and zone_id:
                # Test both local and SIP
                subprocess.Popen(["aplay", wav_file])
                success, result = broadcast_page(zone_id, message, wav_file)
                if success:
                    flash(f'Local and SIP test completed: {result}', 'success')
                else:
                    flash(f'SIP test failed: {result}', 'danger')
                    
            else:
                flash('Invalid test configuration', 'danger')
            
            log_audit(session['user_id'], 'audio_test', 
                      f"Type: {test_type}, Zone: {zone_id}, Message: {message}")
        except Exception as e:
            flash(f'Audio test failed: {str(e)}', 'danger')
        
        return redirect(url_for('test_audio'))
    
    return render_template('test_audio.html', zones=zones)

# ... [Rest of the routes remain similar] ...

# Create database tables and default admin user
def initialize_database():
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        if not User.query.filter_by(username="admin").first():
            password = "admin".encode('utf-8')
            hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
            admin = User(username="admin", password_hash=hashed)
            db.session.add(admin)
            db.session.commit()
            print("Created default admin user")
        
        # Create default SIP config if not exists
        if not SIPConfig.query.first():
            sip_config = SIPConfig(
                sip_user="paging",
                sip_password="changeme",
                sip_server="192.168.1.100",
                sip_port=5060,
                extension="1000",
                display_name="Paging System",
                default_zone="Main Zone"
            )
            db.session.add(sip_config)
            db.session.commit()
            print("Created default SIP configuration")
        
        # Create test zone if none exist
        if not Zone.query.first():
            test_zone = Zone(
                name="Main Zone", 
                description="Primary paging zone", 
                sip_targets="1001,1002",
                multicast_address="239.0.0.1:5004"  # Default multicast
            )
            db.session.add(test_zone)
            db.session.commit()
            print("Created test paging zone")

if __name__ == '__main__':
    initialize_database()
    app.run(host='0.0.0.0', port=8080, debug=True)
EOL

# Create templates
mkdir -p $INSTALL_DIR/templates

# Base template with navigation
cat > $INSTALL_DIR/templates/base.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Paging Control - {% block title %}{% endblock %}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            background-color: #f0f2f5;
        }
        .header {
            background: #0a4f9e;
            color: white;
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            font-size: 1.5rem;
            font-weight: bold;
        }
        .nav-menu {
            display: flex;
            list-style: none;
            padding: 0;
            margin: 0 0 0 2rem;
        }
        .nav-menu li {
            margin-right: 1.5rem;
        }
        .nav-menu a {
            color: white;
            text-decoration: none;
            font-size: 1rem;
        }
        .nav-menu a:hover {
            text-decoration: underline;
        }
        .user-info {
            display: flex;
            align-items: center;
        }
        .username {
            margin-right: 1rem;
        }
        .logout {
            color: white;
            text-decoration: none;
        }
        .container {
            padding: 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }
        {% block extra_css %}{% endblock %}
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center;">
            <a href="{{ url_for('dashboard') }}" class="logo" style="color: white; text-decoration: none;">Paging Control</a>
            <ul class="nav-menu">
                <li><a href="{{ url_for('dashboard') }}">Dashboard</a></li>
                <li><a href="{{ url_for('manage_zones') }}">Zones</a></li>
                <li><a href="{{ url_for('system_settings') }}">Settings</a></li>
                <li><a href="{{ url_for('audit_log') }}">Audit Log</a></li>
            </ul>
        </div>
        <div class="user-info">
            <div class="username">{{ session.username }}</div>
            <a href="{{ url_for('logout') }}" class="logout">Logout</a>
        </div>
    </div>
    
    <div class="container">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
EOL

# Login template (doesn't extend base)
cat > $INSTALL_DIR/templates/login.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Paging Control - Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            width: 300px;
            text-align: center;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #0a4f9e;
            margin-bottom: 1.5rem;
        }
        .form-group {
            margin-bottom: 1rem;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: bold;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .btn {
            background: #0a4f9e;
            color: white;
            border: none;
            padding: 0.75rem;
            border-radius: 4px;
            width: 100%;
            font-size: 1rem;
            cursor: pointer;
        }
        .error {
            color: #d9534f;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">Paging Control</div>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">Sign In</button>
        </form>
        <div style="margin-top: 1rem; font-size: 0.8rem; color: #666;">
            Default: admin/admin
        </div>
    </div>
</body>
</html>
EOL

# Dashboard template (extends base)
cat > $INSTALL_DIR/templates/dashboard.html << 'EOL'
{% extends "base.html" %}

{% block title %}Dashboard{% endblock %}

{% block content %}
    <style>
        .status-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .card {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            text-align: center;
        }
        .card-title {
            font-size: 1.1rem;
            font-weight: bold;
            margin-bottom: 1rem;
            color: #333;
        }
        .card-status {
            font-size: 1.5rem;
            font-weight: bold;
            margin-bottom: 1rem;
        }
        .status-active {
            color: #28a745;
        }
        .status-inactive {
            color: #dc3545;
        }
        .status-warning {
            color: #ffc107;
        }
        .card-content {
            font-size: 0.9rem;
            color: #666;
        }
        .card-footer {
            margin-top: 1rem;
        }
        .btn {
            background: #0a4f9e;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .quick-actions {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 2rem;
        }
        .section-title {
            font-size: 1.25rem;
            font-weight: bold;
            margin-bottom: 1.5rem;
            color: #333;
        }
        .action-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .action-item {
            text-align: center;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .action-item:hover {
            background: #e9ecef;
        }
        .action-icon {
            font-size: 2rem;
            margin-bottom: 0.5rem;
            color: #0a4f9e;
        }
        .action-label {
            font-weight: bold;
        }
        .zone-list {
            list-style: none;
            padding: 0;
        }
        .zone-item {
            background: #f8f9fa;
            border-radius: 4px;
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            display: flex;
            justify-content: space-between;
        }
        .service-status {
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.5rem;
        }
        .service-name {
            font-weight: bold;
        }
    </style>

    <div class="status-cards">
        <div class="card">
            <div class="card-title">System Status</div>
            <div class="card-content">
                <div class="service-status">
                    <span class="service-name">Paging Service:</span>
                    <span class="{% if services.paging == 'active' %}status-active{% else %}status-inactive{% endif %}">
                        {{ services.paging|capitalize }}
                    </span>
                </div>
                <div class="service-status">
                    <span class="service-name">Nginx:</span>
                    <span class="{% if services.nginx == 'active' %}status-active{% else %}status-inactive{% endif %}">
                        {{ services.nginx|capitalize }}
                    </span>
                </div>
                <div class="service-status">
                    <span class="service-name">Asterisk:</span>
                    <span class="{% if services.asterisk == 'active' %}status-active{% else %}status-inactive{% endif %}">
                        {{ services.asterisk|capitalize }}
                    </span>
                </div>
            </div>
            <div class="card-footer">
                <a href="{{ url_for('system_settings') }}" class="btn">Configure</a>
            </div>
        </div>
        
        <div class="card">
            <div class="card-title">Paging Zones</div>
            <div class="card-status">{{ zone_count }}</div>
            <div class="card-content">
                {% if zones %}
                <ul class="zone-list">
                    {% for zone in zones[:3] %}
                    <li class="zone-item">{{ zone.name }}</li>
                    {% endfor %}
                    {% if zones|length > 3 %}
                    <li class="zone-item">+{{ zones|length - 3 }} more...</li>
                    {% endif %}
                </ul>
                {% else %}
                No zones configured
                {% endif %}
            </div>
            <div class="card-footer">
                <a href="{{ url_for('manage_zones') }}" class="btn">Manage</a>
            </div>
        </div>
        
        <div class="card">
            <div class="card-title">SIP Status</div>
            <div class="card-status 
                {% if sip_status == 'Registered' %}status-active
                {% elif sip_status == 'Not Registered' %}status-inactive
                {% else %}status-warning{% endif %}">
                {{ sip_status }}
            </div>
            <div class="card-content">
                {% if sip_status == 'Registered' %}
                Connection active
                {% elif sip_status == 'Not Registered' %}
                SIP not registered
                {% else %}
                Error checking status
                {% endif %}
            </div>
            <div class="card-footer">
                <a href="{{ url_for('system_settings') }}" class="btn">Configure</a>
            </div>
        </div>
    </div>
    
    <div class="quick-actions">
        <div class="section-title">Quick Actions</div>
        <div class="action-grid">
            <a href="#" class="action-item">
                <div class="action-icon"><i class="fas fa-bullhorn"></i></div>
                <div class="action-label">Send Page</div>
            </a>
            <a href="{{ url_for('system_settings') }}" class="action-item">
                <div class="action-icon"><i class="fas fa-cog"></i></div>
                <div class="action-label">System Settings</div>
            </a>
            <a href="{{ url_for('test_audio') }}" class="action-item">
                <div class="action-icon"><i class="fas fa-volume-up"></i></div>
                <div class="action-label">Test Audio</div>
            </a>
            <a href="{{ url_for('audit_log') }}" class="action-item">
                <div class="action-icon"><i class="fas fa-clipboard-list"></i></div>
                <div class="action-label">Audit Logs</div>
            </a>
            <a href="{{ url_for('change_password') }}" class="action-item">
                <div class="action-icon"><i class="fas fa-key"></i></div>
                <div class="action-label">Change Password</div>
            </a>
        </div>
    </div>
    
    <div class="quick-actions">
        <div class="section-title">Getting Started</div>
        <ol>
            <li>Change the default admin password</li>
            <li>Configure your SIP server settings</li>
            <li>Create paging zones</li>
            <li>Test your audio output</li>
            <li>Set up integrations with other systems</li>
        </ol>
    </div>
{% endblock %}
EOL

# ... [Other templates updated to extend base.html] ...

# New audio test template
cat > $INSTALL_DIR/templates/test_audio.html << 'EOL'
{% extends "base.html" %}

{% block title %}Test Audio{% endblock %}

{% block content %}
    <style>
        .test-container {
            background: white;
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 2rem;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: bold;
        }
        input, textarea, select {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 1rem;
        }
        .btn {
            background: #0a4f9e;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 4px;
            font-size: 1rem;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .test-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        .test-option {
            padding: 1rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            text-align: center;
            cursor: pointer;
        }
        .test-option.active {
            border-color: #0a4f9e;
            background-color: #e6f0ff;
        }
    </style>

    <div class="section-title">Test Audio Output</div>
    
    <div class="test-container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                <div class="alert alert-{{ category }}" 
                     style="padding:10px; margin-bottom:20px; 
                            background:{% if category=='success'%}#d4edda{% else %}#f8d7da{% endif %}; 
                            color:{% if category=='success'%}#155724{% else %}#721c24{% endif %}; 
                            border-radius:4px;">
                    {{ message }}
                </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST" action="{{ url_for('test_audio') }}">
            <div class="form-group">
                <label for="message">Test Message</label>
                <input type="text" id="message" name="message" value="This is a test of the paging system">
            </div>
            
            <div class="form-group">
                <label>Test Type</label>
                <div class="test-options">
                    <div class="test-option {% if request.form.get('test_type', 'local') == 'local' %}active{% endif %}" 
                         onclick="selectTestType('local')">
                        <input type="radio" name="test_type" value="local" 
                               {% if request.form.get('test_type', 'local') == 'local' %}checked{% endif %} 
                               style="display: none;">
                        <i class="fas fa-volume-up" style="font-size: 2rem; margin-bottom: 0.5rem;"></i>
                        <div>Local Speaker</div>
                    </div>
                    
                    <div class="test-option {% if request.form.get('test_type') == 'multicast' %}active{% endif %}" 
                         onclick="selectTestType('multicast')">
                        <input type="radio" name="test_type" value="multicast" 
                               {% if request.form.get('test_type') == 'multicast' %}checked{% endif %} 
                               style="display: none;">
                        <i class="fas fa-wifi" style="font-size: 2rem; margin-bottom: 0.5rem;"></i>
                        <div>Multicast</div>
                    </div>
                    
                    <div class="test-option {% if request.form.get('test_type') == 'sip' %}active{% endif %}" 
                         onclick="selectTestType('sip')">
                        <input type="radio" name="test_type" value="sip" 
                               {% if request.form.get('test_type') == 'sip' %}checked{% endif %} 
                               style="display: none;">
                        <i class="fas fa-phone" style="font-size: 2rem; margin-bottom: 0.5rem;"></i>
                        <div>SIP Broadcast</div>
                    </div>
                    
                    <div class="test-option {% if request.form.get('test_type') == 'both' %}active{% endif %}" 
                         onclick="selectTestType('both')">
                        <input type="radio" name="test_type" value="both" 
                               {% if request.form.get('test_type') == 'both' %}checked{% endif %} 
                               style="display: none;">
                        <i class="fas fa-broadcast-tower" style="font-size: 2rem; margin-bottom: 0.5rem;"></i>
                        <div>Both</div>
                    </div>
                </div>
            </div>
            
            <div class="form-group" id="zoneSelection" 
                 style="display: {% if request.form.get('test_type') in ['multicast', 'sip', 'both'] %}block{% else %}none{% endif %};">
                <label for="zone_id">Select Zone</label>
                <select id="zone_id" name="zone_id">
                    {% for zone in zones %}
                    <option value="{{ zone.id }}">{{ zone.name }}</option>
                    {% endfor %}
                </select>
            </div>
            
            <div style="margin-top: 1.5rem;">
                <button type="submit" class="btn">Run Test</button>
            </div>
        </form>
    </div>

    <script>
        function selectTestType(type) {
            // Update UI
            document.querySelectorAll('.test-option').forEach(opt => {
                opt.classList.remove('active');
            });
            event.currentTarget.classList.add('active');
            
            // Update radio button
            document.querySelector(`input[value="${type}"]`).checked = true;
            
            // Show/hide zone selection
            const zoneSelection = document.getElementById('zoneSelection');
            if (type === 'local') {
                zoneSelection.style.display = 'none';
            } else {
                zoneSelection.style.display = 'block';
            }
        }
    </script>
{% endblock %}
EOL

# ... [Rest of the script remains similar with updated templates] ...

# Create systemd service file
echo "Creating systemd service..."
cat > $SERVICE_FILE << EOL
[Unit]
Description=IP Paging Web Interface
After=network.target

[Service]
User=$ADMIN_USER
Group=$ADMIN_USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/bin"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py
Restart=always
RestartSec=5

# Standard output logging
StandardOutput=append:$LOG_DIR/app.log
StandardError=append:$LOG_DIR/error.log

[Install]
WantedBy=multi-user.target
EOL

# ... [Rest of the script remains similar] ...

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
echo "Important Next Steps:"
echo "1. Change the default admin password (in Security menu)"
echo "2. Configure SIP settings with extension and display name"
echo "3. For 3CX/Hikvision/Dahua compatibility:"
echo "   - Use the extension as the authentication ID"
echo "   - Set transport to UDP/TCP"
echo "   - Disable encryption"
echo "   - Use port 5060"
echo "4. Create paging zones and configure multicast addresses"
echo "5. Test audio output using the new test options"
echo ""
echo "Installation log: $LOG_FILE"
echo "====================================================="
