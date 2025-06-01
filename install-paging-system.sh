#!/bin/bash
# Enhanced IP Paging System Installer with Navigation Fixes, Status Monitoring, and Audio Testing
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
    build-essential libssl-dev libffi-dev ufw asterisk espeak ffmpeg

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
import socket
import struct
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt

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
    multicast_address = db.Column(db.String(20), default="239.255.255.250")
    multicast_port = db.Column(db.Integer, default=1234)
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

def get_service_status(service_name):
    try:
        result = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return "unknown"

def broadcast_page(zone_id, message):
    try:
        zone = Zone.query.get(zone_id)
        if not zone:
            return False, "Zone not found"
        
        sip_config = SIPConfig.query.first()
        if not sip_config:
            return False, "SIP not configured"
        
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

def send_multicast_audio(zone_id, audio_file):
    try:
        zone = Zone.query.get(zone_id)
        if not zone:
            return False, "Zone not found"
        
        # Create UDP socket for multicast
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        
        # Read audio file
        with open(audio_file, 'rb') as f:
            audio_data = f.read()
        
        # Split into packets and send
        packet_size = 1400
        for i in range(0, len(audio_data), packet_size):
            packet = audio_data[i:i+packet_size]
            sock.sendto(packet, (zone.multicast_address, zone.multicast_port))
        
        return True, "Multicast audio sent"
    except Exception as e:
        return False, str(e)

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

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
    
    return render_template('dashboard.html', 
                           sip_status=sip_status,
                           zone_count=zone_count,
                           zones=zones)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        user = User.query.get(session['user_id'])
        
        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), user.password_hash.encode('utf-8')):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('change_password'))
        
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('change_password'))
        
        # Update password
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.password_hash = hashed
        db.session.commit()
        
        flash('Password changed successfully', 'success')
        log_audit(session['user_id'], 'password_change')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/system_status')
def system_status():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    services = {
        "Paging Web": get_service_status("paging-web"),
        "Nginx": get_service_status("nginx"),
        "Asterisk": get_service_status("asterisk"),
        "System Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    return render_template('system_status.html', services=services)

@app.route('/zones', methods=['GET', 'POST'])
def manage_zones():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        zone_id = request.form.get('zone_id')
        if zone_id:  # Update existing zone
            zone = Zone.query.get(zone_id)
            if zone:
                zone.name = request.form['name']
                zone.description = request.form['description']
                zone.sip_targets = request.form['sip_targets']
                zone.multicast_address = request.form['multicast_address']
                zone.multicast_port = request.form['multicast_port']
                db.session.commit()
                log_audit(session['user_id'], 'zone_updated', f"Zone: {zone.name}")
                flash('Zone updated successfully', 'success')
        else:  # Create new zone
            name = request.form['name']
            if Zone.query.filter_by(name=name).first():
                flash('Zone name already exists', 'danger')
            else:
                new_zone = Zone(
                    name=name,
                    description=request.form['description'],
                    sip_targets=request.form['sip_targets'],
                    multicast_address=request.form['multicast_address'],
                    multicast_port=request.form['multicast_port']
                )
                db.session.add(new_zone)
                db.session.commit()
                log_audit(session['user_id'], 'zone_created', f"Zone: {name}")
                flash('Zone created successfully', 'success')
        return redirect(url_for('manage_zones'))
    
    zones = Zone.query.all()
    return render_template('zones.html', zones=zones)

@app.route('/zone/delete/<int:zone_id>')
def delete_zone(zone_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    zone = Zone.query.get(zone_id)
    if zone:
        db.session.delete(zone)
        db.session.commit()
        log_audit(session['user_id'], 'zone_deleted', f"Zone: {zone.name}")
        flash('Zone deleted successfully', 'success')
    else:
        flash('Zone not found', 'danger')
    return redirect(url_for('manage_zones'))

@app.route('/settings', methods=['GET', 'POST'])
def system_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    sip_config = SIPConfig.query.first()
    if not sip_config:
        sip_config = SIPConfig(
            sip_user="paging",
            sip_password="changeme",
            sip_server="192.168.1.100",
            sip_port=5060,
            extension="1000",
            display_name="Paging System"
        )
        db.session.add(sip_config)
        db.session.commit()
    
    if request.method == 'POST':
        sip_config.sip_user = request.form['sip_user']
        sip_config.sip_password = request.form['sip_password']
        sip_config.sip_server = request.form['sip_server']
        sip_config.sip_port = request.form['sip_port']
        sip_config.extension = request.form['extension']
        sip_config.display_name = request.form['display_name']
        sip_config.default_zone = request.form['default_zone']
        db.session.commit()
        
        # Regenerate Asterisk config
        success, message = generate_asterisk_config()
        if success:
            flash('SIP settings saved and applied', 'success')
            log_audit(session['user_id'], 'sip_updated', 
                      f"Server: {sip_config.sip_server}")
        else:
            flash(f'Error: {message}', 'danger')
        
        return redirect(url_for('system_settings'))
    
    zones = Zone.query.all()
    sip_status = get_sip_status()
    return render_template('settings.html', 
                           config=sip_config, 
                           zones=zones,
                           sip_status=sip_status)

@app.route('/test_audio', methods=['POST'])
def test_audio():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        # Generate test message
        message = request.form.get('message', 'This is a test of the paging system')
        subprocess.run(["espeak", "-w", "/opt/paging/static/test_message.wav", message])
        
        test_type = request.form.get('test_type', 'local')
        zone_id = request.form.get('zone_id')
        
        if test_type == 'local':
            # Play audio locally
            subprocess.Popen(["aplay", "/opt/paging/static/test_message.wav"])
            details = "Local playback"
        elif test_type == 'multicast' and zone_id:
            # Send multicast audio
            success, result = send_multicast_audio(zone_id, "/opt/paging/static/test_message.wav")
            if not success:
                flash(f'Multicast failed: {result}', 'danger')
                return redirect(url_for('dashboard'))
            details = f"Multicast to zone {zone_id}"
        elif test_type == 'sip' and zone_id:
            # Send SIP page
            success, result = broadcast_page(zone_id, message)
            if not success:
                flash(f'SIP broadcast failed: {result}', 'danger')
                return redirect(url_for('dashboard'))
            details = f"SIP broadcast to zone {zone_id}"
        else:
            flash('Invalid test parameters', 'danger')
            return redirect(url_for('dashboard'))
        
        flash('Audio test completed: ' + details, 'success')
        log_audit(session['user_id'], 'audio_test', details)
    except Exception as e:
        flash(f'Audio test failed: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/audit_log')
def audit_log():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=per_page)
    
    return render_template('audit_log.html', logs=logs)

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
                multicast_address="239.255.255.250",
                multicast_port=1234
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

# Login template
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

# Dashboard template with navigation fix
cat > $INSTALL_DIR/templates/dashboard.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Paging Control - Dashboard</title>
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
        .logo a {
            color: white;
            text-decoration: none;
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
    </style>
</head>
<body>
    <div class="header">
        <div class="logo"><a href="{{ url_for('dashboard') }}">Paging Control</a></div>
        <div class="user-info">
            <div class="username">{{ session.username }}</div>
            <a href="{{ url_for('logout') }}" class="logout">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="status-cards">
            <div class="card">
                <div class="card-title">System Status</div>
                <div class="card-status status-active">Operational</div>
                <div class="card-content">All services running normally</div>
                <div class="card-footer">
                    <a href="{{ url_for('system_status') }}" class="btn">View Details</a>
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
                <a href="#" id="testAudioBtn" class="action-item">
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
        
        <!-- Audio Test Modal -->
        <div id="audioTestModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:1000;">
            <div style="background:white; width:400px; margin:100px auto; padding:20px; border-radius:8px;">
                <h3>Test Audio Output</h3>
                <form method="POST" action="{{ url_for('test_audio') }}">
                    <div class="form-group">
                        <label for="testMessage">Test Message</label>
                        <input type="text" id="testMessage" name="message" class="form-control" value="This is a test of the paging system">
                    </div>
                    
                    <div class="form-group">
                        <label for="testZone">Select Zone</label>
                        <select id="testZone" name="zone_id" class="form-control">
                            {% for zone in zones %}
                            <option value="{{ zone.id }}">{{ zone.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label>Test Type</label>
                        <div>
                            <input type="radio" id="localTest" name="test_type" value="local" checked>
                            <label for="localTest">Local Playback</label>
                        </div>
                        <div>
                            <input type="radio" id="multicastTest" name="test_type" value="multicast">
                            <label for="multicastTest">Multicast Broadcast</label>
                        </div>
                        <div>
                            <input type="radio" id="sipTest" name="test_type" value="sip">
                            <label for="sipTest">SIP Broadcast</label>
                        </div>
                    </div>
                    
                    <div style="margin-top:20px; display:flex; justify-content:space-between;">
                        <button type="button" onclick="document.getElementById('audioTestModal').style.display='none'" class="btn" style="background:#6c757d;">Cancel</button>
                        <button type="submit" class="btn">Run Test</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('testAudioBtn').addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('audioTestModal').style.display = 'block';
        });
    </script>
</body>
</html>
EOL

# System status template
cat > $INSTALL_DIR/templates/system_status.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Paging Control - System Status</title>
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
        .logo a {
            color: white;
            text-decoration: none;
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
        .section-title {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: #333;
        }
        .status-container {
            background: white;
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 2rem;
        }
        .status-table {
            width: 100%;
            border-collapse: collapse;
        }
        .status-table th, .status-table td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        .status-table th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .status-active {
            color: #28a745;
            font-weight: bold;
        }
        .status-inactive {
            color: #dc3545;
            font-weight: bold;
        }
        .status-unknown {
            color: #6c757d;
            font-weight: bold;
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
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo"><a href="{{ url_for('dashboard') }}">Paging Control</a></div>
        <div class="user-info">
            <div class="username">{{ session.username }}</div>
            <a href="{{ url_for('logout') }}" class="logout">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="section-title">System Status</div>
        
        <div class="status-container">
            <table class="status-table">
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for service, status in services.items() %}
                    <tr>
                        <td>{{ service }}</td>
                        <td>
                            {% if status == 'active' %}
                                <span class="status-active">Active</span>
                            {% elif status == 'inactive' or status == 'failed' %}
                                <span class="status-inactive">Inactive</span>
                            {% else %}
                                <span class="status-unknown">Unknown</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <a href="{{ url_for('dashboard') }}" class="btn">
                <i class="fas fa-arrow-left"></i> Back to Dashboard
            </a>
        </div>
    </div>
</body>
</html>
EOL

# Other templates (change_password.html, zones.html, settings.html, audit_log.html) 
# should also have the navigation fix in the header:
# Replace: <div class="logo">Paging Control</div>
# With: <div class="logo"><a href="{{ url_for('dashboard') }}">Paging Control</a></div>

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

# Create Nginx configuration
echo "Configuring Nginx..."
cat > $NGINX_DIR/paging << EOL
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name _;
    
    # Error logging
    error_log $LOG_DIR/nginx-error.log;
    access_log $LOG_DIR/nginx-access.log;
    
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
    
    # Static files
    location /static {
        alias $INSTALL_DIR/static;
        expires 30d;
    }
    
    # Block access to sensitive files
    location ~ /\.(?!well-known).* {
        deny all;
    }
}
EOL

# Remove default site
echo "Removing default Nginx site..."
rm -f $NGINX_ENABLED_DIR/default

# Enable configuration
echo "Enabling Nginx site..."
ln -sf $NGINX_DIR/paging $NGINX_ENABLED_DIR/paging

# Configure firewall
echo "Configuring firewall..."
ufw allow 80/tcp
ufw allow 5060/udp
ufw allow 1234/udp  # Multicast port
ufw --force enable

# Configure Asterisk
echo "Configuring Asterisk..."
mkdir -p /etc/asterisk
cat > /etc/asterisk/sip.conf << EOL
[general]
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
defaultuser=1000
username=1000
secret=changeme
callerid="Paging System" <1000>
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
EOL

cat > /etc/asterisk/extensions.conf << EOL
[page]
exten => s,1,Answer()
same => n,Playback(/opt/paging/static/test_message.wav)
same => n,Hangup()
EOL

# Create test audio file
echo "Creating test audio file..."
mkdir -p $INSTALL_DIR/static
espeak -w $AUDIO_TEST_FILE "This is a test message for the paging system" || \
echo "This is a test message" | espeak -w $AUDIO_TEST_FILE -s 120

# Set permissions
chown -R $ADMIN_USER:$ADMIN_USER $INSTALL_DIR $DB_DIR $LOG_DIR
chown -R asterisk:asterisk /etc/asterisk
chmod 644 $AUDIO_TEST_FILE
chmod 644 /etc/asterisk/*.conf

# Fix Asterisk permissions
usermod -a -G audio asterisk
usermod -a -G $ADMIN_USER asterisk
chmod g+rx $INSTALL_DIR/static
chmod g+r $AUDIO_TEST_FILE

# Start services
echo "Starting services..."
systemctl daemon-reload
systemctl enable paging-web
systemctl start paging-web
systemctl enable asterisk
systemctl start asterisk
systemctl restart nginx

# Wait for app to start
echo "Waiting for application to initialize..."
sleep 10

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
echo "Important Next Steps:"
echo "1. Change the default admin password (in Security menu)"
echo "2. Configure SIP settings with extension and display name"
echo "3. For 3CX/Hikvision/Dahua compatibility:"
echo "   - Use the extension as the authentication ID"
echo "   - Set transport to UDP/TCP"
echo "   - Disable encryption"
echo "   - Use port 5060"
echo "4. Create paging zones"
echo "5. Test audio output using different methods:"
echo "   - Local playback"
echo "   - Multicast broadcast"
echo "   - SIP broadcast"
echo ""
echo "Installation log: $LOG_FILE"
echo "====================================================="

# Verification steps
echo "Running verification checks..."
echo "1. Service status:"
systemctl status paging-web --no-pager | head -10

echo -e "\n2. Nginx status:"
systemctl status nginx --no-pager | head -10

echo -e "\n3. Asterisk status:"
systemctl status asterisk --no-pager | head -10

echo -e "\n4. SIP registration status:"
asterisk -rx "sip show registry" 2>/dev/null || echo "Asterisk command failed"

echo -e "\n5. Database content:"
sqlite3 $DB_FILE "SELECT * FROM user;" 2>/dev/null || echo "Database not found"

echo -e "\nTroubleshooting tips:"
echo "If devices can't register:"
echo "1. Check SIP settings in web interface"
echo "2. Verify extension and display name are correct"
echo "3. Ensure firewall allows traffic on port 5060"
echo "4. Check Asterisk logs: /var/log/asterisk/messages"
echo "5. Test with different transport (UDP/TCP) in device settings"
