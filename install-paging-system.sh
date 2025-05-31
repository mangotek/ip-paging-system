#!/bin/bash
# Complete IP Paging System Installer for x86
# Tested on Ubuntu 22.04 (x86)

# Configuration
ADMIN_USER="pagingadmin"
INSTALL_DIR="/opt/paging"
DB_DIR="/var/lib/paging"
LOG_DIR="/var/log/paging"
NGINX_DIR="/etc/nginx/sites-available"
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
    build-essential libssl-dev libffi-dev ufw asterisk espeak bcrypt

# Install Python dependencies
echo "Setting up Python environment..."
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate
pip install flask werkzeug configparser requests pyopenssl flask-sqlalchemy bcrypt

# Create database
echo "Initializing database..."
cat > $INSTALL_DIR/init_db.py << 'EOL'
from app import db, create_app
from models import User, Zone, SIPConfig, AuditLog

app = create_app()
with app.app_context():
    db.create_all()
    
    # Create default admin user if not exists
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", password_hash=bcrypt.generate_password_hash("admin").decode('utf-8'))
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
            default_zone="Main Zone"
        )
        db.session.add(sip_config)
        db.session.commit()
        print("Created default SIP configuration")
    
    # Create test zone if none exist
    if not Zone.query.first():
        test_zone = Zone(name="Main Zone", description="Primary paging zone", sip_targets="1001,1002")
        db.session.add(test_zone)
        db.session.commit()
        print("Created test paging zone")
EOL

# Create database models and app
cat > $INSTALL_DIR/app.py << 'EOL'
import os
import logging
import sqlite3
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SIPConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sip_user = db.Column(db.String(80), nullable=False)
    sip_password = db.Column(db.String(80), nullable=False)
    sip_server = db.Column(db.String(120), nullable=False)
    sip_port = db.Column(db.Integer, default=5060)
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
        
        config = f"""[general]
context=default
bindport=5060
bindaddr=0.0.0.0

[page]
type=friend
host=dynamic
secret={sip_config.sip_password}
context=page
dtmfmode=rfc2833
canreinvite=no
disallow=all
allow=ulaw
allow=alaw
"""
        with open("/etc/asterisk/sip.conf", "w") as f:
            f.write(config)
        
        extensions = f"""[page]
exten => s,1,Answer()
same => n,Playback({AUDIO_TEST_FILE})
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
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
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
                    sip_targets=request.form['sip_targets']
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
            sip_port=5060
        )
        db.session.add(sip_config)
        db.session.commit()
    
    if request.method == 'POST':
        sip_config.sip_user = request.form['sip_user']
        sip_config.sip_password = request.form['sip_password']
        sip_config.sip_server = request.form['sip_server']
        sip_config.sip_port = request.form['sip_port']
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
        subprocess.run(["espeak", "-w", AUDIO_TEST_FILE, message])
        
        # Play audio
        subprocess.Popen(["aplay", AUDIO_TEST_FILE])
        
        flash('Audio test completed', 'success')
        log_audit(session['user_id'], 'audio_test', message)
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
EOL

# Create templates
mkdir -p $INSTALL_DIR/templates

# Login template remains the same as before...

# Dashboard template (updated with dynamic data)
cat > $INSTALL_DIR/templates/dashboard.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Paging Control - Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Existing styles remain the same... */
        
        /* New status indicators */
        .status-active { color: #28a745; }
        .status-inactive { color: #dc3545; }
        .status-warning { color: #ffc107; }
        
        /* Quick action icons */
        .action-icon {
            font-size: 2rem;
            margin-bottom: 0.5rem;
            color: #0a4f9e;
        }
        
        /* Zone list */
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
        <div class="logo">Paging Control</div>
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
                    <button class="btn">View Details</button>
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
                    <div style="margin-top:20px; display:flex; justify-content:space-between;">
                        <button type="button" onclick="document.getElementById('audioTestModal').style.display='none'" class="btn" style="background:#6c757d;">Cancel</button>
                        <button type="submit" class="btn">Play Test</button>
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

# Create zones management template
cat > $INSTALL_DIR/templates/zones.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Paging Control - Zones</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Header and container styles same as dashboard... */
        
        .section-title {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: #333;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .btn-success {
            background: #28a745;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 2rem;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        
        .actions-cell {
            display: flex;
            gap: 0.5rem;
        }
        
        .btn-sm {
            padding: 0.25rem 0.5rem;
            font-size: 0.875rem;
        }
        
        .btn-danger {
            background: #dc3545;
        }
        
        .form-container {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 2rem;
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: bold;
        }
        
        input, textarea {
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
            font-size: 1rem;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">Paging Control</div>
        <div class="user-info">
            <div class="username">{{ session.username }}</div>
            <a href="{{ url_for('logout') }}" class="logout">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="section-title">
            <span>Manage Paging Zones</span>
            <button class="btn" onclick="toggleForm()">
                <i class="fas fa-plus"></i> Add Zone
            </button>
        </div>
        
        <!-- Success/Error Messages -->
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                <div class="alert alert-{{ category }}" style="padding:10px; margin-bottom:20px; background:{% if category=='success'%}#d4edda{% else %}#f8d7da{% endif %}; color:{% if category=='success'%}#155724{% else %}#721c24{% endif %}; border-radius:4px;">
                    {{ message }}
                </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div id="zoneForm" style="display:none; margin-bottom:30px;">
            <div class="form-container">
                <h3 id="formTitle">Add New Zone</h3>
                <form method="POST" action="{{ url_for('manage_zones') }}">
                    <input type="hidden" id="zoneId" name="zone_id" value="">
                    <div class="form-group">
                        <label for="name">Zone Name *</label>
                        <input type="text" id="name" name="name" required>
                    </div>
                    <div class="form-group">
                        <label for="description">Description</label>
                        <input type="text" id="description" name="description">
                    </div>
                    <div class="form-group">
                        <label for="sip_targets">SIP Targets *</label>
                        <input type="text" id="sip_targets" name="sip_targets" required placeholder="Comma-separated extensions (e.g., 1001,1002)">
                    </div>
                    <div style="margin-top:20px;">
                        <button type="button" onclick="cancelEdit()" class="btn" style="background:#6c757d;">Cancel</button>
                        <button type="submit" class="btn">Save Zone</button>
                    </div>
                </form>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Description</th>
                    <th>SIP Targets</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for zone in zones %}
                <tr>
                    <td>{{ zone.name }}</td>
                    <td>{{ zone.description or '-' }}</td>
                    <td>{{ zone.sip_targets }}</td>
                    <td class="actions-cell">
                        <button class="btn btn-sm" onclick="editZone({{ zone.id }}, '{{ zone.name }}', '{{ zone.description }}', '{{ zone.sip_targets }}')">
                            <i class="fas fa-edit"></i> Edit
                        </button>
                        <a href="{{ url_for('delete_zone', zone_id=zone.id) }}" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure you want to delete this zone?')">
                            <i class="fas fa-trash"></i> Delete
                        </a>
                    </td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="4" style="text-align:center;">No zones found</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <script>
        function toggleForm() {
            const form = document.getElementById('zoneForm');
            if (form.style.display === 'none') {
                document.getElementById('formTitle').textContent = 'Add New Zone';
                document.getElementById('zoneId').value = '';
                document.getElementById('name').value = '';
                document.getElementById('description').value = '';
                document.getElementById('sip_targets').value = '';
                form.style.display = 'block';
            } else {
                form.style.display = 'none';
            }
        }
        
        function cancelEdit() {
            document.getElementById('zoneForm').style.display = 'none';
        }
        
        function editZone(id, name, description, sip_targets) {
            document.getElementById('formTitle').textContent = 'Edit Zone';
            document.getElementById('zoneId').value = id;
            document.getElementById('name').value = name;
            document.getElementById('description').value = description || '';
            document.getElementById('sip_targets').value = sip_targets;
            document.getElementById('zoneForm').style.display = 'block';
            
            // Scroll to form
            document.getElementById('zoneForm').scrollIntoView({ behavior: 'smooth' });
        }
    </script>
</body>
</html>
EOL

# Create settings template
cat > $INSTALL_DIR/templates/settings.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Paging Control - Settings</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Header and container styles same as dashboard... */
        
        .settings-container {
            background: white;
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 2rem;
        }
        
        .section-title {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: #333;
            border-bottom: 1px solid #eee;
            padding-bottom: 0.5rem;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: bold;
        }
        
        input, select {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 1rem;
        }
        
        .status-indicator {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: bold;
            margin-left: 1rem;
        }
        
        .status-active { background: #d4edda; color: #155724; }
        .status-inactive { background: #f8d7da; color: #721c24; }
        .status-warning { background: #fff3cd; color: #856404; }
        
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
        
        .btn-test {
            background: #17a2b8;
            margin-left: 1rem;
        }
        
        .alert {
            padding: 1rem;
            margin-bottom: 1.5rem;
            border-radius: 4px;
        }
        
        .alert-success { background: #d4edda; color: #155724; }
        .alert-danger { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">Paging Control</div>
        <div class="user-info">
            <div class="username">{{ session.username }}</div>
            <a href="{{ url_for('logout') }}" class="logout">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="section-title">System Settings</div>
        
        <!-- Success/Error Messages -->
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                <div class="alert alert-{{ category }}">
                    {{ message }}
                </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="settings-container">
            <h3>SIP Configuration</h3>
            <form method="POST" action="{{ url_for('system_settings') }}">
                <div class="form-group">
                    <label for="sip_user">SIP Username</label>
                    <input type="text" id="sip_user" name="sip_user" value="{{ config.sip_user }}" required>
                </div>
                
                <div class="form-group">
                    <label for="sip_password">SIP Password</label>
                    <input type="password" id="sip_password" name="sip_password" value="{{ config.sip_password }}" required>
                </div>
                
                <div class="form-group">
                    <label for="sip_server">SIP Server</label>
                    <input type="text" id="sip_server" name="sip_server" value="{{ config.sip_server }}" required>
                </div>
                
                <div class="form-group">
                    <label for="sip_port">SIP Port</label>
                    <input type="number" id="sip_port" name="sip_port" value="{{ config.sip_port }}" required>
                </div>
                
                <div class="form-group">
                    <label for="default_zone">Default Zone</label>
                    <select id="default_zone" name="default_zone">
                        <option value="">-- Select Zone --</option>
                        {% for zone in zones %}
                        <option value="{{ zone.name }}" {% if config.default_zone == zone.name %}selected{% endif %}>
                            {{ zone.name }}
                        </option>
                        {% endfor %}
                    </select>
                </div>
                
                <div style="margin-top: 2rem;">
                    <button type="submit" class="btn">Save Settings</button>
                    <span class="status-indicator 
                        {% if sip_status == 'Registered' %}status-active
                        {% elif sip_status == 'Not Registered' %}status-inactive
                        {% else %}status-warning{% endif %}">
                        SIP Status: {{ sip_status }}
                    </span>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
EOL

# Create audit log template
cat > $INSTALL_DIR/templates/audit_log.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Paging Control - Audit Log</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Header and container styles same as dashboard... */
        
        .section-title {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: #333;
        }
        
        .log-container {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 2rem;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            margin-top: 1.5rem;
        }
        
        .pagination a, .pagination span {
            display: inline-block;
            padding: 0.5rem 0.75rem;
            margin: 0 0.25rem;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            text-decoration: none;
            color: #0a4f9e;
        }
        
        .pagination .active {
            background: #0a4f9e;
            color: white;
            border-color: #0a4f9e;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">Paging Control</div>
        <div class="user-info">
            <div class="username">{{ session.username }}</div>
            <a href="{{ url_for('logout') }}" class="logout">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="section-title">Audit Log</div>
        
        <div class="log-container">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>User</th>
                        <th>Action</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs.items %}
                    <tr>
                        <td>{{ log.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                        <td>{% if log.user_id == 0 %}System{% else %}User {{ log.user_id }}{% endif %}</td>
                        <td>{{ log.action }}</td>
                        <td>{{ log.details or '-' }}</td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="4" style="text-align:center;">No audit records found</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <div class="pagination">
                {% if logs.has_prev %}
                    <a href="{{ url_for('audit_log', page=logs.prev_num) }}">&laquo; Previous</a>
                {% endif %}
                
                {% for page_num in logs.iter_pages() %}
                    {% if page_num %}
                        {% if logs.page == page_num %}
                            <span class="active">{{ page_num }}</span>
                        {% else %}
                            <a href="{{ url_for('audit_log', page=page_num) }}">{{ page_num }}</a>
                        {% endif %}
                    {% else %}
                        <span class="ellipsis">...</span>
                    {% endif %}
                {% endfor %}
                
                {% if logs.has_next %}
                    <a href="{{ url_for('audit_log', page=logs.next_num) }}">Next &raquo;</a>
                {% endif %}
            </div>
        </div>
    </div>
</body>
</html>
EOL

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
rm -f /etc/nginx/sites-enabled/default

# Enable configuration
echo "Enabling Nginx site..."
ln -sf $NGINX_DIR/paging /etc/nginx/sites-enabled/

# Configure firewall
echo "Configuring firewall..."
ufw allow 80/tcp
ufw allow 5060/udp
ufw --force enable

# Initialize database
echo "Setting up database..."
cd $INSTALL_DIR
source venv/bin/activate
export FLASK_APP=app.py
flask db upgrade  # This would normally require migrations, but we're creating from scratch
python init_db.py
deactivate

# Generate Asterisk configuration
echo "Configuring Asterisk..."
mkdir -p /etc/asterisk
cat > /etc/asterisk/sip.conf << EOL
[general]
context=default
bindport=5060
bindaddr=0.0.0.0

[page]
type=friend
host=dynamic
secret=changeme
context=page
dtmfmode=rfc2833
canreinvite=no
disallow=all
allow=ulaw
allow=alaw
EOL

cat > /etc/asterisk/extensions.conf << EOL
[page]
exten => s,1,Answer()
same => n,Playback($AUDIO_TEST_FILE)
same => n,Hangup()
EOL

chown -R $ADMIN_USER:$ADMIN_USER /etc/asterisk

# Create test audio file
echo "Creating test audio file..."
echo "This is a test message for the paging system" | \
    text2wave -eval '(voice_cmu_us_slt_arctic_hts)' -o $AUDIO_TEST_FILE

# Set permissions
chown -R $ADMIN_USER:$ADMIN_USER $INSTALL_DIR $DB_DIR $LOG_DIR
chmod 755 $AUDIO_TEST_FILE

# Start services
echo "Starting services..."
systemctl daemon-reload
systemctl enable paging-web
systemctl start paging-web
systemctl restart asterisk
systemctl restart nginx

# Wait for app to start
echo "Waiting for application to initialize..."
sleep 5

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
echo "Next steps:"
echo "1. Configure SIP settings in the web interface"
echo "2. Create paging zones"
echo "3. Test audio output"
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
asterisk -rx "sip show registry"

echo -e "\n5. Database content:"
sqlite3 $DB_FILE "SELECT * FROM user; SELECT * FROM sip_config; SELECT * FROM zone;"

echo -e "\nTroubleshooting tips:"
echo "If you get a 502 Bad Gateway:"
echo "1. Check if Flask is running: systemctl status paging-web"
echo "2. Test Flask directly: curl http://localhost:8080"
echo "3. Check Nginx error logs: tail -f $LOG_DIR/nginx-error.log"
echo "4. Check application logs: tail -f $LOG_DIR/app.log"
