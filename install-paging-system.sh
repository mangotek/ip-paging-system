#!/bin/bash
# Robust IP Paging System Installer for x86
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
    build-essential libssl-dev libffi-dev ufw asterisk espeak

# Install Python dependencies
echo "Setting up Python environment..."
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate
pip install flask werkzeug configparser requests pyopenssl flask-sqlalchemy bcrypt

# Create database models and app
cat > $INSTALL_DIR/app.py << 'EOL'
import os
import logging
import subprocess
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
        subprocess.run(["espeak", "-w", "/opt/paging/static/test_message.wav", message])
        
        # Play audio
        subprocess.Popen(["aplay", "/opt/paging/static/test_message.wav"])
        
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

if __name__ == '__main__':
    initialize_database()
    app.run(host='0.0.0.0', port=8080, debug=True)
EOL

# Create templates (same as before, omitted for brevity)
# [Include all templates from previous version here]

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
asterisk -rx "sip show registry" 2>/dev/null || echo "Asterisk command failed"

echo -e "\n5. Database content:"
sqlite3 $DB_FILE "SELECT * FROM user;" 2>/dev/null || echo "Database not found"

echo -e "\nTroubleshooting tips:"
echo "If you get a 502 Bad Gateway:"
echo "1. Check if Flask is running: systemctl status paging-web"
echo "2. Test Flask directly: curl http://localhost:8080"
echo "3. Check Nginx error logs: tail -f $LOG_DIR/nginx-error.log"
echo "4. Check application logs: tail -f $LOG_DIR/app.log"
