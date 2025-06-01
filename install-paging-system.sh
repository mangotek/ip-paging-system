#!/bin/bash
# Enhanced IP Paging System Installer with SIP Permission Fix and Improved Compatibility
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
    build-essential libssl-dev libffi-dev ufw asterisk espeak sudo

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
import shutil
import tempfile

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
        
        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as sip_temp, \
             tempfile.NamedTemporaryFile(mode='w', delete=False) as ext_temp:
            
            # SIP configuration
            sip_temp.write(f"""[general]
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
""")
            
            # Extensions configuration
            ext_temp.write(f"""[page]
exten => s,1,Answer()
same => n,Playback(/opt/paging/static/test_message.wav)
same => n,Hangup()
""")
            
            sip_temp_path = sip_temp.name
            ext_temp_path = ext_temp.name
        
        # Move files with sudo to preserve permissions
        subprocess.run(["sudo", "mv", sip_temp_path, "/etc/asterisk/sip.conf"])
        subprocess.run(["sudo", "mv", ext_temp_path, "/etc/asterisk/extensions.conf"])
        
        # Set correct permissions
        subprocess.run(["sudo", "chown", "asterisk:asterisk", "/etc/asterisk/sip.conf"])
        subprocess.run(["sudo", "chown", "asterisk:asterisk", "/etc/asterisk/extensions.conf"])
        subprocess.run(["sudo", "chmod", "644", "/etc/asterisk/sip.conf"])
        subprocess.run(["sudo", "chmod", "644", "/etc/asterisk/extensions.conf"])
        
        # Reload Asterisk
        subprocess.run(["sudo", "asterisk", "-rx", "reload"])
        log_audit(1, 'asterisk_reconfigured')
        return True, "Asterisk config updated"
    except Exception as e:
        return False, str(e)

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

# ... [Rest of the routes remain the same] ...

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
            test_zone = Zone(name="Main Zone", description="Primary paging zone", sip_targets="1001,1002")
            db.session.add(test_zone)
            db.session.commit()
            print("Created test paging zone")

if __name__ == '__main__':
    initialize_database()
    app.run(host='0.0.0.0', port=8080, debug=True)
EOL

# Create templates (same as before, no changes needed)

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
ufw allow 5060:5090/udp  # Wider port range for SIP
ufw allow 10000:20000/udp  # RTP port range
ufw --force enable

# Configure sudo for Asterisk config
echo "Configuring sudo permissions..."
cat > /etc/sudoers.d/paging-admin << EOL
$ADMIN_USER ALL=(root) NOPASSWD: /bin/mv /tmp/tmp* /etc/asterisk/sip.conf
$ADMIN_USER ALL=(root) NOPASSWD: /bin/mv /tmp/tmp* /etc/asterisk/extensions.conf
$ADMIN_USER ALL=(root) NOPASSWD: /bin/chown asterisk\:asterisk /etc/asterisk/sip.conf
$ADMIN_USER ALL=(root) NOPASSWD: /bin/chown asterisk\:asterisk /etc/asterisk/extensions.conf
$ADMIN_USER ALL=(root) NOPASSWD: /bin/chmod 644 /etc/asterisk/sip.conf
$ADMIN_USER ALL=(root) NOPASSWD: /bin/chmod 644 /etc/asterisk/extensions.conf
$ADMIN_USER ALL=(root) NOPASSWD: /usr/sbin/asterisk -rx *
EOL

# Configure Asterisk with enhanced settings
echo "Configuring Asterisk with enhanced settings..."
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
; Enhanced compatibility settings
directmedia=no
encryption=no
insecure=port,invite
nat=force_rport,comedia
session-timers=refuse
canreinvite=no
dtmfmode=rfc2833
; 3CX specific settings
qualify=yes
qualifyfreq=30
registertimeout=20
registerattempts=0
; Improved NAT handling
localnet=192.168.0.0/255.255.0.0
localnet=172.16.0.0/255.240.0.0
localnet=10.0.0.0/255.0.0.0
externip=auto

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
qualify=yes
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

# Allow Asterisk to bind to ports
echo "Configuring system for Asterisk..."
setcap 'cap_net_bind_service=+ep' /usr/sbin/asterisk

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
echo "Important Next Steps for 3CX:"
echo "1. In SIP settings:"
echo "   - Use the extension as the authentication ID"
echo "   - Set transport to UDP/TCP"
echo "   - Disable encryption"
echo "   - Use port 5060"
echo "2. In 3CX admin console:"
echo "   - Create SIP trunk with credentials from this system"
echo "   - Set 'Destination: IP Address' to this server's IP: $IP_ADDRESS"
echo "   - Enable 'Allow SIP Trunk to register with 3CX'"
echo "   - Add outbound rule for paging extensions"
echo "3. Test registration in Asterisk:"
echo "   sudo asterisk -rx 'sip show registry'"
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

echo -e "\n5. Sudo permissions:"
sudo -l -U $ADMIN_USER

echo -e "\n6. Port listeners:"
netstat -tuln | grep -E ':(5060|80)'

echo -e "\nTroubleshooting tips:"
echo "If SIP registration fails:"
echo "1. Check 3CX SIP trunk configuration"
echo "2. Verify firewall allows traffic on ports 5060 and RTP range (10000-20000)"
echo "3. Check Asterisk logs: /var/log/asterisk/messages"
echo "4. Test connectivity: nc -vzu $IP_ADDRESS 5060"
echo "5. Review sudo permissions for $ADMIN_USER"
