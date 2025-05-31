#!/bin/bash
# Robust IP Paging System Installer for x86
# Tested on Ubuntu 22.04

# Configuration
ADMIN_USER="pagingadmin"
INSTALL_DIR="/opt/paging"
DB_DIR="/var/lib/paging"
LOG_DIR="/var/log/paging"
NGINX_DIR="/etc/nginx/sites-available"
SERVICE_FILE="/etc/systemd/system/paging-web.service"
APP_DB="$DB_DIR/paging_config.db"

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
mkdir -p "$INSTALL_DIR" "$DB_DIR" "$LOG_DIR"
chmod 755 "$INSTALL_DIR" "$DB_DIR" "$LOG_DIR"

# Create system user
if ! id "$ADMIN_USER" &>/dev/null; then
    echo "Creating system user: $ADMIN_USER"
    useradd -r -s /usr/sbin/nologin "$ADMIN_USER"
fi
chown -R "$ADMIN_USER:$ADMIN_USER" "$INSTALL_DIR" "$DB_DIR" "$LOG_DIR"

# Install dependencies with error handling
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
        net-tools
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
pip install flask werkzeug configparser requests pyopenssl

# Create minimal application
echo "Creating application files..."
cat > "$INSTALL_DIR/app.py" << 'EOL'
import os
from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Simple test route
@app.route('/ping')
def ping():
    return "pong"

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hardcoded credentials for test
        if username == "admin" and password == "admin":
            session['user_id'] = 1
            session['username'] = username
            return redirect('/dashboard')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
EOL

# Create templates
echo "Creating templates..."
mkdir -p "$INSTALL_DIR/templates"

# Login template
cat > "$INSTALL_DIR/templates/login.html" << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .login-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 300px; }
        .form-group { margin-bottom: 1rem; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; box-sizing: border-box; }
        .btn { background: #0a4f9e; color: white; border: none; padding: 10px; width: 100%; cursor: pointer; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2 style="text-align: center; color: #0a4f9e;">Paging System</h2>
        <form method="POST" action="/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn">Sign In</button>
        </form>
        <p style="text-align: center; margin-top: 1rem; font-size: 0.9rem; color: #666;">
            Default: admin/admin
        </p>
    </div>
</body>
</html>
EOL

# Dashboard template
cat > "$INSTALL_DIR/templates/dashboard.html" << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; }
        .header { background: #0a4f9e; color: white; padding: 1rem; text-align: center; }
        .container { padding: 2rem; max-width: 1200px; margin: 0 auto; }
        .card { background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 1.5rem; }
        .status-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Paging Control System</h1>
        <p>Welcome, admin!</p>
    </div>
    
    <div class="container">
        <div class="status-cards">
            <div class="card">
                <h3>System Status</h3>
                <p>All services operational</p>
            </div>
            <div class="card">
                <h3>Paging Zones</h3>
                <p>0 zones configured</p>
            </div>
            <div class="card">
                <h3>Network</h3>
                <p>Online</p>
            </div>
        </div>
        
        <div class="card">
            <h3>Getting Started</h3>
            <ol>
                <li>Change the default admin password</li>
                <li>Configure SIP settings</li>
                <li>Create paging zones</li>
                <li>Test your audio output</li>
            </ol>
        </div>
    </div>
</body>
</html>
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
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOL

# Create Nginx configuration
echo "Configuring Nginx..."
cat > "$NGINX_DIR/paging" << EOL
# Simple Nginx configuration
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

# Start services
echo "Starting services..."
systemctl daemon-reload
systemctl enable paging-web
systemctl start paging-web
systemctl restart nginx

# Wait for services to start
echo "Waiting for services to initialize..."
sleep 5

# Verification steps
echo "Running verification checks..."
echo "1. Service status:"
systemctl status paging-web nginx asterisk --no-pager | head -10 || true

echo -e "\n2. Port check:"
echo "Port 80:"
netstat -tulpn | grep ':80' || echo "Port 80 not found"
echo -e "\nPort 8080:"
netstat -tulpn | grep ':8080' || echo "Port 8080 not found"

echo -e "\n3. Application test:"
curl -s http://localhost:8080/ping || echo "Flask app not responding"
curl -I http://localhost || echo "Nginx not responding"

echo -e "\n4. Log files:"
echo "Application logs:"
tail -n 5 "$LOG_DIR/app.log" 2>/dev/null || echo "No application logs found"
echo -e "\nNginx error logs:"
tail -n 5 "$LOG_DIR/nginx-error.log" 2>/dev/null || echo "No Nginx error logs found"

# Get IP address
IP_ADDRESS=$(hostname -I | awk '{print $1}')
if [ -z "$IP_ADDRESS" ]; then
    IP_ADDRESS="[YOUR_SERVER_IP]"
fi

# Final instructions
echo ""
echo "====================================================="
echo "Installation complete!"
echo "Access the web interface at: http://$IP_ADDRESS"
echo ""
echo "Default credentials:"
echo "  Username: admin"
echo "  Password: admin"
echo ""
echo "Troubleshooting:"
echo "1. Check service status: systemctl status paging-web nginx"
echo "2. View application logs: tail -f $LOG_DIR/app.log"
echo "3. View Nginx logs: tail -f $LOG_DIR/nginx-*.log"
echo "4. Test Flask directly: curl http://localhost:8080/ping"
echo "5. Test Nginx: curl -I http://localhost"
echo "====================================================="
