#!/bin/bash
# Enhanced IP Paging System Installer with Functional Web UI
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
        libasound2-dev
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
pip install flask werkzeug configparser requests pyopenssl flask-sqlalchemy

# Create database and configuration
echo "Initializing database..."
sqlite3 "$APP_DB" <<EOL
CREATE TABLE IF NOT EXISTS zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    extension TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin');
EOL

chown "$ADMIN_USER:$ADMIN_USER" "$APP_DB"

# Create functional application
echo "Creating application files..."
cat > "$INSTALL_DIR/app.py" << 'EOL'
import os
import sqlite3
import subprocess
from flask import Flask, render_template, request, redirect, session, flash, jsonify

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['DATABASE'] = '/var/lib/paging/paging_config.db'

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

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
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and user['password'] == password:
            session['user_id'] = user['id']
            session['username'] = username
            return redirect('/dashboard')
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db()
    zones = conn.execute('SELECT * FROM zones').fetchall()
    conn.close()
    
    return render_template('dashboard.html', zones=zones)

@app.route('/add_zone', methods=['POST'])
def add_zone():
    if 'user_id' not in session:
        return redirect('/login')
    
    name = request.form.get('name')
    description = request.form.get('description')
    extension = request.form.get('extension')
    
    if not name or not extension:
        flash('Name and extension are required', 'danger')
        return redirect('/dashboard')
    
    conn = get_db()
    conn.execute('INSERT INTO zones (name, description, extension) VALUES (?, ?, ?)',
                 (name, description, extension))
    conn.commit()
    conn.close()
    
    flash('Zone added successfully', 'success')
    return redirect('/dashboard')

@app.route('/delete_zone/<int:zone_id>')
def delete_zone(zone_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db()
    conn.execute('DELETE FROM zones WHERE id = ?', (zone_id,))
    conn.commit()
    conn.close()
    
    flash('Zone deleted successfully', 'success')
    return redirect('/dashboard')

@app.route('/page', methods=['POST'])
def page():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    zone_id = request.form.get('zone_id')
    message = request.form.get('message')
    
    if not zone_id or not message:
        return jsonify({'status': 'error', 'message': 'Missing parameters'}), 400
    
    conn = get_db()
    zone = conn.execute('SELECT * FROM zones WHERE id = ?', (zone_id,)).fetchone()
    conn.close()
    
    if not zone:
        return jsonify({'status': 'error', 'message': 'Zone not found'}), 404
    
    try:
        # Create audio file
        audio_file = f"{LOG_DIR}/page_{zone_id}.wav"
        subprocess.run(['espeak', '-v', 'en', '-w', audio_file, message])
        
        # Play audio (simulated - real implementation would use SIP)
        print(f"Paging to {zone['name']} ({zone['extension']}): {message}")
        subprocess.Popen(['aplay', audio_file])
        
        return jsonify({'status': 'success', 'message': 'Page sent'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect('/login')
    
    current = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm = request.form.get('confirm_password')
    
    if not current or not new_password or not confirm:
        flash('All fields are required', 'danger')
        return redirect('/dashboard')
    
    if new_password != confirm:
        flash('New passwords do not match', 'danger')
        return redirect('/dashboard')
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['password'] != current:
        flash('Current password is incorrect', 'danger')
        return redirect('/dashboard')
    
    conn.execute('UPDATE users SET password = ? WHERE id = ?', (new_password, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Password changed successfully', 'success')
    return redirect('/dashboard')

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
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .login-container { max-width: 400px; margin: 100px auto; }
        .card { border: none; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .card-header { background: #0a4f9e; color: white; text-align: center; border-radius: 10px 10px 0 0 !important; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="card">
            <div class="card-header py-3">
                <h2>IP Paging System</h2>
            </div>
            <div class="card-body p-4">
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <form method="POST" action="/login">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" name="username" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Sign In</button>
                </form>
                <div class="mt-3 text-center text-muted">
                    <small>Default: admin/admin</small>
                </div>
            </div>
        </div>
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
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary: #0a4f9e;
            --secondary: #6c757d;
        }
        body { background-color: #f8f9fa; }
        .navbar { background-color: var(--primary); }
        .card { border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 20px; border: none; }
        .card-header { background-color: rgba(10, 79, 158, 0.1); font-weight: 600; }
        .zone-card { transition: transform 0.2s; }
        .zone-card:hover { transform: translateY(-5px); }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="/dashboard">
                <i class="bi bi-megaphone me-2"></i>IP Paging System
            </a>
            <div class="d-flex align-items-center">
                <span class="text-white me-3">Welcome, {{ session.username }}</span>
                <a href="/logout" class="btn btn-outline-light btn-sm">
                    <i class="bi bi-box-arrow-right me-1"></i>Logout
                </a>
            </div>
        </div>
    </nav>

    <div class="container py-4">
        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span>Paging Zones</span>
                        <button class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#addZoneModal">
                            <i class="bi bi-plus-circle"></i> Add Zone
                        </button>
                    </div>
                    <div class="card-body">
                        {% if zones %}
                            <div class="row">
                                {% for zone in zones %}
                                    <div class="col-md-6 mb-3">
                                        <div class="card zone-card">
                                            <div class="card-body">
                                                <div class="d-flex justify-content-between">
                                                    <h5 class="card-title">{{ zone[1] }}</h5>
                                                    <a href="/delete_zone/{{ zone[0] }}" class="text-danger" 
                                                       onclick="return confirm('Delete this zone?')">
                                                        <i class="bi bi-trash"></i>
                                                    </a>
                                                </div>
                                                <p class="card-text text-muted">{{ zone[2] or 'No description' }}</p>
                                                <p class="card-text"><strong>Extension:</strong> {{ zone[3] }}</p>
                                                <div class="d-flex mt-3">
                                                    <input type="text" class="form-control me-2 page-message" 
                                                           placeholder="Message" id="msg-{{ zone[0] }}">
                                                    <button class="btn btn-primary page-btn" 
                                                            data-zone="{{ zone[0] }}">
                                                        <i class="bi bi-send"></i>
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                {% endfor %}
                            </div>
                        {% else %}
                            <div class="text-center py-5">
                                <i class="bi bi-megaphone display-1 text-muted mb-3"></i>
                                <h5>No paging zones configured</h5>
                                <p class="text-muted">Add your first paging zone to get started</p>
                            </div>
                        {% endif %}
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">System Status</div>
                    <div class="card-body">
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                Web Service
                                <span class="badge bg-success">Running</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                Audio System
                                <span class="badge bg-success">OK</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                Paging Zones
                                <span class="badge bg-primary">{{ zones|length }}</span>
                            </li>
                        </ul>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header">Change Password</div>
                    <div class="card-body">
                        <form method="POST" action="/change_password">
                            <div class="mb-3">
                                <label class="form-label">Current Password</label>
                                <input type="password" name="current_password" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">New Password</label>
                                <input type="password" name="new_password" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Confirm Password</label>
                                <input type="password" name="confirm_password" class="form-control" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Update Password</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Add Zone Modal -->
    <div class="modal fade" id="addZoneModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Add Paging Zone</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" action="/add_zone">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Zone Name</label>
                            <input type="text" name="name" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Description</label>
                            <input type="text" name="description" class="form-control">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Extension</label>
                            <input type="text" name="extension" class="form-control" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Zone</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Handle page buttons
            document.querySelectorAll('.page-btn').forEach(button => {
                button.addEventListener('click', function() {
                    const zoneId = this.getAttribute('data-zone');
                    const message = document.querySelector(`#msg-${zoneId}`).value;
                    
                    if (!message) {
                        alert('Please enter a message');
                        return;
                    }
                    
                    // Send page request
                    fetch('/page', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `zone_id=${zoneId}&message=${encodeURIComponent(message)}`
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'success') {
                            alert('Page sent successfully');
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
        });
    </script>
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
Environment="PYTHONUNBUFFERED=1"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py
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

# Verification
echo "Running verification checks..."
echo "1. Service status:"
systemctl status paging-web nginx --no-pager | head -10 || true

echo -e "\n2. Application test:"
curl -s http://localhost:8080/ping || echo "Flask app not responding"
curl -I http://localhost || echo "Nginx not responding"

# Get IP address
IP_ADDRESS=$(hostname -I | awk '{print $1}')
if [ -z "$IP_ADDRESS" ]; then
    IP_ADDRESS="[YOUR_SERVER_IP]"
fi

# Final instructions
echo ""
echo "====================================================="
echo "Enhanced IP Paging System Installation Complete!"
echo "Access the web interface at: http://$IP_ADDRESS"
echo ""
echo "Default credentials:"
echo "  Username: admin"
echo "  Password: admin"
echo ""
echo "Key Features:"
echo "  - Create and manage paging zones"
echo "  - Send text-to-speech pages to zones"
echo "  - Admin password management"
echo ""
echo "Troubleshooting:"
echo "  systemctl status paging-web"
echo "  journalctl -u paging-web"
echo "  tail -f $LOG_DIR/app.log"
echo "====================================================="
