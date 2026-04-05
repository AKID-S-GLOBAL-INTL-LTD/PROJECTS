#!/bin/bash
# ============================================================
#  AKID's Recon Automation Tool — Setup Script
#  Ubuntu 24.04 LTS (EC2)
# ============================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; exit 1; }

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║    AKID's Recon Automation Tool - Setup          ║${NC}"
echo -e "${CYAN}║    Akids Global CyberSecurity Tools © 2026       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"

# ── 1. System packages ────────────────────────────────────────
log "Updating system packages..."
sudo apt-get update -qq
sudo apt-get install -y python3 python3-pip python3-venv nginx curl git jq

# ── 2. Python virtual environment ────────────────────────────
log "Setting up Python virtual environment..."
cd "$BACKEND_DIR"
python3 -m venv venv
source venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
ok "Python dependencies installed"

# ── 3. Environment file ───────────────────────────────────────
if [ ! -f "$BACKEND_DIR/.env" ]; then
  log "Creating .env file with random secrets..."
  JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  APP_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  cat > "$BACKEND_DIR/.env" <<EOF
SECRET_KEY=$APP_SECRET
JWT_SECRET_KEY=$JWT_SECRET
DATABASE_URL=sqlite:///akid_recon.db
FLASK_ENV=production
EOF
  ok ".env file created"
else
  warn ".env already exists, skipping"
fi

# ── 4. Initialize database ────────────────────────────────────
log "Initializing database..."
cd "$BACKEND_DIR"
source venv/bin/activate
python3 -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('[+] Database tables created')
"
ok "Database initialized"

# ── 5. Systemd service ────────────────────────────────────────
log "Installing systemd service..."
sudo tee /etc/systemd/system/akid-recon.service > /dev/null <<EOF
[Unit]
Description=AKID Recon Automation Tool
After=network.target

[Service]
Type=exec
User=$USER
WorkingDirectory=$BACKEND_DIR
Environment=PATH=$BACKEND_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin
EnvironmentFile=$BACKEND_DIR/.env
ExecStart=$BACKEND_DIR/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable akid-recon
sudo systemctl start akid-recon
ok "Systemd service installed and started"

# ── 6. Nginx configuration ────────────────────────────────────
log "Configuring Nginx..."
sudo tee /etc/nginx/sites-available/akid-recon > /dev/null <<EOF
server {
    listen 80;
    server_name _;

    # Serve static frontend files
    root $FRONTEND_DIR;
    index index.html;

    # API proxy to Flask/Gunicorn
    location /api/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Serve frontend pages
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";

    # Gzip
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
}
EOF

sudo ln -sf /etc/nginx/sites-available/akid-recon /etc/nginx/sites-enabled/akid-recon
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
ok "Nginx configured"

# ── 7. Final status ───────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✓  AKID Recon Tool is now running!                 ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║   URL:   http://$(hostname -I | awk '{print $1}')                      ${NC}"
echo -e "${GREEN}║   API:   http://$(hostname -I | awk '{print $1}')/api/                 ${NC}"
echo -e "${GREEN}║                                                      ║${NC}"
echo -e "${GREEN}║   Service:  sudo systemctl status akid-recon         ║${NC}"
echo -e "${GREEN}║   Logs:     sudo journalctl -u akid-recon -f         ║${NC}"
echo -e "${GREEN}║   Restart:  sudo systemctl restart akid-recon        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
warn "For HTTPS: sudo certbot --nginx -d your-domain.com"
echo ""
