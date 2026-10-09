# VaultShare — Deployment Guide

## Project Structure

```
vaultshare/
├── public/                   # Static web files (served to users)
│   ├── index.html            # Main application HTML
│   ├── css/
│   │   └── style.css         # All styles and animations
│   └── js/
│       ├── crypto.js         # Cryptographic engine (Web Crypto API)
│       ├── ui.js             # DOM helpers, drag-drop, toast, progress
│       └── app.js            # Application controller (ties UI + crypto)
├── tests/
│   └── crypto.test.js        # Unit tests for all crypto functions
├── deploy/
│   ├── Dockerfile            # Production Docker image
│   ├── docker-compose.yml    # Multi-container orchestration
│   └── nginx.conf            # Production Nginx config with TLS
├── server.js                 # Express.js static server
├── package.json
└── DEPLOYMENT.md             # This file
```

---

## Option 1: Run Locally (Development)

No build step needed. Open `public/index.html` directly in a modern browser, or serve it:

```bash
# Clone / download the project
cd vaultshare

# Install dependencies (only needed for server.js)
npm install

# Start development server
node server.js
# → http://localhost:3000
```

Browser requirements: Chrome 60+, Firefox 75+, Safari 13+, Edge 79+

---

## Option 2: Deploy to a VPS / Cloud VM (Ubuntu 22.04)

### Step 1 — Provision a Server

Minimum specs: 1 vCPU · 512 MB RAM · 10 GB SSD
Recommended providers: DigitalOcean, Hetzner, Linode, AWS EC2 t3.micro

```bash
# SSH into your new server
ssh root@YOUR_SERVER_IP
```

### Step 2 — Install Node.js 18

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs
node --version   # should show v18.x.x
```

### Step 3 — Install Nginx

```bash
apt-get install -y nginx certbot python3-certbot-nginx
systemctl enable nginx
```

### Step 4 — Upload the Project

```bash
# From your local machine:
scp -r vaultshare/ root@YOUR_SERVER_IP:/var/www/vaultshare

# Back on the server:
cd /var/www/vaultshare
npm install --omit=dev
```

### Step 5 — Configure DNS

In your domain registrar's DNS panel, add an **A record**:

```
Type  : A
Name  : @   (or subdomain, e.g. vault)
Value : YOUR_SERVER_IP
TTL   : 300
```

Wait 5–10 minutes for propagation, then verify:

```bash
dig +short yourdomain.com
# Should return YOUR_SERVER_IP
```

### Step 6 — Obtain a Free TLS Certificate (Let's Encrypt)

```bash
certbot --nginx -d yourdomain.com -d www.yourdomain.com \
        --email you@example.com --agree-tos --no-eff-email

# Verify auto-renewal
certbot renew --dry-run
```

### Step 7 — Install Nginx Config

```bash
cp /var/www/vaultshare/deploy/nginx.conf /etc/nginx/nginx.conf

# Edit the two occurrences of "yourdomain.com"
nano /etc/nginx/nginx.conf

# Test and reload
nginx -t
systemctl reload nginx
```

### Step 8 — Run with PM2 (Process Manager)

```bash
npm install -g pm2

cd /var/www/vaultshare
pm2 start server.js --name vaultshare

# Auto-start on reboot
pm2 startup systemd
pm2 save

# Useful commands
pm2 status
pm2 logs vaultshare
pm2 restart vaultshare
```

### Step 9 — Configure Firewall

```bash
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
ufw status
```

### Step 10 — Verify Deployment

```bash
# Health check
curl -s https://yourdomain.com/health | python3 -m json.tool

# TLS grade (from browser or https://www.ssllabs.com/ssltest/)
# Target: A or A+
```

---

## Option 3: Docker Deployment

### Prerequisites

```bash
apt-get install -y docker.io docker-compose-plugin
systemctl enable --now docker
```

### Build and Run

```bash
cd /var/www/vaultshare

# Build the image
docker build -f deploy/Dockerfile -t vaultshare:latest .

# Start with Compose
docker compose -f deploy/docker-compose.yml up -d

# Check logs
docker compose -f deploy/docker-compose.yml logs -f

# Health check
docker ps   # should show STATUS: healthy
curl http://localhost:3000/health
```

### Update the App

```bash
docker compose -f deploy/docker-compose.yml down
git pull origin main   # or re-upload files
docker build -f deploy/Dockerfile -t vaultshare:latest .
docker compose -f deploy/docker-compose.yml up -d
```

---

## Option 4: Deploy to Netlify / Vercel (Instant, Free)

VaultShare is a fully static app — the Node.js server is optional. You can host the `public/` folder on any CDN.

### Netlify

```bash
npm install -g netlify-cli
cd vaultshare
netlify deploy --dir=public --prod
# Follow prompts — done in ~30 seconds
```

Or drag-and-drop the `public/` folder at https://app.netlify.com

### Vercel

```bash
npm install -g vercel
cd vaultshare
vercel --prod
# Point root to public/ when prompted
```

---

## Option 5: GitHub Pages (Free, Static)

1. Push the project to a GitHub repository
2. Go to **Settings → Pages**
3. Set **Source** → Deploy from a branch → `main` → `/public`
4. Your site is live at `https://USERNAME.github.io/REPO/`

---

## Running Tests

```bash
cd vaultshare
node --experimental-vm-modules tests/crypto.test.js
```

Expected output:
```
══════════════════════════════════════
  VaultShare Cryptographic Test Suite
══════════════════════════════════════

SHA-256 Hash
  ✅  empty buffer produces known hash
  ✅  same input always gives same hash
  ✅  different inputs give different hashes

Key Derivation (PBKDF2)
  ✅  derives a key without throwing
  ✅  same password + salt = same key (deterministic)
  ✅  different passwords produce different keys

AES-256-GCM Round-Trip
  ✅  short text encrypts and decrypts correctly
  ✅  unicode text round-trips correctly
  ✅  1 KB of random data round-trips
  ✅  GCM detects tampering (authentication tag)

...

══════════════════════════════════════
  Results: 16 passed, 0 failed
══════════════════════════════════════
```

---

## Environment Variables

| Variable    | Default       | Description                          |
|-------------|---------------|--------------------------------------|
| `PORT`      | `3000`        | TCP port the Node server listens on  |
| `NODE_ENV`  | `development` | Set to `production` for live servers |

---

## Browser Compatibility

| Browser | Min Version | Notes                        |
|---------|-------------|------------------------------|
| Chrome  | 60+         | Full support                 |
| Firefox | 75+         | Full support                 |
| Safari  | 13+         | Full support                 |
| Edge    | 79+         | Full support (Chromium-based)|
| IE      | ❌           | Web Crypto API not supported |

---

## Security Checklist

- [ ] HTTPS enabled with a valid certificate
- [ ] HTTP → HTTPS redirect in place
- [ ] HSTS header with `max-age=63072000; includeSubDomains; preload`
- [ ] Content-Security-Policy header blocks inline scripts
- [ ] `connect-src 'none'` prevents any external network calls
- [ ] `X-Content-Type-Options: nosniff` header set
- [ ] `X-Frame-Options: DENY` prevents clickjacking
- [ ] Server tokens (`Server:` header) removed / obfuscated
- [ ] Running as non-root user (Docker image: uid 1001)
- [ ] Firewall: only 22, 80, 443 open
- [ ] TLS 1.2/1.3 only (no TLS 1.0/1.1)
- [ ] Auto-renewal configured for TLS certificate
- [ ] PM2 or Docker restart policy ensures uptime after reboots

---

## Troubleshooting

**Port 3000 already in use**
```bash
lsof -ti:3000 | xargs kill -9
node server.js
```

**Nginx 502 Bad Gateway**
```bash
pm2 status          # is the Node process running?
pm2 restart vaultshare
nginx -t            # test config for syntax errors
journalctl -u nginx --no-pager -n 50
```

**Certificate issues**
```bash
certbot certificates             # list current certs
certbot renew --force-renewal   # force renewal
```

**Permissions error on /var/www**
```bash
chown -R www-data:www-data /var/www/vaultshare
chmod -R 755 /var/www/vaultshare
```
