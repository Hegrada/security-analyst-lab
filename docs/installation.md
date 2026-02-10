# 📦 Installation Guide

This guide covers the installation and setup of the Security Audit Lab.

## Prerequisites

### Required Software
- **Python 3.8+** (Python 3.10 recommended)
- **Docker** and **Docker Compose**
- **Git**
- **4GB RAM** minimum (8GB recommended)
- **10GB disk space** minimum

### Install Python Dependencies

```bash
# Clone the repository
git clone https://github.com/hegrada/security-analyst-lab.git
cd security-analyst-lab

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Linux/Mac:
source venv/bin/activate
# Windows:
.\venv\Scripts\activate

# Install core dependencies
pip install -r requirements.txt

# Install audit tools dependencies
pip install -r audit-tools/requirements.txt

# Install dashboard dependencies
pip install -r dashboard/requirements.txt
```

### Install Docker Services

```bash
# Install Docker (Ubuntu)
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Add user to docker group (Linux)
sudo usermod -aG docker $USER
```

## Initial Setup

### 1. Setup Vulnerable Environment

```bash
cd vulnerable-apps

# Start all vulnerable services
docker-compose up -d

# Verify services are running
docker-compose ps
```

Expected output:
```
NAME         IMAGE           COMMAND              SERVICE    CREATED   STATUS    PORTS
vuln-webapp  app-webapp     "python app.py"     webapp     ...       Up        0.0.0.0:8080->5000/tcp
vuln-db      mysql:5.7      "docker-entrypoint"  db         ...       Up        0.0.0.0:3306->3306/tcp
vuln-api     app-api        "python app.py"     api        ...       Up        0.0.0.0:5000->5000/tcp
```

### 2. Initialize Dashboard Database

```bash
cd dashboard
python app.py
```

The database will be automatically initialized with sample data.

### 3. Test the Tools

```bash
# Test port scanner
cd audit-tools
python port_scanner.py -t localhost -p 1-100

# Test vulnerability scanner
python vuln_scanner.py -t http://localhost:8080

# Test log analyzer (create a sample log first)
mkdir -p test_logs
echo "Jan 01 12:00:00 server sshd[123]: Failed password for root from 192.168.1.1" > test_logs/auth.log
python log_analyzer.py -d test_logs/
```

## Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Flask Dashboard
SECRET_KEY=your-secret-key-here
DASHBOARD_PORT=5000

# Docker
DOCKER_NETWORK=vulnnet

# Logging
LOG_LEVEL=INFO
```

### Custom Settings

Edit `config/settings.yaml` to customize:
- Port scanner threads and timeout
- Vulnerability scanner options
- Dashboard settings
- Docker configurations

## Verification Checklist

After installation, verify everything works:

- [ ] Docker services are running (`docker-compose ps`)
- [ ] Web app accessible at http://localhost:8080
- [ ] Database accessible on port 3306
- [ ] API accessible at http://localhost:5000
- [ ] Dashboard accessible at http://localhost:5000
- [ ] Port scanner works (`python port_scanner.py -t localhost`)
- [ ] Vulnerability scanner works (`python vuln_scanner.py -t http://localhost:8080`)
- [ ] Report generator works (`python report_generator.py -i sample.json`)

## Troubleshooting

### Docker Issues

```bash
# Check Docker status
sudo systemctl status docker

# Restart Docker
sudo systemctl restart docker

# View container logs
docker-compose logs

# Rebuild containers
docker-compose down
docker-compose up -d --build
```

### Python Environment Issues

```bash
# Recreate virtual environment
rm -rf venv
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Port Conflicts

If ports are already in use, modify `vulnerable-apps/docker-compose.yml` or run services on different ports.

## Next Steps

1. Read the [Usage Guide](docs/usage.md)
2. Review [Vulnerabilities Reference](docs/vulnerabilities.md)
3. Start testing with the vulnerable applications
4. Run security scans and generate reports
