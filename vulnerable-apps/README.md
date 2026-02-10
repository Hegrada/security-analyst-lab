# 🎯 Vulnerable Applications

This directory contains intentionally vulnerable applications for security testing and training purposes. **FOR EDUCATIONAL USE ONLY**.

## ⚠️ Warning

These applications contain **intentional security vulnerabilities** for testing security tools and practicing penetration testing techniques. **Never deploy these in production environments**.

## 🐳 Available Services

| Service | Port | Description | Vulnerabilities |
|---------|------|-------------|-----------------|
| Web App | 8080 | OWASP Top 10 vulnerable web app | SQLi, XSS, CSRF, IDOR |
| Database | 3306 | MySQL with weak credentials | Weak passwords, plain text |
| API | 5000 | REST API with security flaws | Broken auth, IDOR |
| FTP | 2121 | Unsecured FTP server | Anonymous access |
| SSH | 2222 | SSH with weak auth | Weak credentials |

## 🚀 Quick Start

```bash
# Start all vulnerable services
docker-compose up -d

# Verify services are running
docker-compose ps

# Access the vulnerable web app
curl http://localhost:8080

# Connect to database
mysql -h localhost -P 3306 -u root -ptoor

# Connect to SSH
ssh root@localhost -p 2222
# Password: toor
```

## 📁 Structure

```
vulnerable-apps/
├── docker-compose.yml      # Main Docker Compose configuration
├── web-app/               # Vulnerable web application
│   ├── Dockerfile
│   ├── app.py             # Flask application with vulnerabilities
│   └── requirements.txt
├── database/              # Vulnerable database configuration
│   └── my.cnf
├── api/                   # Vulnerable REST API
│   ├── Dockerfile
│   └── app.py
├── ftp/                   # Vulnerable FTP server
│   └── vsftpd.conf
└── ssh/                   # Vulnerable SSH configuration
    └── Dockerfile
```

## 🔐 Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| MySQL | root | toor |
| FTP | anonymous | (none) |
| SSH | root | toor |

## 🛠️ Individual Service Startup

```bash
# Start only the web app
cd web-app && docker build -t vuln-webapp . && docker run -p 8080:5000 vuln-webapp

# Start only the database
docker run -d --name vuln-db -p 3306:3306 -e MYSQL_ROOT_PASSWORD=toor mysql:5.7

# Start only the API
cd api && docker build -t vuln-api . && docker run -p 5000:5000 vuln-api
```

## 🧪 Testing with Tools

```bash
# Port scan
cd ../audit-tools
python port_scanner.py -t localhost -p 1-10000

# Vulnerability scan
python vuln_scanner.py -t http://localhost:8080

# SQL injection test
python sql_injection_tester.py -u "http://localhost:8080/api/users?id=1"

# Log analysis (capture logs first)
cp /var/log/auth.log ./test_logs/ 2>/dev/null || true
python log_analyzer.py -d ./test_logs/
```

## 🧹 Cleanup

```bash
# Stop all services
docker-compose down

# Remove all images
docker-compose down --rmi all

# Remove volumes (database data)
docker-compose down -v
```

## 📝 Legal Notice

**This software is provided for educational and security testing purposes only.** Use these vulnerable applications only on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.

---

**Use at your own risk!**
