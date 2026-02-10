# 📊 Security Audit Dashboard

Flask-based web dashboard for visualizing security scan results and monitoring vulnerabilities.

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start the dashboard
python app.py

# Access at http://localhost:5000
```

## 📁 Structure

```
dashboard/
├── app.py              # Flask application
├── requirements.txt    # Python dependencies
├── static/            # CSS, JavaScript, images
│   └── css/
│       └── style.css
└── templates/         # HTML templates
    ├── base.html
    ├── index.html
    ├── scan_results.html
    └── vulnerabilities.html
```

## 🛠️ Features

- **Dashboard Overview**: Summary of all security scans
- **Vulnerability Tracking**: Track vulnerabilities by severity
- **Scan History**: Timeline of all scans performed
- **Report Generation**: Export detailed security reports
- **Real-time Updates**: Auto-refresh for live monitoring

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scans` | GET | List all scans |
| `/api/scan/<id>` | GET | Get scan details |
| `/api/vulnerabilities` | GET | List vulnerabilities |
| `/api/vulnerabilities/<severity>` | GET | Filter by severity |
| `/api/report/<scan_id>` | GET | Generate report |

## 🧪 Testing

```bash
# Run the dashboard
python app.py --debug

# Run with custom port
python app.py --port 8080
```

## 🔧 Configuration

Set environment variables:
- `SECRET_KEY`: Flask secret key
- `DATABASE_URL`: SQLite database URL (default: `scans.db`)
- `DEBUG`: Enable debug mode (default: False)

```bash
export SECRET_KEY="your-secret-key"
export DATABASE_URL="sqlite:///security_scans.db"
python app.py
```

## 📝 License

MIT License - See root README.md for details.
