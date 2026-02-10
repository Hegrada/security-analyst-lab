#!/usr/bin/env python3
"""
Security Audit Dashboard
Flask-based web dashboard for visualizing security scan results.
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import json
import os
from datetime import datetime

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///scans.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class Scan(db.Model):
    """Scan result database model"""
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50))
    target = db.Column(db.String(255))
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    duration = db.Column(db.Float)
    results_json = db.Column(db.Text)
    status = db.Column(db.String(20), default='completed')
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'status': self.status
        }


class Vulnerability(db.Model):
    """Vulnerability database model"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))
    title = db.Column(db.String(255))
    severity = db.Column(db.String(20))
    cvss = db.Column(db.Float)
    description = db.Column(db.Text)
    remediation = db.Column(db.Text)
    url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'title': self.title,
            'severity': self.severity,
            'cvss': self.cvss,
            'description': self.description,
            'remediation': self.remediation,
            'url': self.url,
            'created_at': self.created_at.isoformat()
        }


@app.route('/')
def index():
    """Dashboard home page"""
    # Get scan statistics
    total_scans = Scan.query.count()
    critical_vulns = Vulnerability.query.filter_by(severity='Critical').count()
    high_vulns = Vulnerability.query.filter_by(severity='High').count()
    medium_vulns = Vulnerability.query.filter_by(severity='Medium').count()
    low_vulns = Vulnerability.query.filter_by(severity='Low').count()
    
    # Get recent scans
    recent_scans = Scan.query.order_by(Scan.start_time.desc()).limit(10).all()
    
    # Get severity distribution for charts
    severity_dist = {
        'critical': critical_vulns,
        'high': high_vulns,
        'medium': medium_vulns,
        'low': low_vulns,
        'info': Vulnerability.query.filter_by(severity='Info').count()
    }
    
    return render_template(
        'index.html',
        total_scans=total_scans,
        critical_vulns=critical_vulns,
        high_vulns=high_vulns,
        medium_vulns=medium_vulns,
        low_vulns=low_vulns,
        recent_scans=recent_scans,
        severity_dist=severity_dist
    )


@app.route('/scans')
def scans():
    """List all scans"""
    scans_list = Scan.query.order_by(Scan.start_time.desc()).all()
    return render_template('scans.html', scans=scans_list)


@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    """Show scan details"""
    scan = Scan.query.get_or_404(scan_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
    
    results = json.loads(scan.results_json) if scan.results_json else {}
    
    return render_template(
        'scan_details.html',
        scan=scan,
        vulnerabilities=vulnerabilities,
        results=results
    )


@app.route('/vulnerabilities')
def vulnerabilities():
    """List all vulnerabilities"""
    severity = request.args.get('severity')
    if severity:
        vulns = Vulnerability.query.filter_by(severity=severity.capitalize()).all()
    else:
        vulns = Vulnerability.query.all()
    
    return render_template('vulnerabilities.html', vulnerabilities=vulns, filter=severity)


@app.route('/add_scan', methods=['POST'])
def add_scan():
    """Add a new scan result"""
    data = request.get_json()
    
    scan = Scan(
        scan_type=data.get('scan_type', 'unknown'),
        target=data.get('target', ''),
        start_time=datetime.fromisoformat(data.get('start_time', datetime.utcnow().isoformat())),
        end_time=datetime.fromisoformat(data.get('end_time', datetime.utcnow().isoformat())),
        duration=data.get('duration', 0),
        results_json=json.dumps(data.get('results', {})),
        status=data.get('status', 'completed')
    )
    
    db.session.add(scan)
    db.session.commit()
    
    # Add vulnerabilities if present
    for vuln_data in data.get('vulnerabilities', []):
        vuln = Vulnerability(
            scan_id=scan.id,
            title=vuln_data.get('name', 'Unknown'),
            severity=vuln_data.get('severity_name', 'Info'),
            cvss=vuln_data.get('cvss', 0),
            description=vuln_data.get('description', ''),
            remediation=vuln_data.get('remediation', ''),
            url=vuln_data.get('url', '')
        )
        db.session.add(vuln)
    
    db.session.commit()
    
    return jsonify({'success': True, 'scan_id': scan.id})


@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics"""
    stats = {
        'total_scans': Scan.query.count(),
        'total_vulnerabilities': Vulnerability.query.count(),
        'severity_distribution': {
            'critical': Vulnerability.query.filter_by(severity='Critical').count(),
            'high': Vulnerability.query.filter_by(severity='High').count(),
            'medium': Vulnerability.query.filter_by(severity='Medium').count(),
            'low': Vulnerability.query.filter_by(severity='Low').count(),
            'info': Vulnerability.query.filter_by(severity='Info').count()
        },
        'recent_scans': [s.to_dict() for s in Scan.query.order_by(Scan.start_time.desc()).limit(5).all()]
    }
    return jsonify(stats)


@app.route('/api/scans')
def api_scans():
    """API endpoint for scans list"""
    scans = Scan.query.order_by(Scan.start_time.desc()).all()
    return jsonify([s.to_dict() for s in scans])


@app.route('/api/vulnerabilities')
def api_vulnerabilities():
    """API endpoint for vulnerabilities list"""
    severity = request.args.get('severity')
    if severity:
        vulns = Vulnerability.query.filter_by(severity=severity.capitalize()).all()
    else:
        vulns = Vulnerability.query.all()
    return jsonify([v.to_dict() for v in vulns])


def init_db():
    """Initialize the database"""
    with app.app_context():
        db.create_all()
        # Add sample data if empty
        if Scan.query.count() == 0:
            sample_scan = Scan(
                scan_type='port_scan',
                target='localhost',
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                duration=5.5,
                status='completed'
            )
            db.session.add(sample_scan)
            db.session.commit()


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
