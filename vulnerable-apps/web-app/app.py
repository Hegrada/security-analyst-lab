#!/usr/bin/env python3
"""
Vulnerable Web Application - FOR EDUCATIONAL PURPOSES ONLY
Contains intentional security vulnerabilities (OWASP Top 10)
"""

from flask import Flask, request, redirect, url_for, session, render_template_string, make_response
from flask_mysqldb import MySQL
import os
import hashlib
import datetime

app = Flask(__name__)

# VULNERABLE CONFIGURATION - SECRET KEY EXPOSED
app.secret_key = "super_secret_key_12345"

# Database configuration (credentials in code - VULNERABLE)
db_config = {
    'host': os.environ.get('DATABASE_HOST', 'db'),
    'user': 'root',
    'password': 'toor',
    'db': 'users'
}

app.config['MYSQL_HOST'] = db_config['host']
app.config['MYSQL_USER'] = db_config['user']
app.config['MYSQL_PASSWORD'] = db_config['password']
app.config['MYSQL_DB'] = db_config['db']

mysql = MySQL(app)

# HTML Templates with XSS vulnerabilities
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable App</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
        .header { background: #333; color: white; padding: 20px; }
        .content { padding: 20px; }
        .vuln { border: 1px solid red; padding: 10px; margin: 10px 0; }
        input, textarea { width: 100%; padding: 10px; margin: 5px 0; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        a { color: #007bff; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏗️ Vulnerable Web Application</h1>
        <p>OWASP Top 10 Vulnerabilities Demo</p>
    </div>
    <div class="content">
        {{ content | safe }}
    </div>
</body>
</html>
"""

# A1: SQL Injection - Vulnerable login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABLE: SQL Injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cur = mysql.connection.cursor()
            cur.execute(query)
            user = cur.fetchone()
            cur.close()
            
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid credentials'
        except Exception as e:
            error = f'Error: {str(e)}'
    
    content = f"""
    <h2>Login (SQL Injection Demo)</h2>
    <p>Try: <code>admin' OR '1'='1</code> as username</p>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    <p style="color: red;">{error or ''}</p>
    <a href="/">Back to Home</a>
    """
    return render_template_string(HTML_TEMPLATE, content=content)

# A2: Broken Authentication - Weak session management
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # VULNERABLE: Information disclosure
    welcome = f"""
    <h2>Welcome, {session['username']}!</h2>
    <p>Your Session ID: {session.sid}</p>
    <p>Your User ID: {session['user_id']}</p>
    <p>Secret Key: super_secret_key_12345</p>
    """
    
    content = welcome
    return render_template_string(HTML_TEMPLATE, content=content)

# A3: Sensitive Data Exposure - Plain text credentials in response
@app.route('/users')
def users():
    # VULNERABLE: SQL Injection + Plain text passwords
    user_id = request.args.get('id', '')
    
    query = f"SELECT id, username, password, email FROM users WHERE id = '{user_id}'"
    
    try:
        cur = mysql.connection.cursor()
        cur.execute(query)
        users = cur.fetchall()
        cur.close()
        
        content = "<h2>Users (SQL Injection Demo)</h2>"
        content += "<p>Try: <code>' OR '1'='1</code> as id</p>"
        content += "<table border='1'><tr><th>ID</th><th>Username</th><th>Password</th><th>Email</th></tr>"
        for user in users:
            content += f"<tr><td>{user[0]}</td><td>{user[1]}</td><td style='color:red'>{user[2]}</td><td>{user[3]}</td></tr>"
        content += "</table>"
        
    except Exception as e:
        content = f"<p>Error: {str(e)}</p>"
    
    content += "<a href='/'>Back to Home</a>"
    return render_template_string(HTML_TEMPLATE, content=content)

# A7: Cross-Site Scripting (XSS) - Reflected
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # VULNERABLE: XSS - No output encoding
    content = f"""
    <h2>Search (XSS Demo)</h2>
    <p>Search results for: <span id="query">{query}</span></p>
    <form method="GET">
        <input type="text" name="q" placeholder="Try: <script>alert('XSS')</script>" value="{query}">
        <button type="submit">Search</button>
    </form>
    <p>Try: <code><script>alert('XSS')</script></code></p>
    <a href="/">Back to Home</a>
    """
    return render_template_string(HTML_TEMPLATE, content=content)

# A7: XSS - Stored (Comment system)
@app.route('/comments', methods=['GET', 'POST'])
def comments():
    if request.method == 'POST':
        name = request.form['name']
        comment = request.form['comment']
        
        # VULNERABLE: Stored XSS - No sanitization
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO comments (name, comment) VALUES (%s, %s)", (name, comment))
        mysql.connection.commit()
        cur.close()
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT name, comment, created_at FROM comments ORDER BY created_at DESC")
    comments_list = cur.fetchall()
    cur.close()
    
    content = "<h2>Comments (Stored XSS Demo)</h2>"
    content += "<form method='POST'>"
    content += "<input type='text' name='name' placeholder='Name' required>"
    content += "<textarea name='comment' placeholder='Comment' required></textarea>"
    content += "<button type='submit'>Post Comment</button>"
    content += "</form>"
    content += "<p>Try: <code><script>alert(document.cookie)</script></code> in name or comment</p>"
    content += "<hr>"
    
    for c in comments_list:
        content += f"<div class='vuln'><strong>{c[0]}</strong>: {c[1]}</div>"
    
    content += "<a href='/'>Back to Home</a>"
    return render_template_string(HTML_TEMPLATE, content=content)

# A5: Broken Access Control - IDOR
@app.route('/profile/<int:user_id>')
def profile(user_id):
    # VULNERABLE: IDOR - No authorization check
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username, password, email FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    
    if user:
        content = f"""
        <h2>User Profile</h2>
        <p><strong>ID:</strong> {user[0]}</p>
        <p><strong>Username:</strong> {user[1]}</p>
        <p><strong>Password:</strong> {user[2]}</p>
        <p><strong>Email:</strong> {user[3]}</p>
        <p><em>Try changing the user_id in the URL!</em></p>
        <a href="/">Back to Home</a>
        """
    else:
        content = "<p>User not found</p><a href='/'>Back to Home</a>"
    
    return render_template_string(HTML_TEMPLATE, content=content)

# A6: Security Misconfiguration - Debug enabled
@app.route('/debug')
def debug():
    # VULNERABLE: Debug mode information disclosure
    content = """
    <h2>Debug Information</h2>
    <pre>
    DEBUG_MODE: True
    SECRET_KEY: super_secret_key_12345
    DATABASE_HOST: db
    DATABASE_USER: root
    DATABASE_PASSWORD: toor
    
    Flask Configuration:
    - DEBUG: True
    - TESTING: True
    - PROPAGATE_EXCEPTIONS: True
    </pre>
    <a href="/">Back to Home</a>
    """
    return render_template_string(HTML_TEMPLATE, content=content)

# A8: Insecure Deserialization (simulated)
@app.route('/cookie')
def cookie_demo():
    # VULNERABLE: Cookie manipulation
    user_data = request.cookies.get('user_data', '')
    content = f"""
    <h2>Cookie Demo (Insecure Deserialization)</h2>
    <p>Your current cookie: {user_data}</p>
    <p>Try modifying the cookie value!</p>
    <a href="/">Back to Home</a>
    """
    return render_template_string(HTML_TEMPLATE, content=content)

# Home page
@app.route('/')
def home():
    content = """
    <h2>🏗️ Vulnerable Web Application</h2>
    <p>This application contains intentional security vulnerabilities for educational purposes.</p>
    
    <h3>Vulnerabilities Demo:</h3>
    <ul>
        <li><a href="/login">A1: SQL Injection (Login)</a></li>
        <li><a href="/users?id=1">A1: SQL Injection (User List)</a></li>
        <li><a href="/dashboard">A2: Broken Authentication</a></li>
        <li><a href="/profile/1">A5: Broken Access Control (IDOR)</a></li>
        <li><a href="/debug">A6: Security Misconfiguration</a></li>
        <li><a href="/search?q=test">A7: Cross-Site Scripting (Reflected)</a></li>
        <li><a href="/comments">A7: Cross-Site Scripting (Stored)</a></li>
        <li><a href="/cookie">A8: Insecure Deserialization</a></li>
    </ul>
    
    <hr>
    <p><em>Warning: This application is intentionally vulnerable. Do not deploy in production!</em></p>
    """
    return render_template_string(HTML_TEMPLATE, content=content)

# Initialize database
def init_db():
    cur = mysql.connection.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            password VARCHAR(50) NOT NULL,
            email VARCHAR(100)
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(50) NOT NULL,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert vulnerable data
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        users = [
            ('admin', 'admin123', 'admin@example.com'),
            ('user', 'password', 'user@example.com'),
            ('test', 'test123', 'test@example.com'),
        ]
        cur.executemany("INSERT INTO users (username, password, email) VALUES (%s, %s, %s)", users)
        mysql.connection.commit()
    
    cur.close()

if __name__ == '__main__':
    # VULNERABLE: Debug mode enabled
    app.run(host='0.0.0.0', port=5000, debug=True)
