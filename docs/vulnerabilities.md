# 🔓 Vulnerabilities Reference

This document describes the intentionally vulnerable applications and the vulnerabilities they contain.

## ⚠️ Warning

These vulnerabilities are **intentionally included** for educational purposes. **Never deploy these configurations in production.**

---

## 🌐 Vulnerable Web Application (Port 8080)

The web application contains the following OWASP Top 10 vulnerabilities:

### A1: Injection (SQL Injection)

**Location:** `/login`, `/users`

**Description:** User input is directly concatenated into SQL queries without sanitization.

**Example Payload:**
```sql
' OR '1'='1' --
```

**Fix:**
```python
# Vulnerable
cur.execute(f"SELECT * FROM users WHERE username = '{username}'")

# Fixed
cur.execute("SELECT * FROM users WHERE username = %s", (username,))
```

### A2: Broken Authentication

**Location:** Session management, `/dashboard`

**Description:** 
- Weak session ID generation
- Session fixation vulnerabilities
- Hardcoded secret key

**Fix:**
- Use Flask-Login with secure session configuration
- Implement proper session timeout
- Use cryptographically secure secret keys

### A3: Sensitive Data Exposure

**Location:** `/users`, `/debug`

**Description:**
- Passwords displayed in plaintext
- Debug mode enabled in production
- Error messages revealing internal details

**Fix:**
- Hash passwords with bcrypt/Argon2
- Disable debug mode in production
- Sanitize error messages

### A5: Broken Access Control (IDOR)

**Location:** `/profile/<int:user_id>`

**Description:** No authorization check when accessing user profiles.

**Example:** Accessing `/profile/2` when logged in as user 1.

**Fix:**
```python
@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    if user_id != current_user.id:
        abort(403)
    # ...
```

### A6: Security Misconfiguration

**Location:** `/debug`

**Description:**
- Debug mode enabled
- Detailed error pages
- Default credentials
- Unnecessary services enabled

**Fix:**
```python
app.run(debug=False)  # Disable debug in production
```

### A7: Cross-Site Scripting (XSS)

**Location:** `/search`, `/comments`

**Description:**
- Reflected XSS in search parameter
- Stored XSS in comments

**Example Payloads:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
```

**Fix:**
```python
from markupsafe import escape
content = escape(user_input)
```

### A8: Insecure Deserialization

**Location:** `/cookie`

**Description:** Cookie values can be manipulated by users.

**Fix:**
- Use server-side session storage
- Implement integrity checks
- Use secure cookie settings

---

## 🔌 Vulnerable REST API (Port 5000)

### A1: SQL Injection (Simulated)

**Location:** `/api/users`

**Description:** User input not validated before processing.

### A2: Broken Authentication

**Location:** `/api/login`

**Description:**
- Weak JWT secret key
- Long token expiration
- No token verification

**Fix:**
```python
SECRET_KEY = os.environ.get('JWT_SECRET')
token = jwt.encode(
    {'user_id': user.id, 'exp': datetime.utcnow() + timedelta(minutes=15)},
    SECRET_KEY,
    algorithm='HS256'
)
```

### A5: Broken Access Control

**Location:** `/api/users/<int:user_id>`

**Description:** No authorization check for user operations.

### A6: Security Misconfiguration

**Location:** `/api/debug`

**Description:** Exposes sensitive configuration data.

### A7: XSS

**Location:** `/api/search`

**Description:** No output encoding in API responses.

---

## 🗄️ Vulnerable Database (Port 3306)

### Security Issues:
- **Weak credentials:** root/toor
- **Plaintext passwords:** Stored without hashing
- **No SSL:** Connection not encrypted
- **Debug logging:** Enabled

---

## 🔐 Vulnerable SSH Server (Port 2222)

### Security Issues:
- **Weak credentials:** root/toor
- **Root login:** Permitted
- **Empty passwords:** Allowed
- **Weak algorithms:** Legacy SSH algorithms enabled

---

## 📁 Vulnerable FTP Server (Port 21)

### Security Issues:
- **Anonymous access:** Enabled
- **No encryption:** Plain text transfers
- **Weak configuration:** Minimal security controls

---

## 🛠️ Testing Tools

### Quick Test Commands

```bash
# Test SQL Injection
sqlmap -u "http://localhost:8080/users?id=1"

# Test XSS
xsstrike -u "http://localhost:8080/search?q=test"

# Test Authentication
hydra -l root -P passwords.txt ssh://localhost:2222

# Test All OWASP Top 10
zap-cli quick-scan --self-contained http://localhost:8080
```

---

## 📚 Learning Resources

### OWASP Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Recommended Tools
- **SQL Injection:** sqlmap, Havij
- **XSS:** XSStrike, Dalfox
- **Vulnerability Scanning:** Nessus, OpenVAS
- **Web Testing:** Burp Suite, OWASP ZAP

---

## ⚖️ Legal Notice

**This software is for educational and security testing purposes only.**

- Only test systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for misuse

---
