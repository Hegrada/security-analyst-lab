#!/usr/bin/env python3
"""
Vulnerable REST API - FOR EDUCATIONAL PURPOSES ONLY
Contains intentional security vulnerabilities
"""

from flask import Flask, request, jsonify, make_response
import os
import jwt
import datetime

app = Flask(__name__)

# VULNERABLE CONFIGURATION
SECRET_KEY = "secret_api_key_12345"  # Hardcoded secret
ALGORITHM = "HS256"

# In-memory "database" (VULNERABLE)
users_db = {
    1: {"id": 1, "username": "admin", "password": "admin123", "email": "admin@example.com", "role": "admin"},
    2: {"id": 2, "username": "user", "password": "password", "email": "user@example.com", "role": "user"},
    3: {"id": 3, "username": "test", "password": "test123", "email": "test@example.com", "role": "user"},
}

# A1: SQL Injection (simulated)
@app.route('/api/users', methods=['GET'])
def get_users():
    user_id = request.args.get('id', '')
    
    # VULNERABLE: No input validation
    if user_id:
        try:
            uid = int(user_id)
            user = users_db.get(uid)
            if user:
                # VULNERABLE: Returns password
                return jsonify({"success": True, "user": user})
            return jsonify({"error": "User not found"}), 404
        except ValueError:
            # VULNERABLE: SQL Injection-like behavior
            return jsonify({"error": f"Invalid input: {user_id}"}), 400
    
    return jsonify({"success": True, "users": list(users_db.values())})

# A2: Broken Authentication - Weak JWT
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABLE: Plain text comparison
    for user in users_db.values():
        if user['username'] == username and user['password'] == password:
            # VULNERABLE: Weak JWT token
            token = jwt.encode(
                {
                    'user_id': user['id'],
                    'username': user['username'],
                    'role': user['role'],
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                },
                SECRET_KEY,
                algorithm=ALGORITHM
            )
            return jsonify({"token": token})
    
    return jsonify({"error": "Invalid credentials"}), 401

# A5: Broken Access Control - IDOR
@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
def user_operations(user_id):
    # VULNERABLE: No authorization check
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    try:
        # VULNERABLE: No proper token verification
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    
    if user_id not in users_db:
        return jsonify({"error": "User not found"}), 404
    
    if request.method == 'GET':
        # VULNERABLE: Returns sensitive data
        return jsonify({"user": users_db[user_id]})
    
    elif request.method == 'PUT':
        data = request.get_json()
        # VULNERABLE: No validation
        users_db[user_id].update(data)
        return jsonify({"success": True, "user": users_db[user_id]})
    
    elif request.method == 'DELETE':
        # VULNERABLE: No admin check
        del users_db[user_id]
        return jsonify({"success": True})

# A6: Security Misconfiguration
@app.route('/api/debug')
def debug():
    # VULNERABLE: Information disclosure
    return jsonify({
        "debug": True,
        "secret_key": SECRET_KEY,
        "environment": os.environ,
        "python_version": "3.9.0"
    })

# A7: XSS in API responses
@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: No output encoding
    return jsonify({
        "query": query,
        "results": f"No results found for: {query}"
    })

# A8: Insecure Deserialization
@app.route('/api/decode', methods=['POST'])
def decode():
    data = request.get_json()
    token = data.get('token', '')
    
    try:
        # VULNERABLE: No verification
        decoded = jwt.decode(token, options={"verify_signature": False})
        return jsonify({"decoded": decoded})
    except Exception as e:
        return jsonify({"error": str(e)})

# A1: Command Injection
@app.route('/api/ping', methods=['POST'])
def ping():
    host = request.get_json().get('host', '')
    # VULNERABLE: Command injection
    import subprocess
    try:
        result = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT)
        return jsonify({"result": result.decode()})
    except Exception as e:
        return jsonify({"error": str(e)})

# Admin-only endpoint (but no real protection)
@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    # VULNERABLE: No proper role verification
    return jsonify({"all_users": list(users_db.values())})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
