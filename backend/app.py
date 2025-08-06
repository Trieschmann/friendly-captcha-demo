from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify, send_file
import requests
import os
import psycopg2
import psycopg2.extras
import hashlib
from datetime import datetime
import json
import sqlite3
from werkzeug.utils import secure_filename
import uuid

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key-change-in-production")
FRIENDLY_CAPTCHA_SECRET = os.getenv("FRIENDLY_CAPTCHA_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")

# File upload configuration
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
ALLOWED_EXTENSIONS = {'pdf'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database connection for PostgreSQL (Render Standard)
def get_db_connection():
    if DATABASE_URL:
        # Render PostgreSQL
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    else:
        # Local SQLite for Development
        import sqlite3
        conn = sqlite3.connect('members.db')
        conn.row_factory = sqlite3.Row
        return conn

# Database initialization
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    
    if DATABASE_URL:
        # PostgreSQL Tables
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS members (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        membership_type VARCHAR(100) NOT NULL,
                        country VARCHAR(100),
                        company_name VARCHAR(255) NOT NULL,
                        business_activity VARCHAR(100),
                        sub_activity VARCHAR(100),
                        has_online_store BOOLEAN DEFAULT FALSE,
                        online_store_products VARCHAR(50),
                        first_name VARCHAR(100),
                        last_name VARCHAR(100),
                        email VARCHAR(255),
                        phone VARCHAR(50),
                        status VARCHAR(20) DEFAULT 'pending',
                        join_date DATE DEFAULT CURRENT_DATE,
                        data_processing_consent BOOLEAN DEFAULT FALSE,
                        marketing_consent BOOLEAN DEFAULT FALSE,
                        terms_consent BOOLEAN DEFAULT TRUE,
                        consent_document_filename VARCHAR(255),
                        consent_document_original_name VARCHAR(255),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )''')
        
        # Test user for PostgreSQL
        password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cur.execute('''INSERT INTO users (username, password_hash) VALUES (%s, %s) 
                      ON CONFLICT (username) DO NOTHING''', ('admin', password_hash))
    else:
        # SQLite Tables (for local development)
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS members (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        membership_type TEXT NOT NULL,
                        country TEXT,
                        company_name TEXT NOT NULL,
                        business_activity TEXT,
                        sub_activity TEXT,
                        has_online_store BOOLEAN DEFAULT 0,
                        online_store_products TEXT,
                        first_name TEXT,
                        last_name TEXT,
                        email TEXT,
                        phone TEXT,
                        status TEXT DEFAULT 'pending',
                        join_date DATE DEFAULT CURRENT_DATE,
                        data_processing_consent BOOLEAN DEFAULT 0,
                        marketing_consent BOOLEAN DEFAULT 0,
                        terms_consent BOOLEAN DEFAULT 1,
                        consent_document_filename TEXT,
                        consent_document_original_name TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )''')
        
        password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cur.execute('INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)', 
                   ('admin', password_hash))
    
    conn.commit()
    conn.close()

# Helper functions
def verify_user(username, password):
    conn = get_db_connection()
    cur = conn.cursor()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if DATABASE_URL:
        cur.execute('SELECT id FROM users WHERE username = %s AND password_hash = %s', 
                   (username, password_hash))
    else:
        cur.execute('SELECT id FROM users WHERE username = ? AND password_hash = ?', 
                   (username, password_hash))
    
    user = cur.fetchone()
    conn.close()
    return user[0] if user else None

def get_user_members(user_id):
    conn = get_db_connection()
    if DATABASE_URL:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('SELECT * FROM members WHERE user_id = %s ORDER BY created_at DESC', (user_id,))
    else:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute('SELECT * FROM members WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    
    members = cur.fetchall()
    conn.close()
    return members

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    return render_template_string(LOGIN_TEMPLATE, error=request.args.get('error'))

@app.route('/submit', methods=['POST'])
def submit():
    username = request.form.get('username')
    password = request.form.get('password')
    solution = request.form.get('frc-captcha-solution')
    
    # Verify Captcha (only if Secret is set)
    if FRIENDLY_CAPTCHA_SECRET and solution:
        try:
            captcha_response = requests.post(
                "https://api.friendlycaptcha.com/api/v1/siteverify",
                data={"solution": solution, "secret": FRIENDLY_CAPTCHA_SECRET},
                timeout=5
            )
            result = captcha_response.json()
            if not result.get("success"):
                return redirect(url_for('index', error='Captcha failed'))
        except:
            # Continue anyway on Captcha errors (for development)
            pass
    
    # Verify user
    user_id = verify_user(username, password)
    if user_id:
        session['user_id'] = user_id
        session['username'] = username
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('index', error='Invalid credentials'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    members = get_user_members(session['user_id'])
    return render_template_string(DASHBOARD_TEMPLATE, 
                                username=session['username'], 
                                members=members)

@app.route('/membership/new')
def new_membership():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    membership_type = request.args.get('type', 'packaging-paper')
    session['membership_form'] = {'membership_type': membership_type}
    return redirect(url_for('membership_form', step=1))

@app.route('/membership/form/<int:step>')
def membership_form(step):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    if step < 1 or step > 4:
        return redirect(url_for('membership_form', step=1))
    
    form_data = session.get('membership_form', {})
    
    templates = {
        1: MEMBERSHIP_STEP1_TEMPLATE,
        2: MEMBERSHIP_STEP2_TEMPLATE,
        3: MEMBERSHIP_STEP3_TEMPLATE,
        4: MEMBERSHIP_STEP4_TEMPLATE
    }
    
    return render_template_string(templates[step], form_data=form_data, step=step)

@app.route('/membership/form/<int:step>', methods=['POST'])
def save_membership_step(step):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    if 'membership_form' not in session:
        session['membership_form'] = {}
    
    form_data = session['membership_form']
    
    if step == 1:
        form_data.update({
            'country': request.form.get('country'),
            'company_name': request.form.get('company_name'),
            'membership_type': request.form.get('membership_type')
        })
    elif step == 2:
        form_data.update({
            'business_activity': request.form.get('business_activity'),
            'sub_activity': request.form.get('sub_activity'),
            'has_online_store': request.form.get('has_online_store') == 'yes',
            'online_store_products': request.form.get('online_store_products')
        })
    elif step == 3:
        form_data.update({
            'company_street': request.form.get('company_street'),
            'company_postal_code': request.form.get('company_postal_code'),
            'company_city': request.form.get('company_city'),
            'company_country': request.form.get('company_country'),
            'company_phone': request.form.get('company_phone'),
            'company_website': request.form.get('company_website'),
    
            'contact_salutation': request.form.get('contact_salutation'),
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'email': request.form.get('email'),
            'phone': request.form.get('phone')
        })
    elif step == 4:
        form_data.update({
            'data_processing_consent': bool(request.form.get('data_processing_consent')),
            'marketing_consent': bool(request.form.get('marketing_consent')),
            'terms_consent': bool(request.form.get('terms_consent'))
        })
        
        # Handle file upload
        consent_filename = None
        consent_original_name = None
        
        if 'consent_document' in request.files:
            file = request.files['consent_document']
            if file and file.filename != '' and allowed_file(file.filename):
                # Generate unique filename
                file_extension = file.filename.rsplit('.', 1)[1].lower()
                consent_filename = f"{uuid.uuid4().hex}.{file_extension}"
                consent_original_name = secure_filename(file.filename)
                
                # Save file
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], consent_filename)
                file.save(file_path)
        
        # Save member to database
        conn = get_db_connection()
        cur = conn.cursor()
        
        if DATABASE_URL:
            cur.execute('''INSERT INTO members 
                          (user_id, membership_type, country, company_name, business_activity, 
                           sub_activity, has_online_store, online_store_products, first_name, 
                           last_name, email, phone, data_processing_consent, marketing_consent, 
                           terms_consent, consent_document_filename, consent_document_original_name)
                          VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                         (session['user_id'], form_data.get('membership_type'), form_data.get('country'),
                          form_data.get('company_name'), form_data.get('business_activity'),
                          form_data.get('sub_activity'), form_data.get('has_online_store', False),
                          form_data.get('online_store_products'), form_data.get('first_name'),
                          form_data.get('last_name'), form_data.get('email'), form_data.get('phone'),
                          form_data.get('data_processing_consent', False),
                          form_data.get('marketing_consent', False),
                          form_data.get('terms_consent', True),
                          consent_filename, consent_original_name))
        else:
            cur.execute('''INSERT INTO members 
                          (user_id, membership_type, country, company_name, business_activity, 
                           sub_activity, has_online_store, online_store_products, first_name, 
                           last_name, email, phone, data_processing_consent, marketing_consent, 
                           terms_consent, consent_document_filename, consent_document_original_name)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                         (session['user_id'], form_data.get('membership_type'), form_data.get('country'),
                          form_data.get('company_name'), form_data.get('business_activity'),
                          form_data.get('sub_activity'), form_data.get('has_online_store', False),
                          form_data.get('online_store_products'), form_data.get('first_name'),
                          form_data.get('last_name'), form_data.get('email'), form_data.get('phone'),
                          form_data.get('data_processing_consent', False),
                          form_data.get('marketing_consent', False),
                          form_data.get('terms_consent', True),
                          consent_filename, consent_original_name))
        
        conn.commit()
        conn.close()
        
        session.pop('membership_form', None)
        return redirect(url_for('dashboard'))
    
    session['membership_form'] = form_data
    next_step = step + 1 if step < 4 else 4
    return redirect(url_for('membership_form', step=next_step))

@app.route('/download/<int:member_id>/consent')
def download_consent_document(member_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    if DATABASE_URL:
        cur.execute('SELECT consent_document_filename, consent_document_original_name FROM members WHERE id = %s AND user_id = %s', 
                   (member_id, session['user_id']))
    else:
        cur.execute('SELECT consent_document_filename, consent_document_original_name FROM members WHERE id = ? AND user_id = ?', 
                   (member_id, session['user_id']))
    
    result = cur.fetchone()
    conn.close()
    
    if not result or not result[0]:
        return "File not found", 404
    
    filename = result[0]
    original_name = result[1] or filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        return "File not found", 404
    
    return send_file(file_path, as_attachment=True, download_name=original_name)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Health Check for Render
@app.route('/health')
def health_check():
    return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}

# Template Constants
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Membership System</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
               max-width: 400px; margin: 100px auto; padding: 20px; background: #f5f5f5; }
        .login-container { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        h2 { text-align: center; color: #333; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        input[type="text"], input[type="password"] { 
            width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; 
            font-size: 16px; transition: border-color 0.3s;
        }
        input:focus { border-color: #007bff; outline: none; }
        button { 
            width: 100%; padding: 14px; background: #007bff; color: white; 
            border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 600;
            transition: background-color 0.3s;
        }
        button:hover { background: #0056b3; }
        .error { color: #dc3545; margin: 15px 0; text-align: center; padding: 10px; 
                 background: #f8d7da; border-radius: 6px; }
        .test-info { margin-top: 15px; padding: 10px; background: #d1ecf1; 
                     border-radius: 6px; font-size: 14px; text-align: center; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>👥 Membership System</h2>
        {% if error %}
            <div class="error">❌ {{ error }}</div>
        {% endif %}
        <form method="POST" action="/submit">
            <div class="form-group">
                <input type="text" name="username" placeholder="Username" required />
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="Password" required />
            </div>
            <div class="form-group">
                <div class="frc-captcha" data-sitekey="FCMLUC8UHAIO4Q8G"></div>
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="test-info">
            <strong>Test Account:</strong><br>
            Username: admin<br>
            Password: admin123
        </div>
    </div>
    <script src="https://unpkg.com/friendly-challenge@0.9.9/widget.module.min.js" type="module"></script>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Membership System</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
               margin: 0; padding: 20px; background: #f8f9fa; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; padding: 20px 30px; border-radius: 12px; 
                  box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 30px;
                  display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; color: #333; }
        .user-info { display: flex; align-items: center; gap: 15px; }
        .btn { padding: 10px 20px; text-decoration: none; border-radius: 8px; 
               font-weight: 600; transition: all 0.3s; }
        .btn-primary { background: #007bff; color: white; }
        .btn-primary:hover { background: #0056b3; transform: translateY(-1px); }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #545b62; }
        .btn-success { background: #28a745; color: white; }
        .btn-success:hover { background: #218838; }
        .add-button { margin-bottom: 30px; position: relative; display: inline-block; }
        .dropdown-container { position: relative; display: inline-block; }
        .dropdown-button { 
            background: #007bff; color: white; padding: 10px 20px; border: none;
            border-radius: 8px; cursor: pointer; font-weight: 600; 
            display: flex; align-items: center; gap: 8px; transition: all 0.3s;
        }
        .dropdown-button:hover { background: #0056b3; transform: translateY(-1px); }
        .dropdown-arrow { font-size: 12px; transition: transform 0.3s; }
        .dropdown-menu { 
            position: absolute; top: 100%; left: 0; background: white; 
            border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            min-width: 220px; z-index: 1000; opacity: 0; visibility: hidden;
            transform: translateY(-10px); transition: all 0.3s;
        }
        .dropdown-container:hover .dropdown-menu { 
            opacity: 1; visibility: visible; transform: translateY(0);
        }
        .dropdown-container:hover .dropdown-arrow { transform: rotate(180deg); }
        .dropdown-item { 
            display: block; padding: 12px 20px; color: #333; text-decoration: none;
            border-bottom: 1px solid #f0f0f0; transition: background-color 0.3s;
        }
        .dropdown-item:last-child { border-bottom: none; border-radius: 0 0 8px 8px; }
        .dropdown-item:first-child { border-radius: 8px 8px 0 0; }
        .dropdown-item:hover { background: #f8f9fa; }
        .member-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 25px; }
        .member-card { 
            background: white; border-radius: 12px; padding: 25px; 
            box-shadow: 0 4px 12px rgba(0,0,0,0.1); transition: transform 0.3s, box-shadow 0.3s;
        }
        .member-card:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0,0,0,0.15); }
        .member-card h3 { margin: 0 0 15px 0; color: #007bff; font-size: 1.3em; }
        .member-info { margin: 15px 0; line-height: 1.6; }
        .member-info strong { color: #555; }
        .member-actions { margin-top: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
        .member-actions .btn { padding: 8px 16px; font-size: 14px; }
        .empty-state { text-align: center; padding: 80px 20px; color: #6c757d; }
        .empty-state h3 { font-size: 1.5em; margin-bottom: 15px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                 gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 12px; 
                     box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007bff; }
        .stat-label { color: #6c757d; margin-top: 5px; }
        .status-badge { 
            display: inline-block; padding: 4px 12px; border-radius: 20px; 
            font-size: 12px; font-weight: 600; text-transform: uppercase;
        }
        .status-active { background: #d4edda; color: #155724; }
        .status-pending { background: #fff3cd; color: #856404; }
        .status-expired { background: #f8d7da; color: #721c24; }
        .document-info {
            margin-top: 10px; padding: 8px; background: #f8f9fa; border-radius: 6px; 
            font-size: 13px; color: #6c757d;
        }
        .document-info strong { color: #495057; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>👥 Membership System</h1>
            <div class="user-info">
                <span>Welcome, <strong>{{ username }}</strong>!</span>
                <a href="/logout" class="btn btn-secondary">Logout</a>
            </div>
        </div>
        
        {% if members %}
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{{ members|length }}</div>
                <div class="stat-label">Total Members</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ members|selectattr('status', 'equalto', 'active')|list|length }}</div>
                <div class="stat-label">Active Members</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ members|selectattr('consent_document_filename')|list|length }}</div>
                <div class="stat-label">With Documents</div>
            </div>
        </div>
        {% endif %}
        
        <div class="add-button">
            <div class="dropdown-container">
                <button class="dropdown-button">
                    + New Membership
                    <span class="dropdown-arrow">▼</span>
                </button>
                <div class="dropdown-menu">
                    <a href="/membership/new?type=packaging-paper" class="dropdown-item">
                        📦 Packaging & Paper
                    </a>
                    <a href="/membership/new?type=food-service" class="dropdown-item">
                        🍽️ Food Service Packaging
                    </a>
                </div>
            </div>
        </div>
        
        {% if members %}
            <div class="member-grid">
                {% for member in members %}
                <div class="member-card">
                    <h3>{{ member.company_name }}</h3>
                    <div class="member-info">
                        <strong>Contact:</strong> {{ member.first_name }} {{ member.last_name }}<br>
                        <strong>Country:</strong> {{ member.country or 'Not provided' }}<br>
                        <strong>Business:</strong> {{ member.business_activity or 'Not specified' }}<br>
                        <strong>Status:</strong> 
                        <span class="status-badge status-{{ member.status or 'pending' }}">
                            {{ (member.status or 'pending')|title }}
                        </span>
                    </div>
                    
                    {% if member.consent_document_filename %}
                    <div class="document-info">
                        <strong>📄 Consent Document:</strong> {{ member.consent_document_original_name or 'Uploaded' }}
                    </div>
                    {% endif %}
                    
                    <div class="member-actions">
                        <a href="/membership/{{ member.id }}/view" class="btn btn-primary">View</a>
                        <a href="/membership/{{ member.id }}/edit" class="btn btn-secondary">Edit</a>
                        {% if member.consent_document_filename %}
                        <a href="/download/{{ member.id }}/consent" class="btn btn-success">📄 Download PDF</a>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
            </div>
        {% else %}
            <div class="empty-state">
                <h3>👥 No members yet</h3>
                <p>Click "New Membership" to get started.</p>
            </div>
        {% endif %}
    </div>
</body>
</html>
'''

MEMBERSHIP_STEP1_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Membership - Packaging & Paper</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            margin: 0; padding: 20px; background: #f8f9fa; 
        }
        .container { max-width: 600px; margin: 0 auto; }
        .form-card { 
            background: white; padding: 30px; border-radius: 12px; 
            box-shadow: 0 4px 12px rgba(0,0,0,0.1); 
        }
        .header { text-align: center; margin-bottom: 30px; }
        .header h2 { color: #333; margin: 0 0 10px 0; font-size: 1.8em; }
        .header .subtitle { color: #6c757d; font-size: 1.1em; }
        .membership-badge {
            display: inline-block; background: #e3f2fd; color: #1976d2;
            padding: 6px 16px; border-radius: 20px; font-size: 14px;
            font-weight: 600; margin-bottom: 20px;
        }
        .progress { 
            background: #e9ecef; border-radius: 10px; margin-bottom: 30px; height: 8px; 
        }
        .progress-bar { 
            background: linear-gradient(90deg, #007bff, #0056b3); 
            height: 8px; border-radius: 10px; width: 25%; transition: width 0.3s; 
        }
        .step-info {
            text-align: center; color: #6c757d; margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group { margin-bottom: 25px; }
        label { 
            display: block; margin-bottom: 8px; font-weight: 600; color: #555; 
            font-size: 15px;
        }
        input, select { 
            width: 100%; padding: 14px; border: 2px solid #ddd; border-radius: 8px; 
            font-size: 16px; transition: border-color 0.3s; background: white;
            box-sizing: border-box;
        }
        input:focus, select:focus { 
            border-color: #007bff; outline: none; box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
        }
        .required { color: #dc3545; }
        .form-help {
            font-size: 13px; color: #6c757d; margin-top: 5px;
        }
        .btn { 
            padding: 14px 28px; border: none; border-radius: 8px; cursor: pointer; 
            margin-right: 12px; font-weight: 600; transition: all 0.3s; 
            font-size: 16px; text-decoration: none; display: inline-block;
        }
        .btn-primary { background: #007bff; color: white; }
        .btn-primary:hover { background: #0056b3; transform: translateY(-1px); }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #545b62; }
        .navigation { 
            margin-top: 40px; display: flex; justify-content: space-between; 
            align-items: center; padding-top: 20px; border-top: 1px solid #e9ecef;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="form-card">
            <div class="header">
                <div class="membership-badge">📦 Packaging & Paper</div>
                <h2>New Membership Registration</h2>
                <p class="subtitle">Let's get your company registered</p>
            </div>
            
            <div class="progress">
                <div class="progress-bar"></div>
            </div>
            <div class="step-info">Step 1 of 4 - Basic Information</div>
            
            <form method="POST" action="/membership/form/1">
                <div class="form-group">
                    <label for="country">Country <span class="required">*</span></label>
                    <select name="country" id="country" required>
                        <option value="">Please select your country</option>
                        <option value="Germany" {{ 'selected' if form_data.get('country') == 'Germany' else '' }}>
                            🇩🇪 Germany
                        </option>
                        <option value="France" {{ 'selected' if form_data.get('country') == 'France' else '' }}>
                            🇫🇷 France
                        </option>
                        <option value="Austria" {{ 'selected' if form_data.get('country') == 'Austria' else '' }}>
                            🇦🇹 Austria
                        </option>
                    </select>
                    <div class="form-help">Select the country where your company is registered</div>
                </div>
                
                <div class="form-group">
                    <label for="company_name">Company Name <span class="required">*</span></label>
                    <input 
                        type="text" 
                        name="company_name" 
                        id="company_name"
                        value="{{ form_data.get('company_name', '') }}" 
                        placeholder="Enter your company name"
                        required
                    >
                    <div class="form-help">Enter the official registered name of your company</div>
                </div>
                
                <!-- Hidden field to track membership type -->
                <input type="hidden" name="membership_type" value="packaging-paper">
                
                <div class="navigation">
                    <a href="/dashboard" class="btn btn-secondary">← Back to Dashboard</a>
                    <button type="submit" class="btn btn-primary">Continue →</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
'''

MEMBERSHIP_STEP2_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Membership - Business Details</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            margin: 0; padding: 20px; background: #f8f9fa; 
        }
        .container { max-width: 600px; margin: 0 auto; }
        .form-card { 
            background: white; padding: 30px; border-radius: 12px; 
            box-shadow: 0 4px 12px rgba(0,0,0,0.1); 
        }
        .header { text-align: center; margin-bottom: 30px; }
        .header h2 { color: #333; margin: 0 0 10px 0; font-size: 1.8em; }
        .header .subtitle { color: #6c757d; font-size: 1.1em; }
        .membership-badge {
            display: inline-block; background: #e3f2fd; color: #1976d2;
            padding: 6px 16px; border-radius: 20px; font-size: 14px;
            font-weight: 600; margin-bottom: 20px;
        }
        .progress { 
            background: #e9ecef; border-radius: 10px; margin-bottom: 30px; height: 8px; 
        }
        .progress-bar { 
            background: linear-gradient(90deg, #007bff, #0056b3); 
            height: 8px; border-radius: 10px; width: 50%; transition: width 0.3s; 
        }
        .step-info {
            text-align: center; color: #6c757d; margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group { margin-bottom: 25px; }
        label { 
            display: block; margin-bottom: 8px; font-weight: 600; color: #555; 
            font-size: 15px;
        }
        input, select { 
            width: 100%; padding: 14px; border: 2px solid #ddd; border-radius: 8px; 
            font-size: 16px; transition: border-color 0.3s; background: white;
            box-sizing: border-box;
        }
        input:focus, select:focus { 
            border-color: #007bff; outline: none; box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
        }
        .required { color: #dc3545; }
        .form-help {
            font-size: 13px; color: #6c757d; margin-top: 5px;
        }
        .btn { 
            padding: 14px 28px; border: none; border-radius: 8px; cursor: pointer; 
            margin-right: 12px; font-weight: 600; transition: all 0.3s; 
            font-size: 16px; text-decoration: none; display: inline-block;
        }
        .btn-primary { background: #007bff; color: white; }
        .btn-primary:hover { background: #0056b3; transform: translateY(-1px); }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #545b62; }
        .navigation { 
            margin-top: 40px; display: flex; justify-content: space-between; 
            align-items: center; padding-top: 20px; border-top: 1px solid #e9ecef;
        }
        .radio-group {
            display: flex; gap: 20px; margin-top: 10px;
        }
        .radio-option {
            display: flex; align-items: center; gap: 8px;
        }
        .radio-option input[type="radio"] {
            width: auto; margin: 0;
        }
        .radio-option label {
            margin: 0; font-weight: normal; cursor: pointer;
        }
        #sub_activity {
            opacity: 0.6;
            pointer-events: none;
            transition: opacity 0.3s;
        }
        #sub_activity.enabled {
            opacity: 1;
            pointer-events: all;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="form-card">
            <div class="header">
                <div class="membership-badge">📦 Packaging & Paper</div>
                <h2>Business Activity Details</h2>
                <p class="subtitle">Tell us about your business operations</p>
            </div>
            
            <div class="progress">
                <div class="progress-bar"></div>
            </div>
            <div class="step-info">Step 2 of 4 - Business Information</div>
            
            <form method="POST" action="/membership/form/2">
                <div class="form-group">
                    <label for="business_activity">Business Activity <span class="required">*</span></label>
                    <select name="business_activity" id="business_activity" required onchange="updateSubActivities()">
                        <option value="">Please select your main business activity</option>
                        <option value="packaging_manufacturing" {{ 'selected' if form_data.get('business_activity') == 'packaging_manufacturing' else '' }}>
                            📦 Packaging Manufacturing
                        </option>
                        <option value="paper_production" {{ 'selected' if form_data.get('business_activity') == 'paper_production' else '' }}>
                            📄 Paper Production
                        </option>
                        <option value="corrugated_packaging" {{ 'selected' if form_data.get('business_activity') == 'corrugated_packaging' else '' }}>
                            📐 Corrugated Packaging
                        </option>
                        <option value="flexible_packaging" {{ 'selected' if form_data.get('business_activity') == 'flexible_packaging' else '' }}>
                            🎯 Flexible Packaging
                        </option>
                        <option value="sustainable_packaging" {{ 'selected' if form_data.get('business_activity') == 'sustainable_packaging' else '' }}>
                            🌱 Sustainable Packaging Solutions
                        </option>
                    </select>
                    <div class="form-help">Choose the activity that best describes your core business</div>
                </div>
                
                <div class="form-group">
                    <label for="sub_activity">Sub-activity <span class="required">*</span></label>
                    <select name="sub_activity" id="sub_activity" required>
                        <option value="">Please select a business activity first</option>
                    </select>
                    <div class="form-help">Select your specific area of specialization</div>
                </div>
                
                <div class="form-group">
                    <label>Does your client have an online store? <span class="required">*</span></label>
                    <div class="radio-group">
                        <div class="radio-option">
                            <input 
                                type="radio" 
                                name="has_online_store" 
                                value="yes" 
                                id="online_yes"
                                {{ 'checked' if form_data.get('has_online_store') == 'yes' else '' }}
                                required
                                onchange="toggleOnlineStoreProducts()"
                            >
                            <label for="online_yes">Yes</label>
                        </div>
                        <div class="radio-option">
                            <input 
                                type="radio" 
                                name="has_online_store" 
                                value="no" 
                                id="online_no"
                                {{ 'checked' if form_data.get('has_online_store') == 'no' else '' }}
                                required
                                onchange="toggleOnlineStoreProducts()"
                            >
                            <label for="online_no">No</label>
                        </div>
                    </div>
                    <div class="form-help">This helps us understand your distribution channels</div>
                </div>

                <div class="form-group" id="online_store_products" style="display: none;">
                    <label>In their online store, my client sells... <span class="required">*</span></label>
                    <div class="radio-group" style="flex-direction: column; gap: 12px;">
                        <div class="radio-option">
                            <input 
                                type="radio" 
                                name="online_store_products" 
                                value="own_products" 
                                id="own_products"
                                {{ 'checked' if form_data.get('online_store_products') == 'own_products' else '' }}
                            >
                            <label for="own_products">Products they own</label>
                        </div>
                        <div class="radio-option">
                            <input 
                                type="radio" 
                                name="online_store_products" 
                                value="vendor_products" 
                                id="vendor_products"
                                {{ 'checked' if form_data.get('online_store_products') == 'vendor_products' else '' }}
                            >
                            <label for="vendor_products">Products owned by other vendors</label>
                        </div>
                        <div class="radio-option">
                            <input 
                                type="radio" 
                                name="online_store_products" 
                                value="both" 
                                id="both_products"
                                {{ 'checked' if form_data.get('online_store_products') == 'both' else '' }}
                            >
                            <label for="both_products">Both</label>
                        </div>
                    </div>
                    <div class="form-help">This helps us understand your business model and product sourcing</div>
                </div>
                
                <div class="navigation">
                    <a href="/membership/form/1" class="btn btn-secondary">← Previous Step</a>
                    <button type="submit" class="btn btn-primary">Continue →</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // Sub-activity options for each business activity
        const subActivities = {
            'packaging_manufacturing': [
                { value: 'rigid_containers', text: 'Rigid Containers & Boxes' },
                { value: 'protective_packaging', text: 'Protective Packaging Materials' },
                { value: 'custom_packaging', text: 'Custom Packaging Solutions' }
            ],
            'paper_production': [
                { value: 'kraft_paper', text: 'Kraft Paper Production' },
                { value: 'recycled_paper', text: 'Recycled Paper Products' },
                { value: 'specialty_papers', text: 'Specialty Papers & Boards' }
            ],
            'corrugated_packaging': [
                { value: 'shipping_boxes', text: 'Shipping & E-commerce Boxes' },
                { value: 'display_packaging', text: 'Display & Retail Packaging' },
                { value: 'industrial_packaging', text: 'Industrial Corrugated Solutions' }
            ],
            'flexible_packaging': [
                { value: 'food_packaging', text: 'Food & Beverage Packaging' },
                { value: 'pharmaceutical', text: 'Pharmaceutical Packaging' },
                { value: 'pouches_films', text: 'Pouches & Flexible Films' }
            ],
            'sustainable_packaging': [
                { value: 'biodegradable', text: 'Biodegradable Packaging' },
                { value: 'recycling_solutions', text: 'Recycling & Circular Solutions' },
                { value: 'eco_design', text: 'Eco-friendly Design Services' }
            ]
        };

        function updateSubActivities() {
            const businessActivity = document.getElementById('business_activity').value;
            const subActivitySelect = document.getElementById('sub_activity');
            
            // Clear existing options
            subActivitySelect.innerHTML = '<option value="">Please select a sub-activity</option>';
            
            if (businessActivity && subActivities[businessActivity]) {
                // Enable the sub-activity dropdown
                subActivitySelect.classList.add('enabled');
                
                // Add new options
                subActivities[businessActivity].forEach(option => {
                    const optionElement = document.createElement('option');
                    optionElement.value = option.value;
                    optionElement.textContent = option.text;
                    subActivitySelect.appendChild(optionElement);
                });
            } else {
                // Disable the sub-activity dropdown
                subActivitySelect.classList.remove('enabled');
                subActivitySelect.innerHTML = '<option value="">Please select a business activity first</option>';
            }
        }

        function toggleOnlineStoreProducts() {
            const hasOnlineStore = document.querySelector('input[name="has_online_store"]:checked');
            const onlineStoreProductsDiv = document.getElementById('online_store_products');
            const onlineStoreProductsInputs = document.querySelectorAll('input[name="online_store_products"]');
            
            if (hasOnlineStore && hasOnlineStore.value === 'yes') {
                onlineStoreProductsDiv.style.display = 'block';
                // Make the online store products field required when visible
                onlineStoreProductsInputs.forEach(input => {
                    input.required = true;
                });
            } else {
                onlineStoreProductsDiv.style.display = 'none';
                // Remove required attribute when hidden and clear selection
                onlineStoreProductsInputs.forEach(input => {
                    input.required = false;
                    input.checked = false;
                });
            }
        }

        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            updateSubActivities();
            toggleOnlineStoreProducts();
        });
    </script>
</body>
</html>
'''

MEMBERSHIP_STEP3_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Membership - Contact Information</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            margin: 0; padding: 20px; background: #f8f9fa; 
        }
        .container { max-width: 600px; margin: 0 auto; }
        .form-card { 
            background: white; padding: 30px; border-radius: 12px; 
            box-shadow: 0 4px 12px rgba(0,0,0,0.1); 
        }
        .header { text-align: center; margin-bottom: 30px; }
        .header h2 { color: #333; margin: 0 0 10px 0; font-size: 1.8em; }
        .header .subtitle { color: #6c757d; font-size: 1.1em; }
        .membership-badge {
            display: inline-block; background: #e3f2fd; color: #1976d2;
            padding: 6px 16px; border-radius: 20px; font-size: 14px;
            font-weight: 600; margin-bottom: 20px;
        }
        .progress { 
            background: #e9ecef; border-radius: 10px; margin-bottom: 30px; height: 8px; 
        }
        .progress-bar { 
            background: linear-gradient(90deg, #007bff, #0056b3); 
            height: 8px; border-radius: 10px; width: 75%; transition: width 0.3s; 
        }
        .step-info {
            text-align: center; color: #6c757d; margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group { margin-bottom: 25px; }
        .form-row {
            display: grid; grid-template-columns: 1fr 1fr; gap: 15px;
        }
        label { 
            display: block; margin-bottom: 8px; font-weight: 600; color: #555; 
            font-size: 15px;
        }
        input, select { 
            width: 100%; padding: 14px; border: 2px solid #ddd; border-radius: 8px; 
            font-size: 16px; transition: border-color 0.3s; background: white;
            box-sizing: border-box;
        }
        input:focus, select:focus { 
            border-color: #007bff; outline: none; box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
        }
        .required { color: #dc3545; }
        .form-help {
            font-size: 13px; color: #6c757d; margin-top: 5px;
        }
        .btn { 
            padding: 14px 28px; border: none; border-radius: 8px; cursor: pointer; 
            margin-right: 12px; font-weight: 600; transition: all 0.3s; 
            font-size: 16px; text-decoration: none; display: inline-block;
        }
        .btn-primary { background: #007bff; color: white; }
        .btn-primary:hover { background: #0056b3; transform: translateY(-1px); }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #545b62; }
        .navigation { 
            margin-top: 40px; display: flex; justify-content: space-between; 
            align-items: center; padding-top: 20px; border-top: 1px solid #e9ecef;
        }
        @media (max-width: 768px) {
            .form-row {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="form-card">
            <div class="header">
                <div class="membership-badge">📦 Packaging & Paper</div>
                <h2>Contact Information</h2>
                <p class="subtitle">We need your contact details</p>
            </div>
            
            <div class="progress">
                <div class="progress-bar"></div>
            </div>
            <div class="step-info">Step 3 of 4 - Contact Details</div>
            
            <form method="POST" action="/membership/form/3">
                <h3>🏢 Company Details</h3>
            
                <div class="form-group">
                    <label for="company_street">Number and Street <span class="required">*</span></label>
                    <input type="text" name="company_street" id="company_street" value="{{ form_data.get('company_street', '') }}" required>
                </div>
            
                <div class="form-row">
                    <div class="form-group">
                        <label for="company_postal_code">Postal Code <span class="required">*</span></label>
                        <input type="text" name="company_postal_code" id="company_postal_code" value="{{ form_data.get('company_postal_code', '') }}" required>
                    </div>
                    <div class="form-group">
                        <label for="company_city">City <span class="required">*</span></label>
                        <input type="text" name="company_city" id="company_city" value="{{ form_data.get('company_city', '') }}" required>
                    </div>
                </div>
            
                <div class="form-row">
                    <div class="form-group">
                        <label for="company_country">Country <span class="required">*</span></label>
                        <input type="text" name="company_country" id="company_country" value="{{ form_data.get('company_country', '') }}" required>
                    </div>
                    <div class="form-group">
                        <label for="company_phone">Phone Number</label>
                        <input type="tel" name="company_phone" id="company_phone" value="{{ form_data.get('company_phone', '') }}">
                    </div>
                </div>
            
                <div class="form-group">
                    <label for="company_website">Website</label>
                    <input type="url" name="company_website" id="company_website" value="{{ form_data.get('company_website', '') }}">
                </div>
            
                <hr style="margin: 40px 0; border-top: 1px solid #ddd;">
            
                <h3>👤 Contact Person within the Client Company</h3>
            
                <div class="form-group">
                    <label for="contact_salutation">Salutation <span class="required">*</span></label>
                    <select name="contact_salutation" id="contact_salutation" required>
                        <option value="">Please select</option>
                        <option value="Mr" {{ 'selected' if form_data.get('contact_salutation') == 'Mr' else '' }}>Mr</option>
                        <option value="Ms" {{ 'selected' if form_data.get('contact_salutation') == 'Ms' else '' }}>Ms</option>
                    </select>
                </div>
            
                <div class="form-row">
                    <div class="form-group">
                        <label for="first_name">First Name <span class="required">*</span></label>
                        <input type="text" name="first_name" id="first_name" value="{{ form_data.get('first_name', '') }}" required>
                    </div>
                    <div class="form-group">
                        <label for="last_name">Last Name <span class="required">*</span></label>
                        <input type="text" name="last_name" id="last_name" value="{{ form_data.get('last_name', '') }}" required>
                    </div>
                </div>
            
                <div class="form-group">
                    <label for="email">Email Address <span class="required">*</span></label>
                    <input type="email" name="email" id="email" value="{{ form_data.get('email', '') }}" required>
                </div>
            
                <div class="form-group">
                    <label for="phone">Phone Number</label>
                    <input type="tel" name="phone" id="phone" value="{{ form_data.get('phone', '') }}">
                </div>
            
                <div class="navigation">
                    <a href="/membership/form/2" class="btn btn-secondary">← Previous Step</a>
                    <button type="submit" class="btn btn-primary">Continue →</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
'''

MEMBERSHIP_STEP4_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Membership - Final Step</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            margin: 0; padding: 20px; background: #f8f9fa; 
        }
        .container { max-width: 600px; margin: 0 auto; }
        .form-card { 
            background: white; padding: 30px; border-radius: 12px; 
            box-shadow: 0 4px 12px rgba(0,0,0,0.1); 
        }
        .header { text-align: center; margin-bottom: 30px; }
        .header h2 { color: #333; margin: 0 0 10px 0; font-size: 1.8em; }
        .header .subtitle { color: #6c757d; font-size: 1.1em; }
        .membership-badge {
            display: inline-block; background: #e3f2fd; color: #1976d2;
            padding: 6px 16px; border-radius: 20px; font-size: 14px;
            font-weight: 600; margin-bottom: 20px;
        }
        .progress { 
            background: #e9ecef; border-radius: 10px; margin-bottom: 30px; height: 8px; 
        }
        .progress-bar { 
            background: linear-gradient(90deg, #007bff, #0056b3); 
            height: 8px; border-radius: 10px; width: 100%; transition: width 0.3s; 
        }
        .step-info {
            text-align: center; color: #6c757d; margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group { margin-bottom: 25px; }
        .checkbox-group {
            margin-bottom: 20px;
        }
        .checkbox-item {
            display: flex; align-items: flex-start; gap: 12px; margin-bottom: 15px;
            padding: 15px; border: 1px solid #e9ecef; border-radius: 8px;
            background: #f8f9fa;
        }
        .checkbox-item input[type="checkbox"] {
            width: auto; margin: 0; margin-top: 2px;
        }
        .checkbox-item label {
            margin: 0; font-weight: normal; cursor: pointer; line-height: 1.5;
        }
        .checkbox-item.required {
            border-color: #007bff; background: #f0f8ff;
        }
        .file-upload-section {
            background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px;
            border: 2px dashed #007bff;
        }
        .file-upload-section h4 {
            margin: 0 0 15px 0; color: #007bff; display: flex; align-items: center; gap: 8px;
        }
        .file-input-wrapper {
            position: relative; display: inline-block; width: 100%;
        }
        .file-input {
            width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px;
            background: white; cursor: pointer; font-size: 14px;
        }
        .file-input:hover {
            border-color: #007bff;
        }
        .file-help {
            font-size: 13px; color: #6c757d; margin-top: 8px;
        }
        .btn { 
            padding: 14px 28px; border: none; border-radius: 8px; cursor: pointer; 
            margin-right: 12px; font-weight: 600; transition: all 0.3s; 
            font-size: 16px; text-decoration: none; display: inline-block;
        }
        .btn-primary { background: #28a745; color: white; }
        .btn-primary:hover { background: #218838; transform: translateY(-1px); }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #545b62; }
        .navigation { 
            margin-top: 40px; display: flex; justify-content: space-between; 
            align-items: center; padding-top: 20px; border-top: 1px solid #e9ecef;
        }
        .required { color: #dc3545; }
        .summary {
            background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px;
            border-left: 4px solid #007bff;
        }
        .summary h3 {
            margin: 0 0 15px 0; color: #333;
        }
        .summary-item {
            display: flex; justify-content: space-between; margin-bottom: 8px;
        }
        .summary-label {
            font-weight: 600; color: #555;
        }
        .error-message {
            color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 6px;
            margin-bottom: 20px; font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="form-card">
            <div class="header">
                <div class="membership-badge">📦 Packaging & Paper</div>
                <h2>Review & Complete</h2>
                <p class="subtitle">Almost done! Please review and accept our terms</p>
            </div>
            
            <div class="progress">
                <div class="progress-bar"></div>
            </div>
            <div class="step-info">Step 4 of 4 - Final Step</div>
            
            <div class="summary">
                <h3>📋 Membership Summary</h3>
                <div class="summary-item">
                    <span class="summary-label">Company:</span>
                    <span>{{ form_data.get('company_name', 'Not provided') }}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Country:</span>
                    <span>{{ form_data.get('country', 'Not provided') }}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Business Activity:</span>
                    <span>{{ form_data.get('business_activity', 'Not provided') }}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Contact:</span>
                    <span>{{ form_data.get('first_name', '') }} {{ form_data.get('last_name', '') }}</span>
                </div>
            </div>
            
            <form method="POST" action="/membership/form/4" enctype="multipart/form-data">
                <div class="file-upload-section">
                    <h4>📄 Customer Consent Confirmation</h4>
                    <div class="file-input-wrapper">
                        <input 
                            type="file" 
                            name="consent_document" 
                            id="consent_document" 
                            class="file-input"
                            accept=".pdf"
                            onchange="updateFileName(this)"
                        >
                    </div>
                    <div class="file-help">
                        Please upload a PDF document confirming customer consent. Maximum file size: 16MB.
                        <br><strong>Accepted format:</strong> PDF files only
                    </div>
                </div>
                
                <div class="checkbox-group">
                    <div class="checkbox-item required">
                        <input 
                            type="checkbox" 
                            name="terms_consent" 
                            id="terms_consent"
                            value="1"
                            {{ 'checked' if form_data.get('terms_consent') else '' }}
                            required
                        >
                        <label for="terms_consent">
                            <strong>I accept the Terms and Conditions <span class="required">*</span></strong><br>
                            I have read and agree to the membership terms, conditions, and policies.
                        </label>
                    </div>
                    
                    <div class="checkbox-item">
                        <input 
                            type="checkbox" 
                            name="data_processing_consent" 
                            id="data_processing_consent"
                            value="1"
                            {{ 'checked' if form_data.get('data_processing_consent') else '' }}
                        >
                        <label for="data_processing_consent">
                            <strong>Data Processing Consent</strong><br>
                            I consent to the processing of my personal data for membership management purposes.
                        </label>
                    </div>
                    
                    <div class="checkbox-item">
                        <input 
                            type="checkbox" 
                            name="marketing_consent" 
                            id="marketing_consent"
                            value="1"
                            {{ 'checked' if form_data.get('marketing_consent') else '' }}
                        >
                        <label for="marketing_consent">
                            <strong>Marketing Communications</strong><br>
                            I would like to receive updates about industry news, events, and relevant opportunities.
                        </label>
                    </div>
                </div>
                
                <div class="navigation">
                    <a href="/membership/form/3" class="btn btn-secondary">← Previous Step</a>
                    <button type="submit" class="btn btn-primary">✓ Complete Registration</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function updateFileName(input) {
            if (input.files && input.files[0]) {
                const fileName = input.files[0].name;
                const fileSize = input.files[0].size;
                const maxSize = 16 * 1024 * 1024; // 16MB
                
                if (fileSize > maxSize) {
                    alert('File size exceeds 16MB limit. Please choose a smaller file.');
                    input.value = '';
                    return;
                }
                
                if (!fileName.toLowerCase().endsWith('.pdf')) {
                    alert('Please select a PDF file only.');
                    input.value = '';
                    return;
                }
                
                // Update the visual feedback (optional)
                console.log('File selected:', fileName);
            }
        }

        // Prevent form submission if file is too large
        document.querySelector('form').addEventListener('submit', function(e) {
            const fileInput = document.getElementById('consent_document');
            if (fileInput.files[0]) {
                const fileSize = fileInput.files[0].size;
                const maxSize = 16 * 1024 * 1024; // 16MB
                
                if (fileSize > maxSize) {
                    e.preventDefault();
                    alert('File size exceeds 16MB limit. Please choose a smaller file.');
                    return false;
                }
            }
        });
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_ENV") == "development")
