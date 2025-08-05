from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
import requests
import os
import psycopg2
import psycopg2.extras
import hashlib
from datetime import datetime
import json
import sqlite3

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key-change-in-production")
FRIENDLY_CAPTCHA_SECRET = os.getenv("FRIENDLY_CAPTCHA_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")

# Datenbankverbindung für PostgreSQL (Render Standard)
def get_db_connection():
    if DATABASE_URL:
        # Render PostgreSQL
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    else:
        # Lokale SQLite für Development
        import sqlite3
        conn = sqlite3.connect('companies.db')
        conn.row_factory = sqlite3.Row
        return conn

# Datenbankinitialisierung
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    
    if DATABASE_URL:
        # PostgreSQL Tabellen
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS companies (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        company_name VARCHAR(255) NOT NULL,
                        legal_form VARCHAR(100),
                        street TEXT,
                        zip_code VARCHAR(20),
                        city VARCHAR(100),
                        country VARCHAR(100),
                        phone VARCHAR(50),
                        email VARCHAR(255),
                        website TEXT,
                        industry VARCHAR(100),
                        employees VARCHAR(50),
                        founded_year INTEGER,
                        tax_number VARCHAR(100),
                        vat_number VARCHAR(100),
                        data_processing_consent BOOLEAN DEFAULT FALSE,
                        marketing_consent BOOLEAN DEFAULT FALSE,
                        terms_consent BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )''')
        
        # Testuser für PostgreSQL
        password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cur.execute('''INSERT INTO users (username, password_hash) VALUES (%s, %s) 
                      ON CONFLICT (username) DO NOTHING''', ('admin', password_hash))
    else:
        # SQLite Tabellen (für lokale Entwicklung)
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS companies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        company_name TEXT NOT NULL,
                        legal_form TEXT,
                        street TEXT,
                        zip_code TEXT,
                        city TEXT,
                        country TEXT,
                        phone TEXT,
                        email TEXT,
                        website TEXT,
                        industry TEXT,
                        employees TEXT,
                        founded_year INTEGER,
                        tax_number TEXT,
                        vat_number TEXT,
                        data_processing_consent BOOLEAN DEFAULT 0,
                        marketing_consent BOOLEAN DEFAULT 0,
                        terms_consent BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )''')
        
        password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cur.execute('INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)', 
                   ('admin', password_hash))
    
    conn.commit()
    conn.close()

# Hilfsfunktionen
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

def get_user_companies(user_id):
    conn = get_db_connection()
    if DATABASE_URL:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('SELECT * FROM companies WHERE user_id = %s ORDER BY created_at DESC', (user_id,))
    else:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute('SELECT * FROM companies WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    
    companies = cur.fetchall()
    conn.close()
    return companies

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
    
    # Captcha verifizieren (nur wenn Secret gesetzt)
    if FRIENDLY_CAPTCHA_SECRET and solution:
        try:
            captcha_response = requests.post(
                "https://api.friendlycaptcha.com/api/v1/siteverify",
                data={"solution": solution, "secret": FRIENDLY_CAPTCHA_SECRET},
                timeout=5
            )
            result = captcha_response.json()
            if not result.get("success"):
                return redirect(url_for('index', error='Captcha fehlgeschlagen'))
        except:
            # Bei Captcha-Fehlern trotzdem weitermachen (für Development)
            pass
    
    # User verifizieren
    user_id = verify_user(username, password)
    if user_id:
        session['user_id'] = user_id
        session['username'] = username
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('index', error='Ungültige Anmeldedaten'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    companies = get_user_companies(session['user_id'])
    return render_template_string(DASHBOARD_TEMPLATE, 
                                username=session['username'], 
                                companies=companies)

@app.route('/company/new')
def new_company():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    session['company_form'] = {}
    return redirect(url_for('company_form', step=1))

@app.route('/company/form/<int:step>')
def company_form(step):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    if step < 1 or step > 4:
        return redirect(url_for('company_form', step=1))
    
    form_data = session.get('company_form', {})
    
    templates = {
        1: FORM_STEP1_TEMPLATE,
        2: FORM_STEP2_TEMPLATE, 
        3: FORM_STEP3_TEMPLATE,
        4: FORM_STEP4_TEMPLATE
    }
    
    return render_template_string(templates[step], form_data=form_data, step=step)

@app.route('/company/form/<int:step>', methods=['POST'])
def save_company_step(step):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    if 'company_form' not in session:
        session['company_form'] = {}
    
    form_data = session['company_form']
    
    if step == 1:
        form_data.update({
            'company_name': request.form.get('company_name'),
            'legal_form': request.form.get('legal_form'),
            'founded_year': request.form.get('founded_year'),
            'tax_number': request.form.get('tax_number'),
            'vat_number': request.form.get('vat_number')
        })
    elif step == 2:
        form_data.update({
            'street': request.form.get('street'),
            'zip_code': request.form.get('zip_code'),
            'city': request.form.get('city'),
            'country': request.form.get('country'),
            'phone': request.form.get('phone'),
            'email': request.form.get('email'),
            'website': request.form.get('website')
        })
    elif step == 3:
        form_data.update({
            'industry': request.form.get('industry'),
            'employees': request.form.get('employees')
        })
    elif step == 4:
        form_data.update({
            'data_processing_consent': bool(request.form.get('data_processing_consent')),
            'marketing_consent': bool(request.form.get('marketing_consent')),
            'terms_consent': bool(request.form.get('terms_consent'))
        })
        
        # Firma in Datenbank speichern
        conn = get_db_connection()
        cur = conn.cursor()
        
        if DATABASE_URL:
            cur.execute('''INSERT INTO companies 
                          (user_id, company_name, legal_form, street, zip_code, city, country, 
                           phone, email, website, industry, employees, founded_year, tax_number, vat_number,
                           data_processing_consent, marketing_consent, terms_consent)
                          VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                         (session['user_id'], form_data.get('company_name'), form_data.get('legal_form'),
                          form_data.get('street'), form_data.get('zip_code'), form_data.get('city'),
                          form_data.get('country'), form_data.get('phone'), form_data.get('email'),
                          form_data.get('website'), form_data.get('industry'), form_data.get('employees'),
                          int(form_data.get('founded_year')) if form_data.get('founded_year') else None,
                          form_data.get('tax_number'), form_data.get('vat_number'),
                          form_data.get('data_processing_consent', False),
                          form_data.get('marketing_consent', False),
                          form_data.get('terms_consent', True)))
        else:
            cur.execute('''INSERT INTO companies 
                          (user_id, company_name, legal_form, street, zip_code, city, country, 
                           phone, email, website, industry, employees, founded_year, tax_number, vat_number,
                           data_processing_consent, marketing_consent, terms_consent)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                         (session['user_id'], form_data.get('company_name'), form_data.get('legal_form'),
                          form_data.get('street'), form_data.get('zip_code'), form_data.get('city'),
                          form_data.get('country'), form_data.get('phone'), form_data.get('email'),
                          form_data.get('website'), form_data.get('industry'), form_data.get('employees'),
                          int(form_data.get('founded_year')) if form_data.get('founded_year') else None,
                          form_data.get('tax_number'), form_data.get('vat_number'),
                          form_data.get('data_processing_consent', False),
                          form_data.get('marketing_consent', False),
                          form_data.get('terms_consent', True)))
        
        conn.commit()
        conn.close()
        
        session.pop('company_form', None)
        return redirect(url_for('dashboard'))
    
    session['company_form'] = form_data
    next_step = step + 1 if step < 4 else 4
    return redirect(url_for('company_form', step=next_step))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Health Check für Render
@app.route('/health')
def health_check():
    return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}

# Template-Konstanten (extern ausgelagert für bessere Wartbarkeit)
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Firmenverwaltung</title>
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
        <h2>🏢 Firmenverwaltung</h2>
        {% if error %}
            <div class="error">❌ {{ error }}</div>
        {% endif %}
        <form method="POST" action="/submit">
            <div class="form-group">
                <input type="text" name="username" placeholder="Benutzername" required />
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="Passwort" required />
            </div>
            <div class="form-group">
                <div class="frc-captcha" data-sitekey="FCMLUC8UHAIO4Q8G"></div>
            </div>
            <button type="submit">Anmelden</button>
        </form>
        <div class="test-info">
            <strong>Testaccount:</strong><br>
            Benutzername: admin<br>
            Passwort: admin123
        </div>
    </div>
    <script src="https://unpkg.com/friendly-challenge@0.9.9/widget.module.min.js" type="module"></script>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Firmenverwaltung</title>
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
        .add-button { margin-bottom: 30px; }
        .company-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 25px; }
        .company-card { 
            background: white; border-radius: 12px; padding: 25px; 
            box-shadow: 0 4px 12px rgba(0,0,0,0.1); transition: transform 0.3s, box-shadow 0.3s;
        }
        .company-card:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0,0,0,0.15); }
        .company-card h3 { margin: 0 0 15px 0; color: #007bff; font-size: 1.3em; }
        .company-info { margin: 15px 0; line-height: 1.6; }
        .company-info strong { color: #555; }
        .company-actions { margin-top: 20px; display: flex; gap: 10px; }
        .company-actions .btn { padding: 8px 16px; font-size: 14px; }
        .empty-state { text-align: center; padding: 80px 20px; color: #6c757d; }
        .empty-state h3 { font-size: 1.5em; margin-bottom: 15px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                 gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 12px; 
                     box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007bff; }
        .stat-label { color: #6c757d; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏢 Firmenverwaltung</h1>
            <div class="user-info">
                <span>Willkommen, <strong>{{ username }}</strong>!</span>
                <a href="/logout" class="btn btn-secondary">Abmelden</a>
            </div>
        </div>
        
        {% if companies %}
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{{ companies|length }}</div>
                <div class="stat-label">Firmen insgesamt</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ companies|selectattr('industry')|list|length }}</div>
                <div class="stat-label">Mit Branche</div>
            </div>
        </div>
        {% endif %}
        
        <div class="add-button">
            <a href="/company/new" class="btn btn-primary">+ Neue Firma anlegen</a>
        </div>
        
        {% if companies %}
            <div class="company-grid">
                {% for company in companies %}
                <div class="company-card">
                    <h3>{{ company.company_name }}</h3>
                    <div class="company-info">
                        <strong>Rechtsform:</strong> {{ company.legal_form or 'Nicht angegeben' }}<br>
                        <strong>Ort:</strong> {{ company.city or 'Nicht angegeben' }}<br>
                        <strong>Branche:</strong> {{ company.industry or 'Nicht angegeben' }}<br>
                        <strong>Mitarbeiter:</strong> {{ company.employees or 'Nicht angegeben' }}
                    </div>
                    <div class="company-actions">
                        <a href="/company/{{ company.id }}/view" class="btn btn-primary">Anzeigen</a>
                        <a href="/company/{{ company.id }}/edit" class="btn btn-secondary">Bearbeiten</a>
                    </div>
                </div>
                {% endfor %}
            </div>
        {% else %}
            <div class="empty-state">
                <h3>🏭 Noch keine Firmen angelegt</h3>
                <p>Klicken Sie auf "Neue Firma anlegen" um zu beginnen.</p>
            </div>
        {% endif %}
    </div>
</body>
</html>
'''

# Weitere Templates...
FORM_STEP1_TEMPLATE = '''
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Neue Firma - Grunddaten</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
               margin: 0; padding: 20px; background: #f8f9fa; }
        .container { max-width: 600px; margin: 0 auto; }
        .form-card { background: white; padding: 30px; border-radius: 12px; 
                     box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        h2 { color: #333; margin-bottom: 20px; }
        .progress { background: #e9ecef; border-radius: 10px; margin-bottom: 30px; height: 8px; }
        .progress-bar { background: linear-gradient(90deg, #007bff, #0056b3); 
                        height: 8px; border-radius: 10px; width: 25%; transition: width 0.3s; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: 600; color: #555; }
        input, select { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; 
                        font-size: 16px; transition: border-color 0.3s; }
        input:focus, select:focus { border-color: #007bff; outline: none; }
        .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; 
               margin-right: 10px; font-weight: 600; transition: all 0.3s; }
        .btn-primary { background: #007bff; color: white; }
        .btn-primary:hover { background: #0056b3; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #545b62; }
        .navigation { margin-top: 30px; display: flex; justify-content: space-between; }
        .required { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <div class="form-card">
            <h2>🏢 Neue Firma anlegen - Grunddaten</h2>
            <div class="progress">
                <div class="progress-bar"></div>
            </div>
            
            <form method="POST">
                <div class="form-group">
                    <label>Firmenname <span class="required">*</span></label>
                    <input type="text" name="company_name" value="{{ form_data.get('company_name', '') }}" required>
                </div>
                
                <div class="form-group">
                    <label>Rechtsform</label>
                    <select name="legal_form">
                        <option value="">Bitte wählen</option>
                        <option value="GmbH" {% if form_data.get('legal_form') == 'GmbH' %}selected{% endif %}>GmbH</option>
                        <option value="AG" {% if form_data.get('legal_form') == 'AG' %}selected{% endif %}>AG</option>
                        <option value="UG" {% if form_data.get('legal_form') == 'UG' %}selected{% endif %}>UG (haftungsbeschränkt)</option>
                        <option value="OHG" {% if form_data.get('legal_form') == 'OHG' %}selected{% endif %}>OHG</option>
                        <option value="KG" {% if form_data.get('legal_form') == 'KG' %}selected{% endif %}>KG</option>
                        <option value="Einzelunternehmen" {% if form_data.get('legal_form') == 'Einzelunternehmen' %}selected{% endif %}>Einzelunternehmen</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Gründungsjahr</label>
                    <input type="number" name="founded_year" min="1800" max="2024" value="{{ form_data.get('founded_year', '') }}">
                </div>
                
                <div class="form-group">
                    <label>Steuernummer</label>
                    <input type="text" name="tax_number" value="{{ form_data.get('tax_number', '') }}">
                </div>
                
                <div class="form-group">
                    <label>Umsatzsteuer-ID</label>
                    <input type="text" name="vat_number" value="{{ form_data.get('vat_number', '') }}">
                </div>
                
                <div class="navigation">
                    <a href="/dashboard" class="btn btn-secondary">Abbrechen</a>
                    <button type="submit" class="btn btn-primary">Weiter →</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
'''

# Weitere Templates folgen dem gleichen Muster...
FORM_STEP2_TEMPLATE = "<!-- Step 2 Template hier -->"
FORM_STEP3_TEMPLATE = "<!-- Step 3 Template hier -->"  
FORM_STEP4_TEMPLATE = "<!-- Step 4 Template hier -->"

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_ENV") == "development")
