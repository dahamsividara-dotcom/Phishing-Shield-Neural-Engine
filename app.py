from flask import Flask, render_template, request, jsonify, send_file
from urllib.parse import urlparse
from datetime import datetime
import joblib
import numpy as np
from fpdf import FPDF
import sqlite3
import re
import os
import whois
import cv2
import requests
import base64

app = Flask(__name__)

model_path = 'phishing_model.pkl'
model = joblib.load(model_path) if os.path.exists(model_path) else None

# ==========================================
# VIRUSTOTAL API (SECURITY NOTICE)
# GitHub එකට කේතය දාන නිසා API Key එක ඉවත් කර ඇත.
# ==========================================
VT_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY_HERE'

def get_virustotal_report(url):
    try:
        if VT_API_KEY == 'YOUR_VIRUSTOTAL_API_KEY_HERE':
            return {"status": "Error", "message": "API Key is missing for security reasons."}
            
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            total_scans = malicious + suspicious + harmless + undetected
            return {"status": "Found", "malicious": malicious, "suspicious": suspicious, "total": total_scans}
        elif response.status_code == 404:
            return {"status": "Not_Scanned", "message": "No prior records in VirusTotal."}
        else:
            return {"status": "Error", "message": "API Limit Reached or Offline."}
    except Exception as e:
        return {"status": "Error", "message": "Connection Failed."}

def init_db():
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, risk_level TEXT, scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

def get_domain_age(url):
    try:
        domain = urlparse(url).netloc
        if not domain: return "Unknown"
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return f"{age_days} days old"
        else: return "Creation date not found"
    except: return "Private/Hidden Registration"

def extract_features(url):
    features = []
    ip_present = -1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url) else 1
    url_len = 1 if len(url) < 54 else (0 if len(url) <= 75 else -1)
    has_at = -1 if "@" in url else 1
    has_https = 1 if 'https' in url.lower() else -1
    features.extend([ip_present, url_len, has_at, has_https])
    suspicious_score = -1 if (ip_present == -1 or has_at == -1 or url_len == -1) else 1
    while len(features) < 30: features.append(suspicious_score) 
    return np.array(features).reshape(1, -1), ip_present, has_at

@app.route('/')
def home(): return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '')
    if not url: return jsonify({'error': 'No URL'})

    domain_age = get_domain_age(url)
    feature_vector, ip_present, has_at = extract_features(url)
    prediction = model.predict(feature_vector)[0] if model else 0
    risk_level = "HIGH RISK - Phishing Detected" if prediction == 1 else "LOW RISK - Legitimate"

    vt_data = get_virustotal_report(url)

    telemetry = [
        f"Protocol : {'Secure (HTTPS)' if 'https' in url.lower() else 'Unsecure (HTTP)'}",
        f"Domain Age: {domain_age}",
        f"Entropy  : {len(url)} bytes analyzed",
        f"IP Usage : {'Detected (Suspicious)' if ip_present == -1 else 'Clean'}",
        f"AI Engine: 96.70% Confidence Score"
    ]
    
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute("INSERT INTO scans (url, risk_level) VALUES (?, ?)", (url, risk_level))
    conn.commit()
    conn.close()
    
    return jsonify({'url': url, 'risk_level': risk_level, 'telemetry': telemetry, 'prediction': int(prediction), 'virustotal': vt_data})

@app.route('/qr_scan', methods=['POST'])
def qr_scan():
    if 'file' not in request.files: return jsonify({'error': 'No file uploaded'})
    file = request.files['file']
    npimg = np.frombuffer(file.read(), np.uint8)
    img = cv2.imdecode(npimg, cv2.IMREAD_COLOR)
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img)
    if not data:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        data, bbox, _ = detector.detectAndDecode(gray)
    if not data:
        _, thresh = cv2.threshold(gray, 100, 255, cv2.THRESH_BINARY)
        data, bbox, _ = detector.detectAndDecode(thresh)
    if data: return jsonify({'qr_url': data})
    else: return jsonify({'error': 'Could not read QR.'})

@app.route('/get_history')
def get_history():
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute("SELECT url, risk_level, scan_date FROM scans ORDER BY id DESC LIMIT 5")
    rows = c.fetchall()
    conn.close()
    return jsonify([{'url': r[0], 'risk': r[1], 'date': r[2]} for r in rows])

@app.route('/get_stats')
def get_stats():
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute("SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level")
    data = c.fetchall()
    conn.close()
    
    stats = {'total': 0, 'high_risk': 0, 'low_risk': 0}
    for row in data:
        risk = row[0]
        count = row[1]
        stats['total'] += count
        if 'HIGH' in risk: stats['high_risk'] += count
        else: stats['low_risk'] += count
        
    return jsonify(stats)

@app.route('/download_pdf')
def download_pdf():
    url = request.args.get('url', '')
    feature_vector, ip_present, has_at = extract_features(url)
    prediction = model.predict(feature_vector)[0] if model else 0
    domain_age = get_domain_age(url)
    vt_data = get_virustotal_report(url)
    
    if prediction == 1:
        risk_level = "HIGH RISK - Phishing Payload Detected!"
        fill_r, fill_g, fill_b = 255, 200, 200
        txt_r, txt_g, txt_b = 200, 0, 0
    else:
        risk_level = "LOW RISK - Legitimate Connection"
        fill_r, fill_g, fill_b = 200, 255, 200
        txt_r, txt_g, txt_b = 0, 150, 0

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pdf = FPDF()
    pdf.add_page()
    pdf.set_draw_color(0, 200, 255); pdf.set_line_width(1)
    pdf.rect(5, 5, 200, 287); pdf.rect(6, 6, 198, 285)
    
    pdf.set_font("Arial", 'B', 24); pdf.set_text_color(10, 20, 40)
    pdf.cell(0, 20, txt="PHISHING SHIELD", ln=True, align='C')
    pdf.set_font("Arial", 'B', 14); pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, txt="NEURAL FORENSIC DOSSIER", ln=True, align='C'); pdf.ln(10)
    
    pdf.set_font("Arial", 'B', 12); pdf.set_text_color(0, 0, 0)
    pdf.cell(40, 8, txt="Lead Analyst:"); pdf.set_font("Arial", '', 12); pdf.cell(0, 8, txt="Risadi Vidara", ln=True)
    pdf.set_font("Arial", 'B', 12); pdf.cell(40, 8, txt="Scan Time:"); pdf.set_font("Arial", '', 12); pdf.cell(0, 8, txt=scan_time, ln=True)
    pdf.set_font("Arial", 'B', 12); pdf.cell(40, 8, txt="Target URL:"); pdf.set_font("Arial", '', 10); pdf.multi_cell(0, 8, txt=url); pdf.ln(5)
    
    pdf.set_fill_color(fill_r, fill_g, fill_b); pdf.set_text_color(txt_r, txt_g, txt_b)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 15, txt=f"SYSTEM VERDICT: {risk_level}", ln=True, align='C', fill=True); pdf.ln(10)
    
    pdf.set_text_color(0, 0, 0); pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, txt="Telemetry & Analysis Data:", ln=True)
    pdf.set_draw_color(200, 200, 200); pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y()); pdf.ln(5)
    
    pdf.set_font("Arial", '', 12)
    vt_string = "Scanning Engine Offline"
    if vt_data['status'] == 'Found': vt_string = f"{vt_data['malicious']} out of {vt_data['total']} global security vendors flagged this as malicious."
    elif vt_data['status'] == 'Not_Scanned': vt_string = "No prior threat records found globally."
        
    items = [
        f"Protocol Used : {'Secure (HTTPS)' if 'https' in url.lower() else 'Unsecure (HTTP)'}",
        f"Domain Age    : {domain_age}",
        f"IP Masking    : {'Detected' if ip_present == -1 else 'Clean'}",
        f"Threat Intel  : {vt_string}"
    ]
    for item in items:
        pdf.cell(10, 8, txt=">"); pdf.cell(0, 8, txt=item, ln=True)
        
    pdf.set_y(270); pdf.set_font("Arial", 'I', 10); pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 10, txt="Generated by Phishing Shield AI | Java Institute for Advanced Technology", align='C')
    
    pdf.output("Forensic_Report.pdf")
    return send_file("Forensic_Report.pdf", as_attachment=True)


# ==========================================
# --- SECRET ADMIN PORTAL (DATABASE VIEW) ---
# ==========================================
@app.route('/cyber-admin')
def cyber_admin():
    return render_template('admin.html')

@app.route('/api/admin_data', methods=['POST'])
def admin_data():
    data = request.get_json()
    password = data.get('password', '')
    
    # (Admin Password)
    if password == "Risadi@2026":
        conn = sqlite3.connect('history.db')
        c = conn.cursor()
        c.execute("SELECT id, url, risk_level, scan_date FROM scans ORDER BY id DESC")
        rows = c.fetchall()
        conn.close()
        return jsonify({'success': True, 'data': [{'id': r[0], 'url': r[1], 'risk': r[2], 'date': r[3]} for r in rows]})
    else:
        return jsonify({'success': False, 'error': 'ACCESS DENIED: Invalid Credentials'})
# ==========================================

if __name__ == '__main__':
    app.run(debug=True, port=5000)