 🛡️ Phishing Shield | AI Neural Engine V3.0

Phishing Shield** is an enterprise-grade, full-stack cybersecurity application designed to detect, analyze, and prevent phishing attacks using Machine Learning and Global Threat Intelligence. This system provides a comprehensive forensic analysis for suspicious URLs and malicious QR codes.

 🌟 Key Features

🧠 AI Neural Engine:** Utilizes a trained Random Forest classifier to analyze URL features (Entropy, IP usage, HTTPS protocols) with a **96.7% confidence score**.
🌍 Global Threat Intel (VirusTotal):** Integrated with the **VirusTotal API v3** to cross-reference URLs against 70+ global security vendors like Kaspersky and BitDefender in real-time.
📷 QR Code Forensic Scanner:** A custom image processing pipeline using OpenCV to extract and analyze hidden phishing payloads within QR codes.
📊 SIEM Analytics Dashboard:** A real-time Security Information and Event Management (SIEM) dashboard that visualizes scan history, threat trends, and safe entities.
📄 Automated Forensic Dossiers:** Generates downloadable, professional PDF reports detailing domain age, protocol security, and threat intelligence scores.
🔐 Classified Admin Portal:** A secure, password-protected backend endpoint (`/cyber-admin`) for administrators to monitor the complete SQL database logs.


💻 Tech Stack

Backend: Python 3, Flask
Machine Learning: Scikit-Learn (Random Forest), NumPy
APIs & Intel: VirusTotal API v3, Python-Whois
Computer Vision:  OpenCV (`cv2`)
Frontend: HTML5, CSS3 (Glassmorphism UI), JavaScript, Chart.js
Database: SQLite3
Reporting: FPDF


⚙️ Installation & Setup

1. Clone the repository:**
   bash
   git clone [https://github.com/dahamsividara-dotcom/Phishing-Shield-Neural-Engine.git](https://github.com/dahamsividara-dotcom/Phishing-Shield-Neural-Engine.git)
