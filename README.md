# 🚨 Phishing Attack Simulation and Detection System

A multi-layer phishing detection system that analyzes email headers, content, and URLs using Python. This project includes phishing simulation, automated detection, and validation using real-world security tools.

---

## 📌 Project Overview

Phishing is one of the most common and dangerous cyber attacks where attackers trick users into revealing sensitive information through fake emails.

This project demonstrates:

- Simulation of a phishing email  
- Analysis of email headers and authentication mechanisms  
- Detection of phishing indicators using Python  
- Comparison between phishing and legitimate emails  

---

## ⚙️ Features

### 🔍 Header Analysis
- Detects SPF, DKIM, and DMARC failures  
- Identifies spoofed or unauthenticated senders  

### 🧠 Content Analysis
- Detects phishing keywords (urgent, verify, login, password)  
- Identifies social engineering patterns  
- Flags generic greetings (e.g., Dear Customer)  

### 🌐 URL & Domain Analysis
- Extracts URLs from email body  
- Detects suspicious domains and TLDs  
- Identifies domain mismatch  
- Entropy-based detection for random domains  

### 📊 Risk Scoring System
- Weighted scoring model  
- Classification:
  - High Risk Phishing  
  - Suspicious  
  - Likely Legitimate  

### 📁 Output
- Generates structured JSON report  
- Provides explainable flags for detection  

---

## 🛠️ Tools & Technologies

- Python (email parsing, regex, URL analysis)
- Google Admin Toolbox (Header Analysis)
- MXToolbox (Email Diagnostics)
- VirusTotal (URL Scanning)

---

## 📂 Project Structure
Phishing-Detection-System/
│
├── phishing_detector.py
├── phishing_sample.eml
├── legitimate_sample.eml
├── report.json
├── screenshots/
│ ├── phishing_header.png
│ ├── mxtoolbox.png
│ ├── virustotal.png
│ ├── legit_header.png
│ ├── phishing_output.png
│ └── legit_output.png
└── README.md

---

## ▶️ How to Run
  python phishing_detector.py phishing_sample.eml
  
---
## 📊 Results

- Phishing email detected as **High Risk**
- Legitimate email detected as **Likely Legitimate**
- Successfully identified:
  - Authentication failures (SPF, DKIM, DMARC)
  - Suspicious URLs and domains
  - Social engineering patterns (urgency, generic greetings)

---

## 📸 Screenshots

This repository includes:

- Phishing email header analysis (Google Admin Toolbox)  
- MXToolbox diagnostic results  
- VirusTotal URL scan  
- Legitimate email header verification  
- Detection system outputs (phishing & legitimate)  

---

## 🔐 Key Learnings

- Understanding of email authentication (SPF, DKIM, DMARC)  
- Practical phishing detection techniques  
- URL and domain intelligence analysis  
- Importance of multi-layer security approach  

---

## 📈 Future Improvements

- Integration with machine learning models  
- Real-time email filtering system  
- Threat intelligence API integration  
- Browser extension for phishing detection  

---

## 👩‍💻 Author

**Hemamalini Githolla**  
Cybersecurity Student
