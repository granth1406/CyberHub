# 🔐 CyberHub

**CyberHub** is an all-in-one cybersecurity web app that helps users scan files and URLs for malware, phishing, and other online threats. Designed to be powerful yet simple, it’s the perfect tool for students, employees, and everyday users who want to stay safe online — without needing to be cybersecurity experts.

---

## 🌐 Live Demo

> Coming soon...

---

## 🚀 Features

- 🛡️ **File & URL Scanning**  
  Upload files or enter URLs to detect malware, phishing, or suspicious behavior.

- 📊 **Interactive Threat Reports**  
  Get clear, in-browser reports with a safety score, risk reasons, and action tips.

- 🧠 **Heuristic Analysis**  
  Detect suspicious behavior patterns — not just known viruses.

- 🌍 **Real-Time Threat Intelligence**  
  Uses up-to-date info from global threat databases and APIs.

- 📂 **Macro/Script Viewer**  
  View hidden scripts inside documents (DOCX, PDF, etc.) before opening them.

- 📧 **Email Scam Checker**  
  Analyze headers, sender info, and message content to detect phishing.

- 🌑 **Dark Web Scanner**  
  Check if your emails, usernames, or passwords have been leaked.

- 📦 **Bulk Scanner**  
  Upload multiple files or URLs at once for batch scanning.

- 🧠 **Learning Zone**  
  Interactive mini-games and guides to learn cyber awareness and scam detection.

- 🧩 **Browser Extension (Coming Soon)**  
  Warns users instantly when visiting unsafe websites.

---

## 🧱 Tech Stack

| Layer      | Tech Used                          |
|------------|------------------------------------|
| Frontend   | React.js, Tailwind CSS             |
| Backend    | Node.js + Express.js               |
| Security   | VirusTotal API, Google SafeBrowsing, AbuseIPDB, HaveIBeenPwned, WHOIS lookups |
| Analysis   | Custom heuristics, file scanning, macro/script parsing |
| Storage    | MongoDB or PostgreSQL              |
| Tools      | Docker, Git, REST APIs             |

---

## 📁 Folder Structure

```bash
CyberHub/
├── client/         # React frontend
├── server/         # Node.js + Express backend
├── scripts/        # Macro/script analyzer tools
├── scanner/        # Heuristics + API wrappers
├── public/         # Static assets
└── README.md
