<p align="center">
  <img src="https://img.shields.io/badge/GITHUB-PROJECT-181717?style=for-the-badge&logo=github&logoColor=white"/>
  <img src="https://img.shields.io/badge/PYTHON-TOOL-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/CYBER-DARKNAY-1f6feb?style=for-the-badge"/>
</p>

---

# 🔍 WEB SECURITY AUDIT SCANNER

> Lightweight security scanner for detecting exposed secrets, API keys, authentication tokens, and sensitive misconfigurations in web applications.

**Developed by Cyber DarkNay**

---

## ⚡ FEATURES

- 🔑 Detect exposed API Keys (Google, AWS, Stripe, etc)
- 🔐 Detect Authorization & Bearer Tokens
- 🍪 Cookie & Session leakage detection
- 🧠 Base64 hidden data decoding
- 🌐 Deep crawling (JS files, endpoints, links)
- ⚡ Multi-thread fast scanning engine
- 🖥️ Clean and structured terminal output

---

## 🚀 INSTALLATION

```bash
git clone https://github.com/Cyber-DarkNay/SCAN_API.git
cd SCAN_API
pip install requests beautifulsoup4
```

---

## ▶️ USAGE
```
python scan_api.py

Enter target:

https://example.com
```

---

## 📡 SAMPLE OUTPUT
```
[API KEY LEAK]
URL  : https://target.com/app.js
DATA : sk_live_xxxxxxxxx

[AUTH LEAK]
URL  : https://target.com/api
DATA : Bearer eyJhbGciOiJIUzI1NiIs...

[COOKIE FOUND]
URL  : https://target.com
DATA : sessionid=abc123; HttpOnly; Secure
```

---

##  DISCLAIMER

This tool is for:

✔ Security research
✔ Bug bounty programs
✔ Educational purposes only

❌ Do NOT use on systems without permission


---

## 👤 AUTHOR
```
Cyber DarkNay
```
---

