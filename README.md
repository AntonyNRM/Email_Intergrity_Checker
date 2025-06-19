# Email Integrity Checker

A powerful PySide6-based desktop application to analyze emails for spoofing, phishing, and red flags. It supports both `.eml` file analysis and direct connection to IMAP mailboxes. The tool verifies SPF, DKIM, and DMARC records, flags private/internal IPs, and integrates optional threat intelligence using VirusTotal, URLScan, and WHOIS.

---

## ✨ Features

- ✅ **Analyze `.eml` files or IMAP mailbox messages**
- ✅ **SPF, DKIM, and DMARC verification**
- ✅ **Flag private/internal IP addresses**
- ✅ **Base domain and HELO/MX alignment checks**
- ✅ **VirusTotal IP lookup (optional)**
- ✅ **URLScan.io integration (optional)**
- ✅ **WHOIS lookup (optional)**
- ✅ **Red-flag scoring: `ok`, `warn`, `critical`**
- ✅ **Secure API key and IMAP credential storage using `keyring`**
- ✅ **Responsive PySide6 GUI with progress indicators**

---

## 🖼️ Screenshot

> _(You can add a screenshot here after uploading the image to your repo)_

---

## 🚀 Getting Started

### 🔧 Prerequisites

- Python 3.9+
- Recommended: [virtualenv](https://virtualenv.pypa.io/en/latest/)

### 📦 Installation

```bash
pip install -r requirements.txt
```

## 🔐 How to Use Gmail IMAP with App Password
If you're using Gmail and have 2-Step Verification enabled, you cannot use your regular password for IMAP access. Instead, follow these steps to generate an App Password:
1. Go to Google My Account – App Passwords.
2. Sign in and verify your 2FA if prompted.
3. Under Select App, choose Mail.
4. Under Select Device, choose Other and type something like EmailChecker.
5. Click Generate.
6. Copy the 16-character password shown and use it in this application under the Password field.
⚠️ You must also ensure that IMAP is enabled in your Gmail settings:
- Go to Gmail → Settings → See all settings → Forwarding and POP/IMAP → Enable IMAP → Save Changes.
