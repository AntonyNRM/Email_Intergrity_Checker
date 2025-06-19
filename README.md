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
