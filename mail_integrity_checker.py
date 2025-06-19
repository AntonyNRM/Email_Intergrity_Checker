import sys, re, email, ipaddress, subprocess, shlex, requests, dns.resolver, tldextract, whois
import keyring, getpass, json, os, base64
from email.header import decode_header, make_header
from pathlib      import Path
from imapclient   import IMAPClient
import dkim, spf
from checkdmarc   import dmarc
import dns.resolver

# ── Qt imports ───────────────────────────────────────────────────────
import PySide6.QtWidgets as QtWidgets
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem,
    QTextEdit, QFileDialog, QMessageBox, QTabWidget, QCheckBox,
    QProgressDialog, QComboBox
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QProgressDialog
import json

# ================================================================================================
#  Utility helpers
# ================================================================================================

dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']
dns.resolver.default_resolver.lifetime = 10 

APP_ID = "EmailIntegrityChecker"

def _kr_set(key: str, value: str):
    if value:
        keyring.set_password(APP_ID, key, value)

def _kr_get(key: str) -> str | None:
    try:
        return keyring.get_password(APP_ID, key)
    except keyring.errors.KeyringError:
        return None      

def load_settings() -> dict:
    """Non-secret UI prefs (e.g. remember flags) from tiny json."""
    p = Path.home() / ".eic_prefs.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}

def _clean_ascii(s: str) -> str:
    """
    Replace non-ASCII invisible whitespace and ensure the result is pure ASCII.
    Raises ValueError if non-ASCII remains.
    """
    if not s:
        return s
    cleaned = (
        s.replace("\u00A0", " ")   
         .replace("\u200B", "")   
         .strip()
    )
    try:
        cleaned.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("Field contains non-ASCII characters.")
    return cleaned

def save_settings(d: dict):
    p = Path.home() / ".eic_prefs.json"
    try:
        p.write_text(json.dumps(d))
    except Exception:
        pass

def get_dmarc_policy(domain: str):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        txt_list = resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in txt_list:
            txt = "".join([b.decode() for b in rdata.strings])
            if not txt.lower().startswith("v=dmarc1"):
                continue

            # -- NEW, trim & normalise tags ---------------------------------
            tags = {}
            for part in txt.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    tags[k.strip().lower()] = v.strip()

            return tags.get("p", "not set"), txt         
        return None, "not published"
    except Exception as e:
        return None, f"error – {e}"


def decode_mime(val: str) -> str:
    """Decode RFC-2047 encoded header values (e.g., Subject)."""
    try:
        return str(make_header(decode_header(val)))
    except Exception:
        return val or "–"

def get_base_domain(host: str) -> str:
    ext = tldextract.extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else host

def is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False

def is_ip_in_mx_records(domain: str, sender_ip: str) -> bool:
    def _collect_ips(d: str) -> set[str]:
        ips = set()
        try:
            for mx in dns.resolver.resolve(d, "MX", lifetime=5.0):
                host = str(mx.exchange).rstrip(".")
                for rtype in ("A", "AAAA"):
                    try:
                        recs = dns.resolver.resolve(host, rtype, lifetime=3.0)
                        ips.update(r.to_text() for r in recs)
                    except Exception:
                        pass
        except Exception:
            pass
        return ips

    ips = _collect_ips(domain)
    if not ips:
        ips = _collect_ips(get_base_domain(domain))
    return sender_ip.lower() in {ip.lower() for ip in ips}

# ================================================================================================
#  Background worker with progress signals
# ================================================================================================

class AnalyseWorker(QThread):
    progress = Signal(str)
    done     = Signal(str)       
    risk     = Signal(str)        

    def __init__(self, raw_msg: bytes, main_window):
        super().__init__()
        self.raw_msg = raw_msg
        self.main    = main_window

    def run(self):
        text, risk = analyse_email(self.raw_msg, self.main, progress_cb=self.progress.emit)
        self.done.emit(text)
        self.risk.emit(risk)

# ================================================================================================
#  Core analysis
# ================================================================================================

def analyse_email(raw_msg: bytes, main, progress_cb=lambda _: None) -> tuple[str, str]:
    msg     = email.message_from_bytes(raw_msg)
    headers = dict(msg.items())
    flag = lambda bad: " 🚩" if bad else ""

    # ── Basic fields ───────────────────────────────────────────────
    from_hdr      = headers.get("From", "")
    return_path   = headers.get("Return-Path", "").strip("<>")
    from_email    = email.utils.parseaddr(from_hdr)[1] or return_path
    mail_domain   = (from_email.split("@")[-1] if "@" in from_email else "").lower()

    raw_txt       = raw_msg.decode(errors="ignore")
    spf_auth      = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", raw_txt)
    spf_res       = spf_auth.group(1) if spf_auth else "not found"

    ip_match      = re.search(r"\[([a-fA-F0-9:.]+)\]", raw_txt)
    sending_ip    = ip_match[1] if ip_match else ""
    ip_flag = "🚩" if is_private_ip(sending_ip) else ""


    recv_match    = re.search(r"Received: from ([^ ]+)", raw_txt, re.I)
    helo_dom      = recv_match[1] if recv_match else ""

    base_from = get_base_domain(mail_domain)
    base_helo = get_base_domain(helo_dom)
    domain_match_raw = "✔️" if base_from and base_from == base_helo else "❌"

    # ── SPF / MX logic ────────────────────────────────────────────
    if spf_res == "pass":
        mx_mark = "✔️ (spf)"
    else:
        mx_mark = "✔️" if is_ip_in_mx_records(base_from, sending_ip) else "❌"

    # ── Decide final domain_match after MX check ────────────────
    domain_match = "✔️" if mx_mark.startswith("✔️") else domain_match_raw

    # ── Headline lines (after mx/domain match) ─────────────────
    lines = [
        f"From        : {from_email or '–'} {domain_match}",
        f"HELO        : {helo_dom or '–'}",
        f"Sending IP  : {sending_ip or '–'} {ip_flag}",
        f"MX match    : {mx_mark}",
        f"\nSPF (Auth-Results): {spf_res}{flag(spf_res != 'pass')}",
    ]


    domain_match = "✔️" if mx_mark.startswith("✔️") else domain_match_raw
    # ── DKIM ──────────────────────────────────────────────────────
    progress_cb("Verifying DKIM…")
    try:
        dkim_ok = dkim.verify(raw_msg)
    except Exception:
        dkim_ok = False
    dkim_text = 'pass' if dkim_ok else 'fail or none'
    lines.append(f"DKIM               : {dkim_text}{flag(not dkim_ok)}")


    # ── DMARC ─────────────────────────────────────────────────────
    progress_cb("Looking up DMARC…")
    policy, dmarc_raw = get_dmarc_policy(mail_domain)
    if policy:
        dmarc_text = f"policy={policy}\nDMARC  Record     : {dmarc_raw}"
        dmarc_failed = policy.lower() not in ("reject", "quarantine")
    else:
        dmarc_text = dmarc_raw 
        dmarc_failed = True

    lines.append(f"DMARC              : {dmarc_text}{flag(dmarc_failed)}")



    # ── Important Data ───────────────────────────────────────────
    lines.append("\n=== Important Data ===")
    subject     = decode_mime(headers.get("Subject", "–"))
    domain_key  = next((v for k, v in headers.items()
                        if k.lower() in ("domainkey-signature", "dkim-signature")), None)
    msg_id      = headers.get("Message-ID", "–")
    mime_ver    = headers.get("MIME-Version", "–")

    # Extract all Received headers (may be multiple)
    received_headers = [v for k, v in headers.items() if k.lower() == "received"]

    # Flag if any private IPs found in Received chain
    flagged_received = []
    for received in received_headers:
        flagged = False
        ips = re.findall(r"\[([0-9a-fA-F:.]+)\]", received)
        for ip in ips:
            if is_private_ip(ip):
                flagged = True
                break
        if flagged:
            flagged_received.append(received + " 🚩 (Private/internal IP – possible relay, automation, or spoofing)")
        else:
            flagged_received.append(received)

    # Use topmost (most recent) Received header
    received_display = flagged_received[0] if flagged_received else "–"


    x_spam      = headers.get("X-Spam-Status", "–")

    lines.extend([
        f"Subject      : {subject}",
        f"Return-Path  : {return_path or '–'}",
        f"Domain Key   : {'present' if domain_key else '–'}",
        f"Message-ID   : {msg_id}",
        f"MIME-Version : {mime_ver}",
        f"Received     : {received_display}",
        f"X-Spam Status: {x_spam}",
    ])

    # ── Optional threat-intel look-ups ───────────────────────────
    progress_cb("Threat-intel look-ups…")
    if main.chk_vt.isChecked():
        lines.append("\n")
        lines.append("=== Virus Total ===")
        vt_key = main.key_vt.text().strip()
        if vt_key:
            try:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{sending_ip}"
                r   = requests.get(url, headers={"x-apikey": vt_key}, timeout=10).json()
                stats = r["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                total     = sum(stats.values())
                flag      = " 🚩" if malicious else ""
                lines.append(f"Virus Total Malicious Score: {malicious} / {total}{flag}")
            except Exception as e:
                lines.append(f"Virus Total err: {e}")
        else:
            lines.append("Virus Total: key missing")


    if main.chk_us.isChecked():
        lines.append("\n")
        lines.append("=== URLScan ===")
        us_key = main.key_us.text().strip()
        if us_key:
            try:
                hdrs = {"API-Key": us_key, "Content-Type": "application/json"}
                scan_payload = {"url": sending_ip, "public": "off"}
                r = requests.post("https://urlscan.io/api/v1/scan/", json=scan_payload, headers=hdrs, timeout=10)
                uid = r.json().get("uuid", "")
                result_url = f"https://urlscan.io/result/{uid}"
                flag = ""

                # Optional: Lookup scan verdict (wait a bit before checking)
                import time
                time.sleep(3) 

                verdict_resp = requests.get(f"https://urlscan.io/api/v1/result/{uid}", headers=hdrs, timeout=10).json()
                verdicts = verdict_resp.get("verdicts", {})
                if verdicts:
                    overall = verdicts.get("overall", {})
                    if overall.get("malicious") or overall.get("score", 0) > 2:
                        flag = " 🚩"
                lines.append(f"URLScan: {result_url}{flag}")
            except Exception as e:
                lines.append(f"URLScan err: {e}")
        else:
            lines.append("URLScan: key missing")


    if main.chk_whois.isChecked():
        try:
            w = whois.whois(base_from)
            lines.extend([
                "\n=== WHOIS Info ===",
                f"Org Name     : {w.get('org', '–')}",
                f"Registrant   : {w.get('name', '–')}",
                f"Email        : {w.get('emails', '–')}",
                f"Address      : {w.get('address', '–')}",
                f"City         : {w.get('city', '–')}",
                f"State        : {w.get('state', '–')}",
                f"Postal Code  : {w.get('registrant_postal_code', '–')}",
                f"Country      : {w.get('country', '–')}",
                f"DNSSEC       : {w.get('dnssec', '–')}",
            ])
        except Exception as e:
            lines.append(f"WHOIS err: {e}")

    # ── Raw headers preview ─────────────────────────────────────
    lines.append("\n=== RAW HEADERS (top 40) ===")
    header_blob = raw_txt.split("\n\n", 1)[0]
    lines.append("\n".join(header_blob.splitlines()[:40]))

    # ── Basic risk score ────────────────────────────────────────
    red_flags = []
    if domain_match == "❌":         red_flags.append("domain")
    if mx_mark.startswith("❌"):     red_flags.append("mx")
    if spf_res != "pass":           red_flags.append("spf")
    if not dkim_ok:                 red_flags.append("dkim")
    if is_private_ip(sending_ip):   red_flags.append("ip")
    if any("🚩" in r for r in flagged_received):
        red_flags.append("received-loopback")

    risk = "ok"
    if red_flags:
        risk = "critical" if {"domain", "spf", "dkim"} & set(red_flags) else "warn"

    return "\n".join(lines), risk

# ================================================================================================
#  GUI tabs – FileTab & MailboxTab
# ================================================================================================

class FileTab(QWidget):
    def __init__(self, output_box: QTextEdit, main_window):
        super().__init__()
        self.out  = output_box
        self.main = main_window
        vbox = QVBoxLayout(self)

        pick_btn = QPushButton("Choose .eml file…")
        pick_btn.clicked.connect(self.pick_file)
        vbox.addWidget(pick_btn, alignment=Qt.AlignTop)

    def pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select EML file", "", "Email files (*.eml)")
        if not path:
            return
        raw = Path(path).read_bytes()
        self.run_analysis(raw)

    def run_analysis(self, raw):
        dlg = QProgressDialog("Analysing…", None, 0, 0, self)
        dlg.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        dlg.setCancelButton(None)
        dlg.setWindowModality(Qt.ApplicationModal)
        dlg.setMinimumWidth(300)

        # Fix alignment for label
        label = dlg.findChild(QLabel)
        if label:
            label.setAlignment(Qt.AlignHCenter)

        # Tweak progress bar margin
        dlg.setStyleSheet("""
            QProgressBar {
                margin-left: 10px;
                margin-right: 10px;
            }
        """)

        dlg.show()
        
        self.main.save_creds_if_needed()
        worker = AnalyseWorker(raw, self.main)
        self.main.worker = worker
        worker.progress.connect(dlg.setLabelText)
        worker.done.connect(lambda txt: (dlg.close(), self.out.setPlainText(txt)))
        worker.risk.connect(self.show_risk_popup)
        worker.start()





    def show_risk_popup(self, level):
        if level == "ok":
            return
        icon  = QMessageBox.Warning if level == "warn" else QMessageBox.Critical
        title = "Suspicious Email"   if level == "warn" else "Caution!"
        QMessageBox(icon, title, "Red-flags detected. Review analysis.", QMessageBox.Ok, self).exec()

class MailboxTab(QWidget):
    FETCH_LIMIT = 100

    def _load_messages_from(self, folder: str):
        """Select *folder* and show its newest N messages with a responsive UI."""
        try:
            # Indefinite (“busy”) bar for the first long operations
            busy = QProgressDialog("Loading mailbox…", None, 0, 0, self)
            busy.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
            busy.setCancelButton(None)
            busy.setWindowModality(Qt.ApplicationModal)
            busy.setMinimumWidth(300)
            busy.show()
            QCoreApplication.processEvents()

            self.client.select_folder(folder, readonly=True)

            uids  = self.client.search("ALL")              
            dates = self.client.fetch(uids, ["INTERNALDATE"])

            busy.close()                               

            # Now switch to a thin, determinate bar for chunked fetch
            newest = sorted(uids,
                            key=lambda uid: dates[uid][b"INTERNALDATE"],
                            reverse=True)[:self.FETCH_LIMIT]

            prog = QProgressDialog("Fetching message headers…", None,
                                0, len(newest), self)
            prog.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
            prog.setCancelButton(None)
            prog.setWindowModality(Qt.ApplicationModal)
            prog.setMinimumWidth(300)
            prog.show()

            envs = {}
            for i in range(0, len(newest), 50):
                part = newest[i:i+50]
                envs.update(self.client.fetch(part, ["ENVELOPE"]))
                prog.setValue(min(i + 50, len(newest)))
                QCoreApplication.processEvents()         

            prog.close()

            # Build the list-box (unchanged)
            self.listbox.clear()
            for uid in newest:
                env = envs.get(uid)
                if not env:
                    continue
                env  = env[b"ENVELOPE"]
                subj = env.subject.decode(errors="ignore") if env.subject else "(no subject)"
                sndr = f"{env.from_[0].mailbox.decode()}@{env.from_[0].host.decode()}"
                date = env.date.strftime("%Y-%m-%d %H:%M")
                item = QListWidgetItem(f"{date} | {sndr} | {subj}")
                item.setData(Qt.UserRole, uid)
                self.listbox.addItem(item)

        except Exception as e:
            QMessageBox.critical(self, "IMAP error", str(e))
    # ------------------------------------------------------------------
    def _populate_folders(self):
        """Fill the combo box with all selectable folders once per session."""
        self.cmb_folder.clear()
        try:
            for flags, delim, name in self.client.list_folders():
                # Skip Gmail “[Gmail]” container itself
                if name in ("[Gmail]", "[Gmail]/Spam"):         
                    continue
                self.cmb_folder.addItem(name)
        except Exception:
            # fall back to INBOX only
            self.cmb_folder.addItem("INBOX")

    def __init__(self, output_box: QTextEdit, main_window: QWidget):
        super().__init__()
        self.out   = output_box
        self.main  = main_window
        self.client = None

        vbox = QVBoxLayout(self)

        # ── IMAP credentials row ───────────────────────────────────
        row = QHBoxLayout()
        self.host = QLineEdit(); self.host.setPlaceholderText("IMAP host")
        self.user = QLineEdit(); self.user.setPlaceholderText("Username")
        self.pwd  = QLineEdit(); self.pwd.setPlaceholderText("Password")
        self.pwd.setEchoMode(QLineEdit.Password)
        self.cmb_folder = QComboBox(); self.cmb_folder.setMinimumWidth(140) 
        self.cmb_folder.currentTextChanged.connect(
            lambda name: self._load_messages_from(name) if self.client else None)
        vbox.addWidget(self.cmb_folder)



        self.remember = QCheckBox("remember")
        btn = QPushButton("Connect"); btn.clicked.connect(self.connect_mailbox)

        for w in (self.host, self.user, self.pwd, self.cmb_folder, self.remember, btn):
            row.addWidget(w)
        vbox.addLayout(row)

        # ── message list ───────────────────────────────────────────
        self.listbox = QListWidget()
        self.listbox.itemDoubleClicked.connect(self.fetch_and_analyse)
        vbox.addWidget(self.listbox)

        # load persisted creds
        self._load_imap_creds()

    # ------------------------------------------------------------------
    #  Persistence helpers
    # ------------------------------------------------------------------
    def _load_imap_creds(self):
        prefs = load_settings()
        self.remember.setChecked(prefs.get("remember_imap", False))

        if self.remember.isChecked():
            if (v := _kr_get("IMAP_HOST")): self.host.setText(v)
            if (v := _kr_get("IMAP_USER")): self.user.setText(v)
            if (v := _kr_get("IMAP_PASS")): self.pwd .setText(v)

    def _save_imap_creds_if_needed(self):
        if self.remember.isChecked():
            _kr_set("IMAP_HOST", self.host.text().strip())
            _kr_set("IMAP_USER", self.user.text().strip())
            _kr_set("IMAP_PASS", self.pwd .text().strip())
        else:                           
            _kr_set("IMAP_HOST", ""); _kr_set("IMAP_USER", ""); _kr_set("IMAP_PASS", "")

        prefs = load_settings()
        prefs["remember_imap"] = self.remember.isChecked()
        save_settings(prefs)





    # ------------------------------------------------------------------
    #  IMAP logic
    # ------------------------------------------------------------------
    def connect_mailbox(self):
        h, u, p = self.host.text().strip(), self.user.text().strip(), self.pwd.text()
        if not all((h, u, p)):
            QMessageBox.warning(self, "Missing", "Host / user / pass are required")
            return

        self._save_imap_creds_if_needed()

        try:
            try:
                h = _clean_ascii(self.host.text())
                u = _clean_ascii(self.user.text())
                p = _clean_ascii(self.pwd.text())
            except ValueError as e:
                QMessageBox.warning(self, "Bad characters", str(e))
                return

            self.client = IMAPClient(h, ssl=True)
            self.client.login(u, p)

            # ---------- list folders & (re)fill combo ----------
            folders = [f[2] for f in self.client.list_folders()]
            self.cmb_folder.blockSignals(True)       
            self.cmb_folder.clear()
            self.cmb_folder.addItems(sorted(folders))
            self.cmb_folder.blockSignals(False)

            # auto-load INBOX the first time
            if "INBOX" in folders:
                self.cmb_folder.setCurrentText("INBOX")
                self._load_messages_from("INBOX")

        except Exception as e:
            QMessageBox.critical(self, "IMAP error", str(e))



    # ------------------------------------------------------------------
    def fetch_and_analyse(self, item: QListWidgetItem):
        if not self.client:
            return
        uid = item.data(Qt.UserRole)
        raw = self.client.fetch([uid], ["RFC822"])[uid][b"RFC822"]
        self.run_analysis(raw)

    # identical to FileTab.run_analysis but calls main.save_creds_if_needed()
    def run_analysis(self, raw):
        dlg = QProgressDialog("Analysing…", None, 0, 0, self)
        dlg.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        dlg.setCancelButton(None)
        dlg.setWindowModality(Qt.ApplicationModal)
        dlg.setMinimumWidth(300)

        # Fix alignment for label
        label = dlg.findChild(QLabel)
        if label:
            label.setAlignment(Qt.AlignHCenter)

        # Tweak progress bar margin
        dlg.setStyleSheet("""
            QProgressBar {
                margin-left: 10px;
                margin-right: 10px;
            }
        """)

        dlg.show()
        
        self.main.save_creds_if_needed()
        worker = AnalyseWorker(raw, self.main)
        self.main.worker = worker
        worker.progress.connect(dlg.setLabelText)
        worker.done.connect(lambda txt: (dlg.close(), self.out.setPlainText(txt)))
        worker.risk.connect(self.show_risk_popup)
        worker.start()



    def show_risk_popup(self, level):
        if level == "ok":
            return
        icon  = QMessageBox.Warning if level == "warn" else QMessageBox.Critical
        title = "Suspicious Email" if level == "warn" else "Caution!"
        QMessageBox(icon, title, "Red-flags detected. Review analysis.", QMessageBox.Ok, self).exec()


# ================================================================================================
#  Main window
# ================================================================================================

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Email Integrity Checker")
        self.worker = None

        vbox = QVBoxLayout(self)

        # ---------- threat-intel options ----------
        form = QFormLayout()

        self.chk_vt  = QCheckBox("VirusTotal")
        self.key_vt  = QLineEdit(); self.key_vt.setEchoMode(QLineEdit.Password)
        self.key_vt.setPlaceholderText("VT key")
        self.rem_vt  = QCheckBox("remember")

        self.chk_us  = QCheckBox("URLScan")
        self.key_us  = QLineEdit(); self.key_us.setEchoMode(QLineEdit.Password)
        self.key_us.setPlaceholderText("URLScan key")
        self.rem_us  = QCheckBox("remember")

        self.chk_whois = QCheckBox("WHOIS")

        form.addRow(self.chk_vt, self.key_vt)
        form.addRow("", self.rem_vt)
        form.addRow(self.chk_us, self.key_us)
        form.addRow("", self.rem_us)
        form.addRow(self.chk_whois)
        vbox.addLayout(form)

        # ---------- Tabs ----------
        self.output = QTextEdit(); self.output.setReadOnly(True)
        tabs = QTabWidget()
        tabs.addTab(MailboxTab(self.output, self), "Mailbox mode")
        tabs.addTab(FileTab(self.output, self),    "File mode (.eml)")
        vbox.addWidget(tabs)
        vbox.addWidget(self.output)

        # now that all widgets exist we can load persisted data
        self._load_saved_creds()

    # ----------------------------------------------------------------
    def _load_saved_creds(self):
        prefs = load_settings()

        # restore “remember” checkboxes
        self.rem_vt.setChecked(prefs.get("remember_vt",   False))
        self.rem_us.setChecked(prefs.get("remember_us",   False))


        # secrets from keyring
        if self.rem_vt.isChecked():
            if (v := _kr_get("VT_API_KEY")): self.key_vt.setText(v); self.chk_vt.setChecked(True)
        if self.rem_us.isChecked():
            if (v := _kr_get("US_API_KEY")): self.key_us.setText(v); self.chk_us.setChecked(True)


    # called before launching AnalyseWorker
    def save_creds_if_needed(self):
        # VirusTotal
        if self.rem_vt.isChecked():
            _kr_set("VT_API_KEY", self.key_vt.text().strip())
        else:
            _kr_set("VT_API_KEY", "")

        # URLScan
        if self.rem_us.isChecked():
            _kr_set("US_API_KEY", self.key_us.text().strip())
        else:
            _kr_set("US_API_KEY", "")

        prefs = load_settings()
        prefs["remember_vt"] = self.rem_vt.isChecked()
        prefs["remember_us"] = self.rem_us.isChecked()
        save_settings(prefs)


    # ----------------------------------------------------------------
    def closeEvent(self, ev):
        if self.worker and self.worker.isRunning():
            self.worker.quit(); self.worker.wait()
        ev.accept()

# ================================================================================================
#  Entry-point
# ================================================================================================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    mw  = MainWindow(); mw.resize(900, 650); mw.show()
    sys.exit(app.exec())
