import streamlit as st
import re
import joblib
import json
import base64
import hashlib
import requests
import email
from email import policy
from email.parser import BytesParser
from datetime import datetime
from fpdf import FPDF

st.set_page_config(page_title="AI Phishing & Malware SOC Toolkit", page_icon="🛡️", layout="wide")

@st.cache_resource
def load_assets():
    model = joblib.load('phishing_model.pkl')
    vectorizer = joblib.load('tfidf_vectorizer.pkl')
    return model, vectorizer

model, vectorizer = load_assets()

# عينة بريد خام مدمجة للتجربة الفورية
SAMPLE_EML_RAW = b'''From: "Microsoft Security Center" <security-alerts@account-protection-verify.com>
To: "Corporate User" <employee@enterprise.local>
Reply-To: "Security Desk" <credential-harvester@stealth-inbox.xyz>
Subject: CRITICAL: Your Office365 Session Expired - Immediate Re-Authentication Required
Date: Fri, 24 Oct 2026 09:12:00 +0300
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====SAMPLE_SOC_ALERT===="

--====SAMPLE_SOC_ALERT====
Content-Type: text/plain; charset="utf-8"

Dear User,

Your corporate session has encountered an unexpected sync failure.
Access to your company mailbox and OneDrive documents has been locked.

You must verify your authentication details immediately within the next 24 hours to prevent account deactivation.

Secure Sign-In Portal:
http://198.51.100.45/auth/corporate-login.php

Failure to complete this verification immediately will lead to your account being suspended.

Regards,
Security Operations Center
IT Infrastructure Support

--====SAMPLE_SOC_ALERT====
Content-Type: application/octet-stream; name="Urgent_Account_Verification_Instructions.pdf.exe"
Content-Disposition: attachment; filename="Urgent_Account_Verification_Instructions.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAA2AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUuDQ0KJAAAAAAAAAA=
--====SAMPLE_SOC_ALERT====--'''

# كلاس تقرير PDF
class SOCReportPDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.cell(0, 10, 'SOC INCIDENT INVESTIGATION REPORT', border=False, align='C', new_x="LMARGIN", new_y="NEXT")
        self.set_font('Helvetica', 'I', 9)
        self.cell(0, 5, 'CONFIDENTIAL - SECURITY OPERATIONS CENTER INTERNAL USE ONLY', border=False, align='C', new_x="LMARGIN", new_y="NEXT")
        self.ln(5)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

def generate_pdf_report(incident_id, timestamp, verdict, risk_score, sender, subject, indicators, urls, attachments):
    pdf = SOCReportPDF()
    pdf.add_page()
    
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(40, 7, 'Incident ID:', 0)
    pdf.set_font('Helvetica', '', 11)
    pdf.cell(0, 7, str(incident_id), 0, new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(40, 7, 'Timestamp (UTC):', 0)
    pdf.set_font('Helvetica', '', 11)
    pdf.cell(0, 7, str(timestamp), 0, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(40, 7, 'Threat Verdict:', 0)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 7, f"{verdict} (Risk: {risk_score}%)", 0, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(0, 7, 'MITRE ATT&CK Classification', 1, new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.multi_cell(0, 6, "- Tactic: Initial Access (TA0001)\n- Technique: Phishing (T1566)\n- Sub-techniques: Spearphishing Link (T1566.001) / Spearphishing Attachment (T1566.002)")
    pdf.ln(3)

    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 7, 'Email Metadata', 1, new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_font('Helvetica', '', 10)
    clean_sender = sender.encode('latin-1', 'replace').decode('latin-1')
    clean_subject = subject.encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 6, f"Sender: {clean_sender}\nSubject: {clean_subject}")
    pdf.ln(3)

    if attachments:
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(0, 7, 'Extracted Attachments & SHA-256 Hashes', 1, new_x="LMARGIN", new_y="NEXT", fill=True)
        pdf.set_font('Helvetica', '', 9)
        for att in attachments:
            clean_name = att['filename'].encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 5, f"File: {clean_name} ({att['size_kb']} KB)\nSHA-256: {att['sha256']}")
            pdf.ln(1)
        pdf.ln(2)

    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 7, 'Detected Security Indicators (IoCs)', 1, new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_font('Helvetica', '', 10)
    if indicators:
        for ind in indicators:
            clean_ind = ind.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 6, f"- {clean_ind}")
    else:
        pdf.multi_cell(0, 6, "No suspicious heuristics or IoCs flagged.")
    pdf.ln(3)

    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 7, 'Recommended SOC Remediation Steps', 1, new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_font('Helvetica', '', 10)
    remediation_text = (
        "1. Block extracted malicious URLs and file hashes (SHA-256) on Perimeter Gateway & EDR.\n"
        "2. Query SIEM logs for any host executing or writing these attachment hashes to disk.\n"
        "3. Isolate affected endpoints immediately if malicious payload execution is confirmed.\n"
        "4. Purge the suspicious message across all enterprise mailboxes."
    )
    pdf.multi_cell(0, 6, remediation_text)
    
    return bytes(pdf.output())

def parse_eml(file_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
    sender = msg.get('From', '')
    reply_to = msg.get('Reply-To', '')
    subject = msg.get('Subject', '')
    body = ""
    attachments = []
    
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition', ''))
            if 'attachment' in cdispo or part.get_filename():
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True)
                if payload:
                    sha256 = hashlib.sha256(payload).hexdigest()
                    size_kb = round(len(payload) / 1024, 2)
                    attachments.append({
                        "filename": filename,
                        "size_kb": size_kb,
                        "sha256": sha256
                    })
            else:
                if ctype == 'text/plain' and not body:
                    body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                elif ctype == 'text/html' and not body:
                    body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
    else:
        body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
        
    return sender, reply_to, subject, body, attachments

def check_url_virustotal(url: str, api_key: str) -> dict:
    if not api_key:
        return {"status": "skipped", "message": "No API Key provided"}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key.strip()}
    try:
        response = requests.get(endpoint, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
        elif response.status_code == 404:
            return {"status": "not_found", "message": "URL not seen on VirusTotal"}
        return {"status": "error", "message": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_hash_virustotal(file_hash: str, api_key: str) -> dict:
    if not api_key:
        return {"status": "skipped", "message": "No API Key provided"}
    endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key.strip()}
    try:
        response = requests.get(endpoint, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
        elif response.status_code == 404:
            return {"status": "not_found", "message": "Hash not observed in VirusTotal database"}
        return {"status": "error", "message": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# إدارة حالة المدخلات (Session State)
if "sample_sender" not in st.session_state:
    st.session_state.sample_sender = ""
if "sample_reply_to" not in st.session_state:
    st.session_state.sample_reply_to = ""
if "sample_subject" not in st.session_state:
    st.session_state.sample_subject = ""
if "sample_body" not in st.session_state:
    st.session_state.sample_body = ""
if "use_demo_eml" not in st.session_state:
    st.session_state.use_demo_eml = False

def load_manual_sample():
    st.session_state.sample_sender = "security-update@paypal-verification-alert.com"
    st.session_state.sample_reply_to = "attacker-box@dropmail-inbox.xyz"
    st.session_state.sample_subject = "Urgent: Your Account Has Been Suspended - Action Required"
    st.session_state.sample_body = (
        "Dear Customer,\n\n"
        "We have detected unauthorized transactions on your account from an unrecognized IP address.\n"
        "To prevent permanent restriction, you must verify your identity immediately within the next 24 hours.\n\n"
        "Click here immediately to restore access:\n"
        "http://192.168.1.105/auth/verify-account.php\n\n"
        "If you do not complete this verification immediately, your funds will remain locked.\n\n"
        "Security Team\nCustomer Protection Operations"
    )

def clear_manual_sample():
    st.session_state.sample_sender = ""
    st.session_state.sample_reply_to = ""
    st.session_state.sample_subject = ""
    st.session_state.sample_body = ""

# القائمة الجانبية
with st.sidebar:
    st.header("⚙️ Security Integrations")
    vt_api_key = st.text_input("VirusTotal API Key (Optional):", type="password", help="ضع مفتاح VT المجاني لتفعيل فحص الروابط وبصمات المرفقات حياً.")
    st.info("فحص المرفقات والروابط يعمل محلياً، ويفحص حياً عبر السحابة في حال إدخال المفتاح.")

st.title("🛡️ AI Phishing & Malware SOC Incident Detector")
st.markdown("تحليل الإيميلات المشبوهة، تشريح المرفقات وحساب SHA-256، وفحص السمعة الرقمية عبر VirusTotal.")

tab1, tab2 = st.tabs(["📁 Upload / Test .EML File", "✍️ Manual Email Input"])

sender = ""
reply_to = ""
subject = ""
email_body = ""
parsed_attachments = []
active_source = ""

with tab1:
    st.markdown("Upload your own `.eml` file, or click **Use Demo EML** to test an embedded malicious sample:")
    btn_col1, btn_col2 = st.columns([1, 4])
    with btn_col1:
        if st.button("🧪 Use Demo .EML", help="تحميل عينة بريد خبيثة مدمجة تحوي مرفق .pdf.exe وروابط احتيال"):
            st.session_state.use_demo_eml = True
    with btn_col2:
        if st.session_state.use_demo_eml:
            if st.button("🔄 Reset Demo"):
                st.session_state.use_demo_eml = False
                st.rerun()

    uploaded_file = st.file_uploader("Upload raw email file (.eml)", type=['eml'])

    if uploaded_file is not None:
        st.session_state.use_demo_eml = False
        try:
            file_bytes = uploaded_file.read()
            sender, reply_to, subject, email_body, parsed_attachments = parse_eml(file_bytes)
            active_source = f"Uploaded File ({uploaded_file.name})"
            st.success("File parsed successfully!")
        except Exception as e:
            st.error(f"Error parsing .eml: {str(e)}")
    elif st.session_state.use_demo_eml:
        sender, reply_to, subject, email_body, parsed_attachments = parse_eml(SAMPLE_EML_RAW)
        active_source = "Pre-loaded Demo .EML Sample"
        st.info("⚡ Active: Pre-loaded Demo .EML (Malicious Attachment + Phishing Link)")

    if sender or email_body or parsed_attachments:
        col_a, col_b = st.columns(2)
        col_a.text_input("Extracted Sender:", value=sender, disabled=True)
        col_a.text_input("Extracted Subject:", value=subject, disabled=True)
        col_b.text_input("Extracted Reply-To:", value=reply_to, disabled=True)
        st.text_area("Extracted Body Preview:", value=email_body[:400] + ("..." if len(email_body) > 400 else ""), height=80, disabled=True)
        if parsed_attachments:
            st.warning(f"📎 Extracted {len(parsed_attachments)} Attachment(s):")
            for att in parsed_attachments:
                st.code(f"Filename: {att['filename']} | Size: {att['size_kb']} KB\nSHA-256: {att['sha256']}", language="bash")

with tab2:
    btn_m1, btn_m2, _ = st.columns([1.2, 1, 4])
    with btn_m1:
        st.button("🧪 Load Sample Email", on_click=load_manual_sample, help="تعبئة بيانات بريد تصيد احتيالي تجريبي تلقائياً")
    with btn_m2:
        st.button("🗑️ Clear", on_click=clear_manual_sample)

    col1, col2 = st.columns(2)
    with col1:
        sender_input = st.text_input("Sender Email:", value=st.session_state.sample_sender, placeholder="support@service-update.com")
        subject_input = st.text_input("Subject:", value=st.session_state.sample_subject, placeholder="Urgent: Security Verification Required")
    with col2:
        reply_to_input = st.text_input("Reply-To Email (Optional):", value=st.session_state.sample_reply_to, placeholder="attacker@drop-mailbox.xyz")
    
    body_input = st.text_area("Email Content:", value=st.session_state.sample_body, height=140, placeholder="Paste email body or headers here...")
    
    if not active_source and body_input.strip():
        sender = sender_input
        reply_to = reply_to_input
        subject = subject_input
        email_body = body_input
        active_source = "Manual Input"

st.markdown("---")

if st.button("🔍 Scan Email & Investigate Threats", use_container_width=True):
    # إذا لم تكن البيانات مأخوذة من التبويب الأول، نأخذها من التبويب الثاني
    if not email_body.strip() and not parsed_attachments:
        if body_input.strip():
            sender = sender_input
            reply_to = reply_to_input
            subject = subject_input
            email_body = body_input
            active_source = "Manual Input"

    if not email_body.strip() and not parsed_attachments:
        st.warning("Please provide email content or click 'Load Sample Email' to test.")
    else:
        indicators = []
        heuristic_score = 0
        vt_url_results = []
        vt_hash_results = []

        # 1. فحص الترويسة
        if reply_to and sender and (sender.strip().lower() != reply_to.strip().lower()):
            heuristic_score += 30
            indicators.append(f"Mismatched Header: Sender ({sender}) differs from Reply-To ({reply_to})")

        # 2. فحص المرفقات
        dangerous_exts = ['.exe', '.scr', '.iso', '.vbs', '.js', '.bat', '.ps1', '.cmd', '.hta', '.jar']
        for att in parsed_attachments:
            fname = att['filename'].lower()
            fhash = att['sha256']
            if any(fname.endswith(ext) for ext in dangerous_exts):
                heuristic_score += 50
                indicators.append(f"High-Risk Executable Attachment: {att['filename']}")
            if re.search(r'\.[a-z0-9]{2,4}\.(exe|scr|vbs|bat|js)$', fname):
                heuristic_score += 60
                indicators.append(f"Double Extension Masquerading Detected: {att['filename']}")

            if vt_api_key:
                h_res = check_hash_virustotal(fhash, vt_api_key)
                vt_hash_results.append({"filename": att['filename'], "hash": fhash, "result": h_res})
                if h_res.get("status") == "success" and h_res.get("malicious", 0) > 0:
                    heuristic_score += 60
                    indicators.append(f"Malware Hash Confirmed: {att['filename']} flagged malicious by {h_res.get('malicious')} AV engines.")

        # 3. فحص الروابط
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_body)
        raw_ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

        for u in urls:
            if raw_ip_pattern.match(u):
                heuristic_score += 25
                indicators.append(f"Raw IP URL detected: {u}")
            if any(short in u for short in ['bit.ly', 'tinyurl.com', 'is.gd']):
                heuristic_score += 15
                indicators.append(f"Shortened URL detected: {u}")

            if vt_api_key:
                u_res = check_url_virustotal(u, vt_api_key)
                vt_url_results.append({"url": u, "result": u_res})
                if u_res.get("status") == "success" and (u_res.get("malicious", 0) > 0 or u_res.get("suspicious", 0) > 0):
                    heuristic_score += 40
                    indicators.append(f"VirusTotal URL Alert: {u} flagged malicious by {u_res.get('malicious')} engines.")

        # 4. لغة الاستعجال
        urgency_terms = ['urgent', 'immediately', 'suspended', 'locked', 'action required', '24 hours', 'verify identity', 'expired']
        found_terms = [t for t in urgency_terms if t in (subject + " " + email_body).lower()]
        if found_terms:
            heuristic_score += 15
            indicators.append(f"Urgency/Social Engineering triggers: {', '.join(found_terms)}")

        # 5. استدلال الذكاء الاصطناعي
        full_text = f"{subject} {email_body}"
        transformed = vectorizer.transform([full_text])
        ai_prob = float(model.predict_proba(transformed)[0][1])

        total_risk = min(int((ai_prob * 40) + (heuristic_score * 0.6)), 100)
        verdict = "PHISHING / MALICIOUS" if (total_risk >= 50 or ai_prob >= 0.70) else "CLEAN / LEGITIMATE"

        st.subheader("📊 Investigation Summary")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Risk Score", f"{total_risk}%")
        m2.metric("AI Confidence", f"{ai_prob * 100:.1f}%")
        m3.metric("Extracted URLs", len(urls))
        m4.metric("Attachments", len(parsed_attachments))

        if verdict == "PHISHING / MALICIOUS":
            st.error(f"🚨 **Verdict: {verdict}**")
        else:
            st.success(f"✅ **Verdict: {verdict}**")

        if vt_hash_results:
            st.subheader("🧬 Attachment Threat Intelligence:")
            for item in vt_hash_results:
                fname = item["filename"]
                r = item["result"]
                if r.get("status") == "success":
                    st.write(f"- `{fname}` ➔ **Malicious:** {r.get('malicious')} | **Suspicious:** {r.get('suspicious')} | **Harmless:** {r.get('harmless')}")
                else:
                    st.write(f"- `{fname}` ➔ {r.get('message', 'Scan unavailable')}")

        if indicators:
            st.subheader("🔎 Indicators of Compromise (IoCs):")
            for ind in indicators:
                st.write(f"- {ind}")

        incident_id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        now_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        soc_report = {
            "incident_id": incident_id,
            "timestamp": now_time + " UTC",
            "source_type": active_source,
            "analyst_assessment": {
                "verdict": verdict,
                "total_risk_score": f"{total_risk}/100",
                "ai_phishing_probability": f"{ai_prob * 100:.2f}%"
            },
            "email_metadata": {
                "sender": sender if sender else "N/A",
                "reply_to": reply_to if reply_to else "N/A",
                "subject": subject if subject else "N/A"
            },
            "attachments_forensics": parsed_attachments,
            "extracted_artifacts": {
                "urls": urls,
                "virustotal_urls": vt_url_results,
                "virustotal_hashes": vt_hash_results
            },
            "detected_indicators": indicators
        }

        report_json = json.dumps(soc_report, indent=4, ensure_ascii=False)

        pdf_bytes = generate_pdf_report(
            incident_id=incident_id,
            timestamp=now_time,
            verdict=verdict,
            risk_score=total_risk,
            sender=sender if sender else "N/A",
            subject=subject if subject else "N/A",
            indicators=indicators,
            urls=urls,
            attachments=parsed_attachments
        )

        st.markdown("---")
        st.subheader("📑 Export Incident Documentation")
        col_dl1, col_dl2 = st.columns(2)
        with col_dl1:
            st.download_button(
                label="📄 Download Executive Incident Report (PDF)",
                data=pdf_bytes,
                file_name=f"{incident_id}_report.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        with col_dl2:
            st.download_button(
                label="⬇️ Download Raw Incident Data (JSON)",
                data=report_json,
                file_name=f"{incident_id}_report.json",
                mime="application/json",
                use_container_width=True
            )
