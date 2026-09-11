import streamlit as st
import sqlite3
import hashlib
import os
from datetime import datetime

# Configure page layout
st.set_page_config(page_title="Cybercrime Scene Investigator", page_icon="🔍", layout="wide")

# Ensure required directories exist
os.makedirs("database/evidence_files", exist_ok=True)

# Database connection
conn = sqlite3.connect("database/forensics.db", check_same_thread=False)
c = conn.cursor()

# Initialize clean relational tables
c.execute("""
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    investigator TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    file_name TEXT,
    file_size INTEGER,
    sha256_hash TEXT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id)
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    event_type TEXT,
    severity INTEGER,
    description TEXT,
    timestamp TEXT,
    FOREIGN KEY(case_id) REFERENCES cases(id)
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS browser_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    url TEXT,
    title TEXT,
    visit_count INTEGER,
    last_visit_time TEXT,
    FOREIGN KEY(case_id) REFERENCES cases(id)
)
""")
conn.commit()

# --- SIDEBAR: Case Management ---
st.sidebar.header("📁 Case Management")

with st.sidebar.form("new_case_form"):
    new_case_name = st.text_input("New Case Name")
    investigator_name = st.text_input("Investigator Name")
    case_description = st.text_area("Case Description")
    register_btn = st.form_submit_button("Register Case")

    if register_btn:
        if new_case_name.strip() and investigator_name.strip():
            c.execute("INSERT INTO cases (name, investigator, description) VALUES (?, ?, ?)",
                      (new_case_name.strip(), investigator_name.strip(), case_description.strip()))
            conn.commit()
            st.sidebar.success(f"Case '{new_case_name}' created!")
            st.rerun()
        else:
            st.sidebar.error("Case name and investigator are required.")

# Fetch active cases for assignment
cases = c.execute("SELECT id, name FROM cases ORDER BY id DESC").fetchall()
case_options = {f"{name} (ID: {cid})": cid for cid, name in cases}

st.title("🔍 Cybercrime Scene Investigator")

selected_case_id = None
if case_options:
    selected_case_label = st.selectbox("Select Active Case", list(case_options.keys()))
    selected_case_id = case_options[selected_case_label]
else:
    st.info("No cases registered yet. Use the sidebar on the left to create your first case.")

# --- SIDEBAR: Export Case Report ---
if selected_case_id:
    with st.sidebar.expander("📄 Export Case Report"):
        case_info = c.execute("SELECT name, investigator, description, created_at FROM cases WHERE id = ?", (selected_case_id,)).fetchone()
        evidence_records = c.execute("SELECT file_name, file_size, sha256_hash, uploaded_at FROM evidence WHERE case_id = ?", (selected_case_id,)).fetchall()
        event_records = c.execute("SELECT event_type, severity, description, timestamp FROM events WHERE case_id = ? ORDER BY timestamp ASC", (selected_case_id,)).fetchall()
        browser_records = c.execute("SELECT url, title, visit_count, last_visit_time FROM browser_history WHERE case_id = ?", (selected_case_id,)).fetchall()

        report_md = f"""# Forensic Investigation Dossier
**Case:** {case_info[0]}  
**Investigator:** {case_info[1]}  
**Description:** {case_info[2]}  
**Case Opened:** {case_info[3]}  

---
## 1. Chain of Custody (Evidence)
| File Name | Size (Bytes) | SHA-256 Checksum | Ingested At |
|---|---|---|---|
"""
        for row in evidence_records:
            report_md += f"| `{row[0]}` | {row[1]} | `{row[2]}` | {row[3]} |\n"

        report_md += "\n## 2. Event Timeline\n| Timestamp | Event Type | Severity | Notes |\n|---|---|---|---|\n"
        for row in event_records:
            report_md += f"| {row[3]} | {row[0]} | {row[1]}/10 | {row[2]} |\n"

        report_md += "\n## 3. Web Footprints & Artifacts\n| URL | Title | Visit Count | Last Visited |\n|---|---|---|---|\n"
        for row in browser_records:
            report_md += f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} |\n"

        st.download_button(
            label="📥 Download Dossier (.md)",
            data=report_md,
            file_name=f"Forensic_Report_Case_{selected_case_id}.md",
            mime="text/markdown",
            use_container_width=True
        )

# Main Interface Tabs
tab_evidence, tab_events, tab_browser = st.tabs([
    "📁 Evidence Ingestion", 
    "⏱️ Event Timeline", 
    "🌐 Browser Artifacts"
])

# --- TAB 1: Evidence Ingestion ---
with tab_evidence:
    st.subheader("Acquire Artifact & Compute Checksum")
    uploaded_file = st.file_uploader("Upload suspicious artifact", type=None)

    if uploaded_file is not None and selected_case_id:
        file_bytes = uploaded_file.read()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        file_path = os.path.join("database/evidence_files", uploaded_file.name)

        with open(file_path, "wb") as f:
            f.write(file_bytes)

        if st.button("Store Evidence to Ledger", use_container_width=True):
            c.execute("INSERT INTO evidence (case_id, file_name, file_size, sha256_hash) VALUES (?, ?, ?, ?)",
                      (selected_case_id, uploaded_file.name, len(file_bytes), sha256))
            conn.commit()
            st.success(f"Evidence '{uploaded_file.name}' logged securely!")
            st.rerun()

    st.markdown("### Chain of Custody Ledger")
    if selected_case_id:
        evidence_list = c.execute("SELECT file_name, file_size, sha256_hash, uploaded_at FROM evidence WHERE case_id = ?",
                                  (selected_case_id,)).fetchall()
        if evidence_list:
            st.dataframe(
                [{"File Name": row[0], "Size (Bytes)": row[1], "SHA-256 Hash": row[2], "Acquired At": row[3]} for row in evidence_list],
                use_container_width=True
            )
        else:
            st.info("No evidence files cataloged for this case.")

# --- TAB 2: Event Timeline ---
with tab_events:
    st.subheader("Log Security Findings")
    with st.expander("Record New Event", expanded=True):
        col1, col2 = st.columns(2)
        with col1:
            event_type = st.selectbox("Event Type", [
                "Brute Force Attempt", 
                "Malware Execution", 
                "Registry Modification", 
                "Data Exfiltration", 
                "Privilege Escalation"
            ])
            severity = st.slider("Severity Level", 1, 10, 5)
        with col2:
            description = st.text_area("Event Description", placeholder="e.g. Unauthorized process injection observed in svchost.exe")
            event_time = st.text_input("Timestamp", value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        if st.button("Log Event", use_container_width=True):
            if selected_case_id:
                c.execute("INSERT INTO events (case_id, event_type, severity, description, timestamp) VALUES (?, ?, ?, ?, ?)",
                          (selected_case_id, event_type, severity, description, event_time))
                conn.commit()
                st.success("Event successfully recorded to timeline!")
                st.rerun()
            else:
                st.error("Please select or register an active case first.")

    st.markdown("### Timeline Audit Ledger")
    if selected_case_id:
        events = c.execute("SELECT event_type, severity, description, timestamp FROM events WHERE case_id = ? ORDER BY timestamp DESC",
                           (selected_case_id,)).fetchall()
        if events:
            st.dataframe(
                [{"Event": e[0], "Severity": f"🚨 {e[1]}" if e[1] >= 8 else f"⚠️ {e[1]}", "Description": e[2], "Timestamp": e[3]} for e in events],
                use_container_width=True
            )
        else:
            st.info("No timeline events logged yet.")

# --- TAB 3: Browser Artifacts ---
with tab_browser:
    st.subheader("Browser History & Digital Artifacts")
    
    with st.expander("Import Browser Artifacts"):
        browser_mode = st.radio("Artifact Source", ["Manual Entry", "Upload Chrome/Edge History SQLite File"])
        
        if browser_mode == "Manual Entry":
            b_col1, b_col2 = st.columns(2)
            with b_col1:
                b_url = st.text_input("Target URL", value="https://malicious-domain.com/c2")
                b_title = st.text_input("Page Title", value="Suspicious Portal")
            with b_col2:
                b_count = st.number_input("Visit Count", min_value=1, value=1)
                b_time = st.text_input("Last Visit Timestamp", value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                
            if st.button("Log Browser Artifact", use_container_width=True):
                if not selected_case_id:
                    st.error("No active case selected! Please select or register a case.")
                elif not b_url.strip():
                    st.warning("Please type a valid Target URL.")
                else:
                    c.execute("INSERT INTO browser_history (case_id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)",
                              (selected_case_id, b_url.strip(), b_title.strip(), b_count, b_time))
                    conn.commit()
                    st.success("Artifact logged successfully!")
                    st.rerun()
                    
        elif browser_mode == "Upload Chrome/Edge History SQLite File":
            history_file = st.file_uploader("Upload Chrome/Edge 'History' file", type=None, key="history_upload")
            if history_file and selected_case_id:
                if st.button("Parse & Ingest SQLite History", use_container_width=True):
                    temp_hist_path = "database/temp_history.db"
                    with open(temp_hist_path, "wb") as f:
                        f.write(history_file.read())
                    
                    try:
                        h_conn = sqlite3.connect(temp_hist_path)
                        h_c = h_conn.cursor()
                        rows = h_c.execute("SELECT url, title, visit_count, datetime(last_visit_time/1000000-11644473600, 'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 50").fetchall()
                        for row in rows:
                            c.execute("INSERT INTO browser_history (case_id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)",
                                      (selected_case_id, row[0], row[1] or "N/A", row[2], row[3] or "Unknown"))
                        conn.commit()
                        h_conn.close()
                        os.remove(temp_hist_path)
                        st.success(f"Parsed and imported {len(rows)} browser records!")
                        st.rerun()
                    except Exception as err:
                        st.error(f"Failed to parse history database: {err}")

    st.markdown("### Captured Web Footprints")
    if selected_case_id:
        history = c.execute("SELECT url, title, visit_count, last_visit_time FROM browser_history WHERE case_id = ? ORDER BY id DESC",
                            (selected_case_id,)).fetchall()
        if history:
            st.dataframe(
                [{"URL": h[0], "Title": h[1], "Visits": h[2], "Last Visited": h[3]} for h in history],
                use_container_width=True
            )
        else:
            st.info("No browser artifacts imported for this case.")