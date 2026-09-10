import hashlib
import os
import sqlite3
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Cybercrime Scene Investigator", page_icon="🔍", layout="wide"
)

DB_PATH = "database/evidence.db"


def get_connection():
  return sqlite3.connect(DB_PATH)


st.title("🔍 Cybercrime Scene Investigator")

st.sidebar.header("📁 Case Management")
new_case_name = st.sidebar.text_input("New Case Name")
investigator_name = st.sidebar.text_input("Investigator Name")
case_desc = st.sidebar.text_area("Case Description")

if st.sidebar.button("Register Case"):
  if new_case_name and investigator_name:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO cases (case_name, investigator, description) VALUES (?,"
        " ?, ?)",
        (new_case_name, investigator_name, case_desc),
    )
    conn.commit()
    conn.close()
    st.sidebar.success(f"Case '{new_case_name}' created!")
    st.rerun()
  else:
    st.sidebar.warning("Please enter both Case Name and Investigator.")

conn = get_connection()
cases_df = pd.read_sql_query(
    "SELECT case_id, case_name, investigator, created_at FROM cases ORDER BY"
    " created_at DESC",
    conn,
)

if cases_df.empty:
  st.info(
      "No cases registered yet. Use the sidebar on the left to add your first"
      " case."
  )
  conn.close()
  st.stop()

case_options = {
    f"{row['case_name']} (ID: {row['case_id']})": row["case_id"]
    for _, row in cases_df.iterrows()
}
selected_label = st.selectbox("Select Active Case", list(case_options.keys()))
active_case_id = case_options[selected_label]

tab_evidence, tab_events, tab_browser = st.tabs(
    ["📁 Evidence Ingestion", "⏱ Event Timeline", "🌐 Browser Artifacts"]
)

with tab_evidence:
  st.subheader("Acquire Artifact & Compute Checksum")
  uploaded_file = st.file_uploader(
      "Upload suspicious artifact", key="evidence_uploader"
  )
  if uploaded_file is not None:
    file_bytes = uploaded_file.read()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    file_size = len(file_bytes)
    file_ext = os.path.splitext(uploaded_file.name)[1]
    evidence_dir = "database/evidence_files"
    os.makedirs(evidence_dir, exist_ok=True)
    stored_path = os.path.join(evidence_dir, uploaded_file.name)
    with open(stored_path, "wb") as f:
      f.write(file_bytes)
    st.write(f"Computed SHA-256: {sha256_hash}")
    st.write(f"File Size: {file_size} bytes")
    if st.button("Commit Artifact to Evidence Ledger"):
      cur = conn.cursor()
      cur.execute(
          """
                INSERT INTO evidence (case_id, filename, file_path, file_type, size, sha256, created_time)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
          (
              active_case_id,
              uploaded_file.name,
              stored_path,
              file_ext,
              file_size,
              sha256_hash,
          ),
      )
      conn.commit()
      st.success(f"Artifact locked: {uploaded_file.name}")
      st.rerun()
  st.divider()
  st.subheader("Chain of Custody Ledger")
  ev_df = pd.read_sql_query(
      "SELECT evidence_id, filename, file_type, size, sha256, created_time"
      " FROM evidence WHERE case_id = ?",
      conn,
      params=(active_case_id,),
  )
  if not ev_df.empty:
    st.dataframe(ev_df, use_container_width=True)
  else:
    st.info("No evidence files cataloged for this case.")

with tab_events:
  st.subheader("Log Security Findings")
  with st.expander("Record New Event"):
    col1, col2 = st.columns(2)
    with col1:
      event_type = st.selectbox("Event Type", ["Brute Force Attempt", "Malware Execution", "Registry Modification", "Data Exfiltration", "Privilege Escalation"])