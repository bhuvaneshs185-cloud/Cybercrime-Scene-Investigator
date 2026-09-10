import os
import sqlite3

# Ensure database directory exists
os.makedirs("database", exist_ok=True)

# Connect to database
conn = sqlite3.connect("database/evidence.db")
cursor = conn.cursor()

# Enable foreign key support
cursor.execute("PRAGMA foreign_keys = ON;")

# 1. Cases Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS cases (
    case_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_name TEXT NOT NULL,
    investigator TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# 2. Evidence Table (Stores collected files, hashes, timestamps)
cursor.execute("""
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_type TEXT,
    size INTEGER,
    sha256 TEXT,
    created_time TIMESTAMP,
    modified_time TIMESTAMP,
    accessed_time TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
)
""")

# 3. Events Table (Timeline & suspicious activities)
cursor.execute("""
CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    source TEXT,
    description TEXT,
    risk_score REAL DEFAULT 0.0,
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
)
""")

# 4. Browser Table (Web history / digital traces)
cursor.execute("""
CREATE TABLE IF NOT EXISTS browser (
    browser_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    url TEXT,
    title TEXT,
    visit_time TIMESTAMP,
    visit_count INTEGER DEFAULT 1,
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
)
""")

conn.commit()
conn.close()
print("All tables (cases, evidence, events, browser) initialized successfully!")