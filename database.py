import sqlite3
import datetime

DB_PATH = "arp_events.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            target_ip TEXT,
            source_mac TEXT,
            target_mac TEXT,
            details TEXT,
            severity TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_event(event_type, source_ip=None, target_ip=None,
                 source_mac=None, target_mac=None, details="", severity="info"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    c.execute('''
        INSERT INTO events (timestamp, event_type, source_ip, target_ip,
                            source_mac, target_mac, details, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, event_type, source_ip, target_ip,
          source_mac, target_mac, details, severity))
    conn.commit()
    conn.close()

def get_events(limit=100, offset=0, event_type=None, severity=None, search=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = "SELECT * FROM events"
    conditions = []
    params = []
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if search:
        conditions.append("(details LIKE ? OR source_ip LIKE ? OR target_ip LIKE ?)")
        search_pattern = f"%{search}%"
        params.extend([search_pattern, search_pattern, search_pattern])
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    columns = ['id', 'timestamp', 'event_type', 'source_ip', 'target_ip',
               'source_mac', 'target_mac', 'details', 'severity']
    return [dict(zip(columns, row)) for row in rows]

def get_event_counts():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT event_type, COUNT(*) FROM events GROUP BY event_type")
    type_counts = c.fetchall()
    c.execute("SELECT severity, COUNT(*) FROM events GROUP BY severity")
    severity_counts = c.fetchall()
    conn.close()
    return {
        'type_counts': dict(type_counts),
        'severity_counts': dict(severity_counts)
    }

def clear_events():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM events")
    conn.commit()
    conn.close()