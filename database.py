import sqlite3
from datetime import datetime

DB_PATH = "soc_security.db"

def get_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    """서버 시작 시 안전하게 테이블 및 인덱스 생성 (기존 데이터 유지)"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            user_id TEXT PRIMARY KEY,
            reason TEXT,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS event_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            prompt TEXT,
            threat_score REAL,
            attack_type TEXT,
            action TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_user ON event_logs(user_id)")
    
    conn.commit()
    conn.close()
    print("[DB] Security Database Initialized Successfully!")

def reset_db():
    """테스트/개발용: 데이터베이스 전체 삭제 후 초기화"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("DROP TABLE IF EXISTS blacklist")
    cursor.execute("DROP TABLE IF EXISTS event_logs")
    conn.commit()
    conn.close()
    
    init_db()
    print("[DB Warning] Database has been completely reset!")



def is_user_blocked(user_id: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM blacklist WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row is not None

def block_user(user_id: str, reason: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO blacklist (user_id, reason) VALUES (?, ?)",
        (user_id, reason)
    )
    conn.commit()
    conn.close()

def log_event(user_id: str, prompt: str, threat_score: float, attack_type: str, action: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO event_logs (user_id, prompt, threat_score, attack_type, action) VALUES (?, ?, ?, ?, ?)",
        (user_id, prompt, threat_score, attack_type, action)
    )
    conn.commit()
    conn.close()

if __name__ == "__main__":
    confirm = input("⚠️ 경고: 데이터베이스 전체(블랙리스트, 로그)가 초기화됩니다. 진행하시겠습니까? (y/N): ")
    if confirm.lower() == "y":
        reset_db()
    else:
        print("[DB] 초기화 작업이 취소되었습니다.")