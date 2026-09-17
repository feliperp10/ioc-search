import os
import sqlite3
import json
from datetime import datetime, timedelta

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ioc_cache.db")


class Database:
    def __init__(self, db_path=DEFAULT_DB_PATH):
        self.conn = sqlite3.connect(db_path)
        self.create_table()

    def create_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS ioc_results (
            ioc TEXT PRIMARY KEY,
            ioc_type TEXT,
            data JSON,
            last_updated TIMESTAMP
        )
        """
        self.conn.execute(query)
        self.conn.commit()

    def get_cached_result(self, ioc, expiry_hours=48):
        """Retorna o cache apenas se tiver menos de 48 horas."""
        cursor = self.conn.cursor()
        query = "SELECT data, last_updated FROM ioc_results WHERE ioc = ?"
        cursor.execute(query, (ioc,))
        row = cursor.fetchone()
        
        if row:
            data, last_updated = row
            last_date = datetime.strptime(last_updated, '%Y-%m-%d %H:%M:%S')
            
            # Se o cache for recente (menos de 48h), retorna os dados
            if datetime.now() - last_date < timedelta(hours=expiry_hours):
                return data
            else:
                # Se for antigo, remove do banco para forçar nova consulta
                self.conn.execute("DELETE FROM ioc_results WHERE ioc = ?", (ioc,))
                self.conn.commit()
        return None

    def save_result(self, ioc, ioc_type, data):
        query = "INSERT OR REPLACE INTO ioc_results (ioc, ioc_type, data, last_updated) VALUES (?, ?, ?, ?)"
        self.conn.execute(query, (ioc, ioc_type, json.dumps(data), datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        self.conn.commit()

    def get_all_history(self):
        cursor = self.conn.cursor()
        query = "SELECT last_updated, ioc_type, ioc, data FROM ioc_results ORDER BY last_updated DESC"
        cursor.execute(query)
        return cursor.fetchall()

    def cleanup_old_records(self, expiry_hours=48):
        """Limpeza forçada de tudo o que for mais antigo que 48h."""
        limit_date = (datetime.now() - timedelta(hours=expiry_hours)).strftime('%Y-%m-%d %H:%M:%S')
        self.conn.execute("DELETE FROM ioc_results WHERE last_updated < ?", (limit_date,))
        self.conn.commit()