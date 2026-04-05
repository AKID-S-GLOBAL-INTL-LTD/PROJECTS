"""Database model helpers — thin wrappers around raw SQL."""

from db.database import get_connection
from datetime import datetime


class RuleModel:
    @staticmethod
    def all():
        with get_connection() as c:
            rows = c.execute(
                "SELECT * FROM rules ORDER BY priority ASC, id ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def enabled():
        with get_connection() as c:
            rows = c.execute(
                "SELECT * FROM rules WHERE enabled=1 ORDER BY priority ASC, id ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get(rule_id):
        with get_connection() as c:
            row = c.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def create(data):
        with get_connection() as c:
            cur = c.execute("""
                INSERT INTO rules (name, description, action, protocol, direction,
                                   src_ip, dst_ip, src_port, dst_port,
                                   is_default, enabled, priority)
                VALUES (:name,:description,:action,:protocol,:direction,
                        :src_ip,:dst_ip,:src_port,:dst_port,
                        :is_default,:enabled,:priority)
            """, data)
            c.commit()
            return cur.lastrowid

    @staticmethod
    def update(rule_id, data):
        data['id'] = rule_id
        data['updated_at'] = datetime.utcnow().isoformat()
        with get_connection() as c:
            c.execute("""
                UPDATE rules SET name=:name, description=:description,
                  action=:action, protocol=:protocol, direction=:direction,
                  src_ip=:src_ip, dst_ip=:dst_ip, src_port=:src_port,
                  dst_port=:dst_port, enabled=:enabled, priority=:priority,
                  updated_at=:updated_at
                WHERE id=:id
            """, data)
            c.commit()

    @staticmethod
    def delete(rule_id):
        with get_connection() as c:
            c.execute("DELETE FROM rules WHERE id=? AND is_default=0", (rule_id,))
            c.commit()

    @staticmethod
    def toggle(rule_id):
        with get_connection() as c:
            c.execute(
                "UPDATE rules SET enabled = 1 - enabled WHERE id=?", (rule_id,)
            )
            c.commit()


class BlacklistModel:
    @staticmethod
    def all():
        with get_connection() as c:
            rows = c.execute(
                "SELECT * FROM blacklist ORDER BY added_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def contains(ip):
        with get_connection() as c:
            row = c.execute(
                "SELECT id FROM blacklist WHERE ip_address=?", (ip,)
            ).fetchone()
            return row is not None

    @staticmethod
    def add(ip, reason=''):
        with get_connection() as c:
            try:
                c.execute(
                    "INSERT OR IGNORE INTO blacklist (ip_address, reason) VALUES (?,?)",
                    (ip, reason)
                )
                c.commit()
                return True
            except Exception:
                return False

    @staticmethod
    def remove(ip):
        with get_connection() as c:
            c.execute("DELETE FROM blacklist WHERE ip_address=?", (ip,))
            c.commit()

    @staticmethod
    def remove_by_id(entry_id):
        with get_connection() as c:
            c.execute("DELETE FROM blacklist WHERE id=?", (entry_id,))
            c.commit()


class LogModel:
    @staticmethod
    def add(entry):
        with get_connection() as c:
            c.execute("""
                INSERT INTO traffic_logs
                  (action, src_ip, dst_ip, src_port, dst_port,
                   protocol, rule_id, rule_name, size, flags)
                VALUES (:action,:src_ip,:dst_ip,:src_port,:dst_port,
                        :protocol,:rule_id,:rule_name,:size,:flags)
            """, entry)
            c.commit()

    @staticmethod
    def recent(limit=200, action_filter=None, ip_filter=None):
        query = "SELECT * FROM traffic_logs WHERE 1=1"
        params = []
        if action_filter and action_filter != 'all':
            query += " AND action=?"
            params.append(action_filter)
        if ip_filter:
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
            params.extend([f'%{ip_filter}%', f'%{ip_filter}%'])
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with get_connection() as c:
            rows = c.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def stats():
        with get_connection() as c:
            total   = c.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
            blocked = c.execute("SELECT COUNT(*) FROM traffic_logs WHERE action='block'").fetchone()[0]
            allowed = c.execute("SELECT COUNT(*) FROM traffic_logs WHERE action='allow'").fetchone()[0]
            today   = c.execute(
                "SELECT COUNT(*) FROM traffic_logs WHERE date(timestamp)=date('now')"
            ).fetchone()[0]

            top_blocked = c.execute("""
                SELECT src_ip, COUNT(*) as cnt FROM traffic_logs
                WHERE action='block' GROUP BY src_ip ORDER BY cnt DESC LIMIT 5
            """).fetchall()

            top_protocols = c.execute("""
                SELECT protocol, COUNT(*) as cnt FROM traffic_logs
                GROUP BY protocol ORDER BY cnt DESC LIMIT 5
            """).fetchall()

            return {
                'total': total,
                'blocked': blocked,
                'allowed': allowed,
                'today': today,
                'top_blocked_ips': [dict(r) for r in top_blocked],
                'top_protocols': [dict(r) for r in top_protocols],
            }

    @staticmethod
    def purge_old(max_entries=50000):
        with get_connection() as c:
            count = c.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
            if count > max_entries:
                delete_count = count - max_entries
                c.execute("""
                    DELETE FROM traffic_logs WHERE id IN (
                        SELECT id FROM traffic_logs ORDER BY id ASC LIMIT ?
                    )
                """, (delete_count,))
                c.commit()


class SettingsModel:
    @staticmethod
    def get(key, default=None):
        with get_connection() as c:
            row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return row['value'] if row else default

    @staticmethod
    def set(key, value):
        with get_connection() as c:
            c.execute("""
                INSERT INTO settings (key, value) VALUES (?,?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value,
                  updated_at=datetime('now')
            """, (key, str(value)))
            c.commit()

    @staticmethod
    def all():
        with get_connection() as c:
            rows = c.execute("SELECT key, value FROM settings").fetchall()
            return {r['key']: r['value'] for r in rows}
