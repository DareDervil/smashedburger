"""
Reset all application data without touching the schema or the DB file.
Safe to run on a volume-backed SQLite on Fly.io.

Usage:
    python3 scripts/reset_db.py           # wipe everything
    python3 scripts/reset_db.py --confirm # skip the confirmation prompt

Does NOT delete: users, auth_codes, feeds (so you can log back in immediately
and feeds don't need re-seeding). Pass --wipe-users to also clear auth tables.
"""
import sys, sqlite3, os

DB_PATH = os.getenv("DB_PATH", "smashedburger.db")
print(f"Target DB: {os.path.abspath(DB_PATH)}")

# Tables wiped by default — all application data except auth and feeds
DATA_TABLES = [
    "messages", "conversations",
    "checklist_items", "links",
    "infra_vendors", "infra_products", "infra_versions", "infra_relationships", "network_constraints",
    "iocs", "ioc_sources",
    "monitors", "monitor_news",
    "vt_results", "kev_status",
    "cwe_controls", "cwe_cache",
    "topics", "topic_mentions",
    "learning_recs", "telemetry_events", "telemetry_suggestions",
    "nvd_retry_queue",
    "cve_records", "pkg_records", "pkg_conv_links",
    "news_items",
]

AUTH_TABLES = ["users", "auth_codes"]

wipe_users = "--wipe-users" in sys.argv
confirm    = "--confirm"    in sys.argv

if not confirm:
    print(f"About to wipe all data in {DB_PATH}.")
    if wipe_users:
        print("INCLUDING users and auth_codes (--wipe-users set).")
    ans = input("Type 'yes' to continue: ")
    if ans.strip().lower() != "yes":
        print("Aborted.")
        sys.exit(0)

tables = DATA_TABLES + (AUTH_TABLES if wipe_users else [])

conn = sqlite3.connect(DB_PATH)
conn.execute("PRAGMA foreign_keys = OFF")
for t in tables:
    try:
        conn.execute(f"DELETE FROM {t}")
        print(f"  cleared {t}")
    except Exception as e:
        print(f"  skipped {t}: {e}")
conn.execute("PRAGMA foreign_keys = ON")
conn.commit()
conn.close()
print("Done. Schema intact. Restart the app to re-seed default feeds.")
