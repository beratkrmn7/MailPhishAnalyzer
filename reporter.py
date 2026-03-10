import json
import os
from datetime import datetime

def ensure_dirs():
    os.makedirs("reports", exist_ok=True)
    os.makedirs(os.path.join("reports", "messages"), exist_ok=True)

def write_daily_summary(day_str, daily):
    ensure_dirs()
    out = {
        "day": day_str,
        "scanned": daily.get("scanned", 0),
        "suspect": daily.get("suspect", 0),
        "levels": daily.get("levels", {"LOW": 0, "MEDIUM": 0, "HIGH": 0}),
        "top_from_domains": sorted(daily.get("top_from_domains", {}).items(), key=lambda x: x[1], reverse=True)[:10],
        "top_link_domains": sorted(daily.get("top_link_domains", {}).items(), key=lambda x: x[1], reverse=True)[:10],
        "top_findings": sorted(daily.get("top_findings", {}).items(), key=lambda x: x[1], reverse=True)[:15],
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }
    path = os.path.join("reports", f"summary_{day_str}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"📝 Günlük özet yazıldı: {path}")

def save_message_report(message_id, report: dict):
    ensure_dirs()
    path = os.path.join("reports", "messages", f"{message_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return path