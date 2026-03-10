import time
import json
import argparse
import os
from datetime import datetime, timedelta

from colorama import Fore, Style, init

from gmail_client import GmailClient
from analyzer import analyze_message
from reporter import write_daily_summary, save_message_report
from safe_browsing_client import SafeBrowsingClient, enrich_report_with_safe_browsing
from telegram_alert import TelegramAlertClient
from llm_client import GeminiReviewClient

init(autoreset=True)

STATE_FILE = "state.json"


def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
    except FileNotFoundError:
        state = {}

    state.setdefault("processed_ids", [])
    state.setdefault("day", None)
    state.setdefault("last_check_ts", None)
    state.setdefault("daily", {
        "scanned": 0,
        "suspect": 0,
        "levels": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
        "top_from_domains": {},
        "top_link_domains": {},
        "top_findings": {}
    })
    return state


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def today_str():
    return datetime.now().strftime("%Y-%m-%d")


def rotate_day_if_needed(state):
    t = today_str()
    if state.get("day") != t:
        if state.get("day") is not None:
            write_daily_summary(state["day"], state["daily"])

        state["day"] = t
        state["daily"] = {
            "scanned": 0,
            "suspect": 0,
            "levels": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
            "top_from_domains": {},
            "top_link_domains": {},
            "top_findings": {}
        }
        state["processed_ids"] = state.get("processed_ids", [])[-3000:]


def bump_counter(d, key):
    d[key] = d.get(key, 0) + 1


def build_query(base_query: str, last_check_ts: str | None, fallback_hours: int = 24, overlap_seconds: int = 120) -> str:
    q = base_query.strip()

    if last_check_ts:
        try:
            dt = datetime.fromisoformat(last_check_ts)
            dt = dt - timedelta(seconds=overlap_seconds)
            unix_ts = int(dt.timestamp())
            return f"{q} after:{unix_ts}"
        except Exception:
            pass

    fallback_dt = datetime.now() - timedelta(hours=fallback_hours)
    unix_ts = int(fallback_dt.timestamp())
    return f"{q} after:{unix_ts}"


def _has_strong_rule_evidence(report: dict) -> bool:
    ids = {f.get("id") for f in report.get("findings", [])}
    strong = {
        "THREAT_INTEL_MATCH",
        "LINK_TEXT_MISMATCH",
        "RISKY_ATTACHMENTS",
        "LOOKALIKE_DOMAIN",
    }
    return bool(ids & strong)


def apply_llm_second_opinion(report: dict, llm_client: GeminiReviewClient | None) -> dict:
    if not llm_client or not llm_client.enabled():
        return report

    if report.get("level") != "MEDIUM":
        return report

    llm = llm_client.review_medium_report(report)
    report["llm_review"] = llm

    if llm.get("error"):
        return report

    action = llm.get("final_action")
    confidence = int(llm.get("confidence", 0))
    rationale = llm.get("rationale", "")

    strong_rule_evidence = _has_strong_rule_evidence(report)

    if action == "escalate_high" and confidence >= 75:
        report["risk"] = max(70, report["risk"] + 15)
        report["level"] = "HIGH"
        note = f"Gemini anlamsal analiz yukseltti: {rationale}"
        report["reasons"] = [note] + report.get("reasons", [])[:4]
        report.setdefault("findings", []).append({
            "category": "LLM",
            "id": "LLM_ESCALATION",
            "score": 15,
            "title": "Gemini anlamsal analizi phishing olasiligini yuksek buldu",
            "evidence": {
                "confidence": confidence,
                "verdict": llm.get("verdict"),
                "rationale": rationale,
                "model": llm.get("model"),
            },
        })
        return report

    if action == "downgrade_low" and confidence >= 80 and not strong_rule_evidence:
        report["risk"] = min(24, report["risk"])
        report["level"] = "LOW"
        note = f"Gemini anlamsal analiz dusurdu: {rationale}"
        report["reasons"] = [note] + report.get("reasons", [])[:4]
        report.setdefault("findings", []).append({
            "category": "LLM",
            "id": "LLM_DOWNGRADE",
            "score": -10,
            "title": "Gemini anlamsal analizi e-postayi muhtemelen mesru buldu",
            "evidence": {
                "confidence": confidence,
                "verdict": llm.get("verdict"),
                "rationale": rationale,
                "model": llm.get("model"),
            },
        })
        return report

    return report


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + "=" * 68)
    print(Fore.CYAN + Style.BRIGHT + " MailPhishAnalyzer")
    print(Fore.CYAN + " Hybrid Gmail Phishing Triage & Alerting System")
    print(Fore.CYAN + Style.BRIGHT + "=" * 68)


def print_status(label: str, value: str, color=Fore.WHITE):
    print(Fore.WHITE + Style.BRIGHT + f"[{label}] " + color + str(value))


def print_query(query: str):
    print(Fore.MAGENTA + Style.BRIGHT + f"[QUERY] " + Fore.WHITE + query)


def print_result(report: dict):
    level = report.get("level", "UNKNOWN")
    subject = report.get("meta", {}).get("subject", "") or "Konu yok"
    risk = report.get("risk", 0)
    sender = (report.get("from") or {}).get("addr", "?")
    reasons = "; ".join(report.get("reasons", [])[:3])

    if level == "HIGH":
        color = Fore.RED + Style.BRIGHT
    elif level == "MEDIUM":
        color = Fore.YELLOW + Style.BRIGHT
    else:
        color = Fore.GREEN + Style.BRIGHT

    print(color + f"[{level}] " + Fore.WHITE + f"{subject}")
    print(Fore.WHITE + f"  Risk   : {risk}/100")
    print(Fore.WHITE + f"  From   : {sender}")
    if reasons:
        print(Fore.WHITE + f"  Reason : {reasons}")
    print(Fore.BLUE + "-" * 68)


def run_loop(interval_seconds: int, base_query: str, threshold: int, max_results: int,
             export_messages: bool, enable_label: bool):
    state = load_state()
    rotate_day_if_needed(state)

    gmail = GmailClient()

    safe_browsing_api_key = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
    telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    gemini_api_key = os.getenv("GEMINI_API_KEY", "").strip()

    sb_client = SafeBrowsingClient(safe_browsing_api_key) if safe_browsing_api_key else None
    tg_client = TelegramAlertClient(telegram_bot_token, telegram_chat_id) if telegram_bot_token and telegram_chat_id else None
    llm_client = GeminiReviewClient(gemini_api_key) if gemini_api_key else None

    label_ids = {}
    if enable_label:
        try:
            label_ids["HIGH"] = gmail.get_or_create_label_id("PHISH_HIGH")
            label_ids["MEDIUM"] = gmail.get_or_create_label_id("PHISH_MED")
            label_ids["LOW"] = gmail.get_or_create_label_id("PHISH_LOW")
        except Exception:
            enable_label = False

    print_banner()
    print_status("STATUS", "Calisiyor", Fore.GREEN + Style.BRIGHT)
    print_status("INTERVAL", f"{interval_seconds} saniye", Fore.CYAN)
    print_status("THRESHOLD", f"{threshold}", Fore.CYAN)
    print_status("QUERY BASE", base_query, Fore.CYAN)
    print_status("MAX", f"{max_results}", Fore.CYAN)
    print_status("EXPORT", "Aktif" if export_messages else "Kapali", Fore.CYAN)
    print_status("LABEL", "Aktif" if enable_label else "Kapali", Fore.CYAN)
    print_status("SAFE BROWSING", "Aktif" if sb_client else "Kapali", Fore.GREEN if sb_client else Fore.RED)
    print_status("TELEGRAM", "Aktif" if tg_client else "Kapali", Fore.GREEN if tg_client else Fore.RED)
    print_status("GEMINI REVIEW", "Aktif" if llm_client else "Kapali", Fore.GREEN if llm_client else Fore.RED)
    print(Fore.BLUE + "-" * 68)

    if tg_client:
        startup_result = tg_client.send_startup_message(
            interval_seconds=interval_seconds,
            base_query=base_query,
            safe_browsing_enabled=bool(sb_client),
            gemini_enabled=bool(llm_client),
            last_check_ts=state.get("last_check_ts"),
        )
        if not startup_result.get("ok", False):
            print_status("STARTUP MSG ERROR", startup_result.get("error"), Fore.RED + Style.BRIGHT)

    while True:
        rotate_day_if_needed(state)

        effective_query = build_query(base_query, state.get("last_check_ts"))
        print_query(effective_query)

        message_ids = gmail.list_message_ids(query=effective_query, max_results=max_results)

        for mid in message_ids:
            if mid in state["processed_ids"]:
                continue

            msg = gmail.get_message(mid)
            report = analyze_message(msg)

            if sb_client:
                report = enrich_report_with_safe_browsing(report, sb_client)

            report = apply_llm_second_opinion(report, llm_client)

            state["processed_ids"].append(mid)
            state["daily"]["scanned"] += 1

            lvl = report["level"]
            state["daily"]["levels"][lvl] = state["daily"]["levels"].get(lvl, 0) + 1

            from_dom = (report.get("from") or {}).get("domain")
            if from_dom:
                bump_counter(state["daily"]["top_from_domains"], from_dom)

            for l in (report.get("links") or [])[:8]:
                dom = l.get("domain")
                if dom:
                    bump_counter(state["daily"]["top_link_domains"], dom)

            for f in (report.get("findings") or [])[:12]:
                bump_counter(state["daily"]["top_findings"], f.get("id", "UNKNOWN"))

            if export_messages:
                save_message_report(mid, report)

            print_result(report)

            if report["risk"] >= threshold:
                state["daily"]["suspect"] += 1

                if enable_label:
                    try:
                        gmail.add_label(mid, label_ids.get(lvl, label_ids.get("MEDIUM")))
                    except Exception:
                        pass

                if tg_client and report["level"] == "HIGH":
                    result = tg_client.send_alert(report)
                    if not result.get("ok", False):
                        print_status("TELEGRAM ERROR", result.get("error"), Fore.RED + Style.BRIGHT)

        state["last_check_ts"] = datetime.now().isoformat(timespec="seconds")
        save_state(state)
        time.sleep(interval_seconds)


def main():
    parser = argparse.ArgumentParser(description="MailPhishAnalyzer - Gmail phishing triage")
    parser.add_argument("--interval", type=int, default=120, help="Kac saniyede bir kontrol edilsin")
    parser.add_argument("--query", type=str, default="in:inbox", help="Temel Gmail arama sorgusu")
    parser.add_argument("--threshold", type=int, default=70, help="Supheli sayilmasi icin risk esigi")
    parser.add_argument("--max", type=int, default=25, help="Her turda en fazla kac mail bakilsin")
    parser.add_argument("--export", action="store_true", help="Her mail icin JSON raporu kaydet")
    parser.add_argument("--label", action="store_true", help="Seviyeye gore Gmail label ekle")
    args = parser.parse_args()

    run_loop(
        interval_seconds=args.interval,
        base_query=args.query,
        threshold=args.threshold,
        max_results=args.max,
        export_messages=args.export,
        enable_label=args.label
    )


if __name__ == "__main__":
    main()