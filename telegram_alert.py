import json
import html
import urllib.request
import urllib.error


class TelegramAlertClient:
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = (bot_token or "").strip()
        self.chat_id = str(chat_id).strip()

    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def _escape(self, text):
        return html.escape(str(text or ""))

    def _pretty_subject(self, subject: str) -> str:
        subject = (subject or "").strip()
        if not subject or subject.lower() == "(no subject)":
            return "Konu yok"
        return subject

    def _shorten(self, text: str, max_len: int = 90) -> str:
        text = str(text or "")
        if len(text) <= max_len:
            return text
        return text[:max_len - 3] + "..."

    def _level_icon(self, level: str) -> str:
        if level == "HIGH":
            return "🚨"
        if level == "MEDIUM":
            return "⚠️"
        return "🟢"

    def _level_label(self, level: str) -> str:
        if level == "HIGH":
            return "Yüksek Risk"
        if level == "MEDIUM":
            return "Orta Risk"
        return "Düşük Risk"

    def _build_message(self, report: dict) -> str:
        meta = report.get("meta", {}) or {}
        sender = (report.get("from") or {}).get("addr", "?")
        sender_name = (report.get("from") or {}).get("name", "")
        subject = self._pretty_subject(meta.get("subject", ""))
        risk = report.get("risk", 0)
        level = report.get("level", "UNKNOWN")
        reasons = report.get("reasons", [])[:3]
        findings = report.get("findings", [])[:3]
        links = report.get("links", [])[:2]

        icon = self._level_icon(level)
        level_label = self._level_label(level)

        lines = []
        lines.append(f"{icon} <b>{self._escape(level_label)} E-Posta Alarmı</b>")
        lines.append("")
        lines.append(f"<b>Risk Skoru:</b> {self._escape(risk)}/100")
        lines.append(f"<b>Seviye:</b> {self._escape(level)}")
        lines.append(f"<b>Konu:</b> {self._escape(subject)}")

        if sender_name:
            lines.append(f"<b>Gönderen:</b> {self._escape(sender_name)} &lt;{self._escape(sender)}&gt;")
        else:
            lines.append(f"<b>Gönderen:</b> {self._escape(sender)}")

        if reasons:
            lines.append("")
            lines.append("<b>Neden Şüpheli?</b>")
            for r in reasons:
                lines.append(f"• {self._escape(r)}")

        if findings:
            lines.append("")
            lines.append("<b>Tetiklenen Kurallar</b>")
            for f in findings:
                fid = f.get("id", "UNKNOWN")
                title = f.get("title", "")
                score = f.get("score", 0)
                lines.append(f"• <code>{self._escape(fid)}</code> (+{self._escape(score)})")
                if title:
                    lines.append(f"  {self._escape(title)}")
        
        llm = report.get("llm_review") or {}
        if llm and not llm.get("error") and llm.get("enabled"):
            lines.append("")
            lines.append("<b>Gemini Ikinci Gorus</b>")
            lines.append(f"• <b>Karar:</b> {self._escape(llm.get('verdict', 'unknown'))}")
            lines.append(f"• <b>Guven:</b> {self._escape(llm.get('confidence', 0))}/100")
            rationale = llm.get("rationale", "")
            if rationale:
                lines.append(f"• <b>Yorum:</b> {self._escape(self._shorten(rationale, 180))}")




        if links:
            lines.append("")
            lines.append("<b>Şüpheli Linkler</b>")
            for l in links:
                href = l.get("href", "")
                if href:
                    lines.append(f"• <code>{self._escape(self._shorten(href, 100))}</code>")

        lines.append("")
        lines.append("<i>MailPhishAnalyzer tarafından üretildi.</i>")

        return "\n".join(lines)[:3900]
    

    def send_startup_message(self, interval_seconds: int, base_query: str, safe_browsing_enabled: bool, gemini_enabled: bool, last_check_ts: str | None) -> dict:
        if not self.enabled():
            return {"ok": False, "error": "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing"}

        from datetime import datetime

        started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        sb_text = "Aktif" if safe_browsing_enabled else "Kapalı"
        gemini_text = "Aktif" if gemini_enabled else "Kapalı"

        if last_check_ts:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(last_check_ts)
                last_check_text = dt.strftime("%d.%m.%Y %H:%M:%S")
            except Exception:
                last_check_text = last_check_ts
        else:
            last_check_text = "İlk çalıştırma / kayıt yok"

        text = (
            "🟢 <b>MailPhishAnalyzer Başlatıldı</b>\n\n"
            f"<b>Saat:</b> {started_at}\n"
            f"<b>İzleme Durumu:</b> Gmail takibi başladı\n"
            f"<b>Kontrol Aralığı:</b> {interval_seconds} saniye\n"
            f"<b>Sorgu:</b> <code>{base_query}</code>\n"
            f"<b>Son Kontrol Zamanı:</b> {last_check_text}\n"
            f"<b>Safe Browsing:</b> {sb_text}\n"
            f"<b>Gemini İkinci Görüş:</b> {gemini_text}\n\n"
            "<i>Sistem başarıyla açıldı ve izleme döngüsü başlatıldı.</i>"
        )

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        req = urllib.request.Request(
            url=url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {"ok": True}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="ignore")
            return {"ok": False, "error": f"HTTPError {e.code}: {detail}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}






    def send_alert(self, report: dict) -> dict:
        if not self.enabled():
            return {"ok": False, "error": "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing"}

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": self._build_message(report),
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        req = urllib.request.Request(
            url=url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {"ok": True}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="ignore")
            return {"ok": False, "error": f"HTTPError {e.code}: {detail}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}