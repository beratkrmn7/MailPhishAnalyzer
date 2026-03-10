import json
import os
from google import genai


class GeminiReviewClient:
    def __init__(self, api_key: str | None = None, model: str = "gemini-3-flash-preview"):
        self.api_key = (api_key or os.getenv("GEMINI_API_KEY", "")).strip()
        self.model = model
        self.client = genai.Client(api_key=self.api_key) if self.api_key else None

    def enabled(self) -> bool:
        return self.client is not None

    def review_medium_report(self, report: dict) -> dict:
        if not self.enabled():
            return {"enabled": False, "error": "GEMINI_API_KEY missing"}

        schema = {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["phishing", "suspicious", "likely_legit"]
                },
                "confidence": {"type": "integer"},
                "social_engineering": {"type": "boolean"},
                "rationale": {"type": "string"},
                "final_action": {
                    "type": "string",
                    "enum": ["escalate_high", "keep_medium", "downgrade_low"]
                }
            },
            "required": [
                "verdict",
                "confidence",
                "social_engineering",
                "rationale",
                "final_action"
            ]
        }

        compact = {
            "subject": (report.get("meta") or {}).get("subject", ""),
            "sender_name": (report.get("from") or {}).get("name", ""),
            "sender_addr": (report.get("from") or {}).get("addr", ""),
            "reply_to": report.get("reply_to", {}),
            "return_path": report.get("return_path", {}),
            "auth": report.get("auth", {}),
            "risk": report.get("risk", 0),
            "level": report.get("level", ""),
            "reasons": report.get("reasons", []),
            "findings": [
                {
                    "id": f.get("id"),
                    "title": f.get("title"),
                    "score": f.get("score"),
                    "category": f.get("category"),
                }
                for f in report.get("findings", [])[:8]
            ],
            "links": [
                {
                    "href": l.get("href"),
                    "domain": l.get("domain"),
                    "visible_domains": l.get("visible_domains", []),
                }
                for l in report.get("links", [])[:5]
            ],
            "attachments": report.get("attachments", [])[:5],
            "text_excerpt": (report.get("meta") or {}).get("text_excerpt", "")[:2500],
        }

        prompt = f"""
You are reviewing an email security triage result.
The rule engine has already classified this email as MEDIUM risk.

Your job:
- Decide whether this email is likely phishing, merely suspicious, or likely legitimate.
- Pay extra attention to social engineering, impersonation, and whether the findings together look malicious.
- Be conservative: do not downgrade if there is strong evidence like link mismatch, threat-intel match, or dangerous attachment.
- Return ONLY valid JSON.

Email report:
{json.dumps(compact, ensure_ascii=False, indent=2)}
"""

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    "response_json_schema": schema,
                },
            )
            data = json.loads(response.text)
            data["enabled"] = True
            data["model"] = self.model
            return data
        except Exception as e:
            return {
                "enabled": True,
                "model": self.model,
                "error": str(e)
            }