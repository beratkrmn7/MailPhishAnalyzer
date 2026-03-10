import json
import urllib.request
import urllib.error


class SafeBrowsingClient:
    def __init__(self, api_key: str, client_id: str = "mailphishanalyzer", client_version: str = "1.0"):
        self.api_key = (api_key or "").strip()
        self.client_id = client_id
        self.client_version = client_version

    def enabled(self) -> bool:
        return bool(self.api_key)

    def lookup_urls(self, urls: list[str]) -> dict:
        if not self.api_key:
            return {"enabled": False, "matched": False, "matches": [], "error": "SAFE_BROWSING_API_KEY missing"}

        cleaned = []
        seen = set()
        for u in urls:
            u = (u or "").strip()
            if not u or u in seen:
                continue
            seen.add(u)
            cleaned.append(u)

        if not cleaned:
            return {"enabled": True, "matched": False, "matches": []}

        body = {
            "client": {
                "clientId": self.client_id,
                "clientVersion": self.client_version
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in cleaned[:20]]
            }
        }

        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        req = urllib.request.Request(
            url=url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8")
                data = json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="ignore")
            return {
                "enabled": True,
                "matched": False,
                "matches": [],
                "error": f"HTTPError {e.code}: {detail}"
            }
        except Exception as e:
            return {
                "enabled": True,
                "matched": False,
                "matches": [],
                "error": str(e)
            }

        matches = data.get("matches", []) if isinstance(data, dict) else []
        return {
            "enabled": True,
            "matched": bool(matches),
            "matches": matches
        }


def enrich_report_with_safe_browsing(report: dict, sb_client: SafeBrowsingClient) -> dict:
    if not sb_client or not sb_client.enabled():
        return report

    urls = [l.get("href") for l in report.get("links", []) if l.get("href")]
    intel = sb_client.lookup_urls(urls)

    report["threat_intel"] = {
        "provider": "Google Safe Browsing",
        "enabled": intel.get("enabled", False),
        "matched": intel.get("matched", False),
        "error": intel.get("error"),
        "matches": intel.get("matches", [])[:5],
    }

    if intel.get("matched"):
        title = "Google Safe Browsing eşleşmesi bulundu (unsafe URL)"
        report.setdefault("findings", []).append({
            "category": "LINKS",
            "id": "THREAT_INTEL_MATCH",
            "score": 100,
            "title": title,
            "evidence": {
                "provider": "Google Safe Browsing",
                "matches": intel.get("matches", [])[:5]
            },
        })

        report["risk"] = 100
        report["level"] = "HIGH"

        reasons = report.get("reasons", [])
        if title not in reasons:
            report["reasons"] = [title] + reasons[:4]

        breakdown = report.get("category_breakdown", {})
        breakdown["THREAT_INTEL"] = 100
        report["category_breakdown"] = breakdown

    return report