import base64
import re
import ipaddress
import json
import os
from urllib.parse import urlparse
from difflib import SequenceMatcher
from bs4 import BeautifulSoup
from email.utils import parseaddr, getaddresses

URL_RE = re.compile(r"https?://[^\s<>\"]+")
DOMAIN_RE = re.compile(r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "icloud.com", "proton.me", "protonmail.com", "yandex.com"
}

SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly", "is.gd", "cutt.ly", "rb.gy"
}

BRAND_DOMAINS = {
    "instagram": "instagram.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "steam": "steampowered.com",
    "discord": "discord.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
    "yemeksepeti": "yemeksepeti.com",
    "garanti": "garantibbva.com.tr",
    "garantibbva": "garantibbva.com.tr",
    "amazon.com.tr": "amazon.com.tr",
}

DANGEROUS_EXTS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".hta", ".lnk", ".iso", ".img"}
OFFICE_MACRO_EXTS = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".gz", ".bz2", ".xz"}

SOCIAL_WORDS = [
    "acil", "hemen", "kapat", "kapatıl", "askıya", "suspend", "urgent",
    "doğrula", "verify", "confirm", "security", "güvenlik",
    "şifre", "password", "login", "sign in", "reset", "re-auth", "2fa",
    "ödül", "gift", "kazandın", "voucher", "prize",
    "invoice", "fatura", "ödeme", "payment", "bank", "banka",
]

CRED_HARVEST_PATTERNS = [
    "login", "sign in", "verify", "confirm", "reset password", "şifre sıfırla",
    "account", "hesab", "credentials", "kimlik bilgileri"
]

CATEGORY_CAPS = {
    "SENDER": 45,
    "AUTH": 35,
    "RECEIVED": 18,
    "LINKS": 70,
    "CONTENT": 18,
    "ATTACHMENTS": 70,
    "BEHAVIOR": 15,
    "COMBO": 30,
    "ALLOWLIST": 20,
}

def _get_header(headers, name):
    name_low = name.lower()
    for h in headers:
        if h.get("name", "").lower() == name_low:
            return h.get("value", "")
    return ""

def _get_headers_all(headers, name):
    name_low = name.lower()
    out = []
    for h in headers:
        if h.get("name", "").lower() == name_low:
            out.append(h.get("value", ""))
    return out

def _email_name_addr(value):
    name, addr = parseaddr(value or "")
    return (name or "").strip(), (addr or "").strip().lower()

def _domain_from_email(addr):
    if "@" not in (addr or ""):
        return None
    return addr.split("@", 1)[1].lower()

def _message_id_domain(message_id):
    if not message_id:
        return None
    m = re.search(r"@([^>\s]+)", message_id)
    return m.group(1).lower() if m else None

def _normalize_domain(d):
    d = (d or "").strip().lower()
    if d.startswith("www."):
        d = d[4:]
    return d

def _normalize_email(addr):
    return (addr or "").strip().lower()

def _org_domain(domain: str | None) -> str | None:
    domain = _normalize_domain(domain)
    if not domain:
        return None
    parts = domain.split(".")
    if len(parts) < 2:
        return domain
    two_level = {"co.uk", "org.uk", "ac.uk", "com.au", "com.br", "co.jp", "com.tr"}
    last2 = ".".join(parts[-2:])
    if last2 in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def _base_label(domain):
    domain = _normalize_domain(domain)
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return domain

def _similar(a, b):
    a = re.sub(r"[^a-z0-9]", "", (a or "").lower())
    b = re.sub(r"[^a-z0-9]", "", (b or "").lower())
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()

def _extract_visible_domain(text):
    if not text:
        return None
    t = text.strip()
    if "http://" in t or "https://" in t:
        try:
            return _normalize_domain(urlparse(t).hostname)
        except Exception:
            return None
    m = DOMAIN_RE.search(t)
    if m:
        return _normalize_domain(m.group(0))
    return None

def _is_same_or_subdomain(domain: str, official: str) -> bool:
    domain = _normalize_domain(domain)
    official = _normalize_domain(official)
    return domain == official or domain.endswith("." + official)

def _extract_text_and_links(payload):
    parts = []

    def walk(p):
        if "parts" in p:
            for sp in p["parts"]:
                walk(sp)
        else:
            mime = p.get("mimeType", "")
            body = p.get("body", {}).get("data")
            if body:
                try:
                    raw = base64.urlsafe_b64decode(body.encode("utf-8")).decode("utf-8", errors="ignore")
                except Exception:
                    raw = ""
                parts.append((mime, raw))

    walk(payload or {})

    text = ""
    links_map = {}
    plain_links = set()

    for mime, raw in parts:
        if "text/html" in mime:
            soup = BeautifulSoup(raw, "html.parser")
            text += "\n" + soup.get_text(" ", strip=True)

            for a in soup.find_all("a"):
                href = (a.get("href") or "").strip()
                visible = a.get_text(" ", strip=True) or ""
                if href.startswith("http"):
                    if href not in links_map:
                        links_map[href] = {"href": href, "visible": set()}
                    if visible:
                        links_map[href]["visible"].add(visible)

        elif "text/plain" in mime:
            text += "\n" + raw

        for u in URL_RE.findall(raw):
            plain_links.add(u)

    for u in plain_links:
        if u not in links_map:
            links_map[u] = {"href": u, "visible": set()}

    links = []
    for href, item in links_map.items():
        host = _normalize_domain(urlparse(href).hostname)
        visible_domains = set()
        for v in item["visible"]:
            d = _extract_visible_domain(v)
            if d:
                visible_domains.add(d)

        links.append({
            "href": href,
            "domain": host,
            "visible_texts": list(item["visible"])[:3],
            "visible_domains": list(visible_domains)[:3],
        })

    return text.strip(), links

def _extract_attachments(payload):
    atts = []

    def walk(p):
        filename = (p.get("filename") or "").strip()
        mime = p.get("mimeType", "")
        body = p.get("body", {}) or {}
        attachment_id = body.get("attachmentId")
        size = body.get("size", 0)

        if filename or attachment_id:
            atts.append({
                "filename": filename,
                "mime": mime,
                "size": size,
                "has_attachment_id": bool(attachment_id),
            })

        for sp in p.get("parts", []) or []:
            walk(sp)

    walk(payload or {})
    return atts

def _ext_of(name):
    name = (name or "").lower().strip()
    if "." not in name:
        return ""
    return "." + name.split(".")[-1]

def _has_double_extension(name):
    name = (name or "").lower()
    parts = name.split(".")
    return len(parts) >= 3

def _split_recipients(header_value):
    addrs = [addr.lower() for _, addr in getaddresses([header_value or ""]) if addr]
    return list(dict.fromkeys(addrs))

def _find_private_ips_in_received(received_lines):
    priv = []
    for line in received_lines or []:
        for ip in IP_RE.findall(line):
            try:
                if ipaddress.ip_address(ip).is_private:
                    priv.append(ip)
            except ValueError:
                pass
    return list(dict.fromkeys(priv))

def _parse_auth_results(auth_res):
    out = {}
    if not auth_res:
        return out

    low = auth_res.lower()

    for key in ["spf", "dkim", "dmarc"]:
        m = re.search(rf"{key}=(pass|fail|softfail|neutral|none|temperror|permerror)", low)
        if m:
            out[key] = m.group(1)

    m_from = re.search(r"header\.from=([a-z0-9\.\-]+)", low)
    if m_from:
        out["header_from"] = m_from.group(1)

    m_mailfrom = re.search(r"smtp\.mailfrom=([^;\s]+)", low)
    if m_mailfrom:
        mailfrom = m_mailfrom.group(1)
        if "@" in mailfrom:
            out["smtp_mailfrom_domain"] = mailfrom.split("@", 1)[1]
        else:
            out["smtp_mailfrom_domain"] = mailfrom

    m_d = re.search(r"header\.d=([a-z0-9\.\-]+)", low)
    if m_d:
        out["dkim_d"] = m_d.group(1)

    return out

def _url_obfuscation_score(url):
    u = (url or "").lower()
    score = 0
    if len(u) > 120:
        score += 8
    if "@" in u:
        score += 18
    if "xn--" in u:
        score += 25
    if re.search(r"https?://\d+\.\d+\.\d+\.\d+", u):
        score += 30
    if u.count("%") >= 6:
        score += 8
    parsed = urlparse(u)
    host = (parsed.hostname or "")
    if host.count(".") >= 3:
        score += 10
    if any(x in u for x in ["redirect", "continue", "next", "return", "url="]):
        score += 10
    if any(x in u for x in ["login", "verify", "reset", "password"]):
        score += 8
    return min(score, 30)

def _load_allowlist():
    path = "allowlist.json"
    if not os.path.exists(path):
        return {"trusted_domains": [], "trusted_sender_addresses": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            data.setdefault("trusted_domains", [])
            data.setdefault("trusted_sender_addresses", [])
            return data
    except Exception:
        return {"trusted_domains": [], "trusted_sender_addresses": []}

def _is_trusted_domain(domain: str, trusted_domains: list[str]) -> bool:
    domain = _normalize_domain(domain)
    for td in trusted_domains:
        td = _normalize_domain(td)
        if domain == td or domain.endswith("." + td):
            return True
    return False

def _is_trusted_sender(addr: str, trusted_sender_addresses: list[str]) -> bool:
    addr = _normalize_email(addr)
    trusted = {_normalize_email(x) for x in trusted_sender_addresses}
    return addr in trusted

def _has_strong_negative_signal(findings):
    ids = {f.get("id") for f in findings}
    strong_ids = {
        "THREAT_INTEL_MATCH",
        "LINK_TEXT_MISMATCH",
        "RISKY_ATTACHMENTS",
        "LOOKALIKE_DOMAIN"
    }
    return bool(ids & strong_ids)

def _add(findings, category, fid, score, title, evidence=None):
    findings.append({
        "category": category,
        "id": fid,
        "score": int(score),
        "title": title,
        "evidence": evidence or {},
    })

def rule_sender_identity(meta, findings):
    from_domain = meta.get("from_domain")
    reply_domain = meta.get("reply_to_domain")
    return_path_domain = meta.get("return_path_domain")
    msgid_domain = meta.get("message_id_domain")
    from_name = (meta.get("from_name") or "")
    from_addr = (meta.get("from_addr") or "")
    subject = (meta.get("subject") or "")
    text = (meta.get("text") or "")

    if from_domain and reply_domain and _org_domain(from_domain) != _org_domain(reply_domain):
        _add(findings, "SENDER", "REPLY_TO_MISMATCH", 20,
             "Reply-To domain, From domain ile farklı",
             {"from_domain": from_domain, "reply_to_domain": reply_domain})

    if from_domain and return_path_domain and _org_domain(from_domain) != _org_domain(return_path_domain):
        _add(findings, "SENDER", "RETURN_PATH_MISMATCH", 10,
             "Return-Path domain, From domain ile farklı",
             {"from_domain": from_domain, "return_path_domain": return_path_domain})

    if from_domain and msgid_domain and _org_domain(from_domain) not in (_org_domain(msgid_domain) or ""):
        _add(findings, "SENDER", "MESSAGE_ID_MISMATCH", 3,
             "Message-ID domain, From domain ile tutarsız",
             {"from_domain": from_domain, "message_id_domain": msgid_domain})

    if from_domain in FREE_EMAIL_DOMAINS:
        low_name = from_name.lower()
        for brand in BRAND_DOMAINS.keys():
            if brand in low_name:
                _add(findings, "SENDER", "BRAND_ON_FREE_EMAIL", 25,
                     "Gönderen adı marka gibi ama domain free email",
                     {"from_name": from_name, "from_domain": from_domain})
                break
    

   
    low_blob = (subject + " " + text).lower()
    if from_domain in FREE_EMAIL_DOMAINS:
        brand_hit = any(brand in low_blob for brand in BRAND_DOMAINS.keys())
        security_hit = any(word in low_blob for word in [
            "security", "login", "sign in", "verify", "confirm",
            "password", "reset", "hesap", "güvenlik", "şifre", "doğrula"
        ])
        if brand_hit and security_hit:
            _add(findings, "SENDER", "PERSONAL_FREE_EMAIL_BRAND_CONTEXT", 18,
                 "Kişisel/free email adresinden marka ve güvenlik temalı mesaj geliyor",
                 {"from_domain": from_domain})





    low_blob = (subject + " " + text).lower()
    for brand, official in BRAND_DOMAINS.items():
        if brand in low_blob and from_domain:
            if _org_domain(from_domain) != _org_domain(official):
                _add(findings, "SENDER", "BRAND_MENTION_DOMAIN_MISMATCH", 6,
                     "Mail marka içeriyor ama gönderen domain resmi domain ile uyuşmuyor",
                     {"brand": brand, "official": official, "from_domain": from_domain})
            break

    if from_addr and "@" in from_addr:
        local = from_addr.split("@", 1)[0]
        if len(local) >= 20 and sum(c.isdigit() for c in local) >= 6:
            _add(findings, "SENDER", "WEIRD_SENDER_LOCALPART", 4,
                 "Gönderen email local-part çok karmaşık görünüyor",
                 {"local_part": local})

def rule_authentication(meta, findings):
    auth = meta.get("auth_results", {})
    from_domain = meta.get("from_domain")
    if not auth:
        _add(findings, "AUTH", "AUTH_UNKNOWN", 2,
             "SPF/DKIM/DMARC sonucu bulunamadı")
        return

    for key, score in [("spf", 20), ("dkim", 20), ("dmarc", 15)]:
        val = auth.get(key)
        if val in {"fail", "softfail", "permerror", "temperror"}:
            _add(findings, "AUTH", f"{key.upper()}_FAIL", score,
                 f"{key.upper()} başarısız görünüyor ({val})",
                 {key: val})

    dkim_d = auth.get("dkim_d")
    if from_domain and auth.get("dkim") == "pass" and dkim_d:
        if _org_domain(dkim_d) != _org_domain(from_domain):
            _add(findings, "AUTH", "DKIM_ALIGNMENT_MISMATCH", 4,
                 "DKIM pass ama d= domain From ile uyumlu değil",
                 {"dkim_d": dkim_d, "from_domain": from_domain})

    mailfrom_dom = auth.get("smtp_mailfrom_domain")
    if from_domain and auth.get("spf") in {"pass", "neutral"} and mailfrom_dom:
        if _org_domain(mailfrom_dom) != _org_domain(from_domain):
            _add(findings, "AUTH", "SPF_ALIGNMENT_MISMATCH", 4,
                 "SPF sonucu var ama mailfrom domain From ile uyumlu değil",
                 {"smtp_mailfrom_domain": mailfrom_dom, "from_domain": from_domain})

def rule_received_chain(meta, findings):
    hops = meta.get("received_hops", 0)
    received_lines = meta.get("received_lines", [])
    priv_ips = meta.get("private_ips_in_received", [])

    if hops >= 8:
        _add(findings, "RECEIVED", "MANY_RECEIVED_HOPS", 5,
             "Received hop sayısı yüksek", {"received_hops": hops})

    if priv_ips:
        _add(findings, "RECEIVED", "PRIVATE_IP_IN_RECEIVED", 4,
             "Received zincirinde private IP görüldü", {"private_ips": priv_ips[:6]})

    blob = " ".join(received_lines).lower()
    if any(x in blob for x in [" unknown ", "localhost", "127.0.0.1"]):
        _add(findings, "RECEIVED", "SUSPICIOUS_RECEIVED_TEXT", 6,
             "Received zincirinde 'unknown/localhost' benzeri ifade")

def rule_links(meta, findings):
    links = meta.get("links", [])
    if not links:
        return

    mismatches = []
    for l in links:
        href_dom = l.get("domain")
        for vdom in l.get("visible_domains", []):
            if href_dom and vdom and _normalize_domain(href_dom) != _normalize_domain(vdom):
                mismatches.append({
                    "visible_domain": vdom,
                    "href_domain": href_dom,
                    "href": l.get("href")
                })

    if mismatches:
        _add(findings, "LINKS", "LINK_TEXT_MISMATCH", 70,
             "Link yazısı ile gerçek link domain’i farklı",
             {"examples": mismatches[:3]})

    worst = 0
    worst_href = None
    for l in links[:30]:
        href = l.get("href") or ""
        s = _url_obfuscation_score(href)
        if s > worst:
            worst = s
            worst_href = href

        dom = _normalize_domain(urlparse(href).hostname)
        if dom in SHORTENER_DOMAINS:
            _add(findings, "LINKS", "URL_SHORTENER", 10,
                 "Link kısaltıcı kullanıyor", {"domain": dom, "href": href})

    if worst >= 18:
        _add(findings, "LINKS", "SUSPICIOUS_URL_PATTERN", min(30, worst),
             "URL pattern şüpheli",
             {"worst_score": worst, "example": worst_href})

    content = (meta.get("subject", "") + " " + meta.get("text", "")).lower()
    mentioned_targets = []
    for brand, dom in BRAND_DOMAINS.items():
        if brand in content:
            mentioned_targets.append(dom)

    for l in links:
        for vdom in l.get("visible_domains", []):
            if vdom and vdom not in mentioned_targets:
                mentioned_targets.append(vdom)

    lookalikes = []
    for l in links:
        d = l.get("domain")
        if not d:
            continue

        skip_current = False
        for target in mentioned_targets[:10]:
            if _is_same_or_subdomain(d, target):
                skip_current = True
                break
        if skip_current:
            continue

        if "xn--" in d:
            lookalikes.append({
                "type": "punycode",
                "domain": d,
                "href": l.get("href")
            })

        for target in mentioned_targets[:10]:
            if not target:
                continue
            if _is_same_or_subdomain(d, target):
                continue

            sim = _similar(_base_label(d), _base_label(target))
            if sim >= 0.80:
                lookalikes.append({
                    "type": "similarity",
                    "domain": d,
                    "target": target,
                    "similarity": round(sim, 3),
                    "href": l.get("href"),
                })

    if lookalikes:
        _add(findings, "LINKS", "LOOKALIKE_DOMAIN", 30,
             "Markaya benzeyen (lookalike) domain tespit edildi",
             {"examples": lookalikes[:4]})

def rule_content(meta, findings):
    subject = (meta.get("subject") or "")
    text = (meta.get("text") or "")
    low = (subject + " " + text).lower()

    triggers = [w for w in SOCIAL_WORDS if w in low]
    if triggers:
        _add(findings, "CONTENT", "SOCIAL_ENGINEERING_LANGUAGE", 8,
             "Sosyal mühendislik dili",
             {"words": triggers[:12]})

    cred = [p for p in CRED_HARVEST_PATTERNS if p in low]
    if cred:
        _add(findings, "CONTENT", "CRED_HARVEST_HINT", 10,
             "Credential toplama kalıpları",
             {"patterns": cred[:10]})

    if subject.strip() == "" or len(subject.strip()) <= 3:
        _add(findings, "CONTENT", "EMPTY_OR_SHORT_SUBJECT", 4,
             "Konu boş veya çok kısa")

def rule_attachments(meta, findings):
    atts = meta.get("attachments", [])
    if not atts:
        return

    risky = []
    score = 0
    text_low = (meta.get("text") or "").lower()

    for a in atts:
        fn = a.get("filename") or ""
        ext = _ext_of(fn)

        if ext in DANGEROUS_EXTS:
            score += 60
            risky.append({"filename": fn, "reason": "dangerous_ext"})
        elif ext in OFFICE_MACRO_EXTS:
            score += 40
            risky.append({"filename": fn, "reason": "office_macro_ext"})
        elif ext in ARCHIVE_EXTS:
            score += 12
            risky.append({"filename": fn, "reason": "archive_ext"})

        if _has_double_extension(fn) and ext in DANGEROUS_EXTS:
            score += 20
            risky.append({"filename": fn, "reason": "double_extension"})

        if ext in {".zip", ".rar", ".7z"} and any(w in text_low for w in ["password", "şifre", "parola"]):
            score += 8
            risky.append({"filename": fn, "reason": "archive_with_password_words"})

    if risky:
        _add(findings, "ATTACHMENTS", "RISKY_ATTACHMENTS", min(70, score),
             "Şüpheli ek dosya(lar) tespit edildi",
             {"attachments": risky[:6]})

def rule_behavior(meta, findings):
    to_addrs = meta.get("to_addrs", [])
    cc_addrs = meta.get("cc_addrs", [])
    bcc_addrs = meta.get("bcc_addrs", [])
    total = len(to_addrs) + len(cc_addrs) + len(bcc_addrs)

    if total >= 8:
        _add(findings, "BEHAVIOR", "MASS_RECIPIENTS", 6,
             "Birden fazla alıcı (mass-mail) sinyali",
             {"to": len(to_addrs), "cc": len(cc_addrs), "bcc": len(bcc_addrs)})

    if bcc_addrs:
        _add(findings, "BEHAVIOR", "BCC_PRESENT", 8,
             "Bcc kullanımı görüldü", {"bcc_count": len(bcc_addrs)})

def apply_combo_rules(meta, findings):
    ids = {f["id"] for f in findings}
    low_blob = (meta.get("subject", "") + " " + meta.get("text", "")).lower()

    if "REPLY_TO_MISMATCH" in ids and "SOCIAL_ENGINEERING_LANGUAGE" in ids:
        _add(findings, "COMBO", "COMBO_REPLYTO_SOCIAL", 10,
             "Reply-To uyumsuzluğu ve sosyal mühendislik dili birlikte görüldü")

    if "BRAND_ON_FREE_EMAIL" in ids and "LINK_TEXT_MISMATCH" in ids:
        _add(findings, "COMBO", "COMBO_BRAND_FREE_LINK", 20,
             "Marka taklidi + free email + link uyumsuzluğu birlikte görüldü")

    if "LOOKALIKE_DOMAIN" in ids:
        for brand in BRAND_DOMAINS.keys():
            if brand in low_blob:
                _add(findings, "COMBO", "COMBO_LOOKALIKE_BRAND", 20,
                     "Lookalike domain ile marka içeriği birlikte görüldü")
                break

    auth_fail = any(x in ids for x in ["SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"])
    sender_mismatch = any(x in ids for x in ["REPLY_TO_MISMATCH", "RETURN_PATH_MISMATCH", "MESSAGE_ID_MISMATCH"])
    if auth_fail and sender_mismatch:
        _add(findings, "COMBO", "COMBO_AUTH_AND_SENDER", 15,
             "Auth başarısızlığı ve gönderen uyumsuzluğu birlikte görüldü")

    if "RISKY_ATTACHMENTS" in ids and "SOCIAL_ENGINEERING_LANGUAGE" in ids:
        _add(findings, "COMBO", "COMBO_ATTACH_SOCIAL", 10,
             "Şüpheli ek dosya ve sosyal mühendislik dili birlikte görüldü")

def apply_allowlist_adjustment(meta, findings):
    allowlist = _load_allowlist()
    trusted_domains = allowlist.get("trusted_domains", [])
    trusted_sender_addresses = allowlist.get("trusted_sender_addresses", [])

    from_domain = meta.get("from_domain")
    from_addr = meta.get("from_addr")

    if not from_domain and not from_addr:
        return

    is_trusted = False
    reason = None

    if from_addr and _is_trusted_sender(from_addr, trusted_sender_addresses):
        is_trusted = True
        reason = {"from_addr": from_addr, "match_type": "trusted_sender_address"}

    elif from_domain and _is_trusted_domain(from_domain, trusted_domains):
        is_trusted = True
        reason = {"from_domain": from_domain, "match_type": "trusted_domain"}

    if not is_trusted:
        return

    if _has_strong_negative_signal(findings):
        return

    findings.append({
        "category": "ALLOWLIST",
        "id": "TRUSTED_ALLOWLIST_MATCH",
        "score": -15,
        "title": "Gönderen allowlist içinde, risk azaltıldı",
        "evidence": reason or {}
    })

def _score_with_caps(findings):
    cat_sum = {}
    for f in findings:
        cat = f["category"]
        cat_sum[cat] = cat_sum.get(cat, 0) + int(f["score"])

    capped = {}
    total = 0
    for cat, s in cat_sum.items():
        cap = CATEGORY_CAPS.get(cat, 100)

        # Negatif allowlist puanı da geçerli olsun
        if cat == "ALLOWLIST":
            capped_val = max(-cap, s)
        else:
            capped_val = min(cap, s)

        capped[cat] = capped_val
        total += capped_val

    return max(0, min(100, total)), capped

def _level(risk):
    if risk >= 70:
        return "HIGH"
    if risk >= 30:
        return "MEDIUM"
    return "LOW"

def analyze_message(msg: dict):
    headers = msg.get("payload", {}).get("headers", [])

    subject = _get_header(headers, "Subject")
    from_h = _get_header(headers, "From")
    reply_to_h = _get_header(headers, "Reply-To")
    return_path_h = _get_header(headers, "Return-Path")
    message_id_h = _get_header(headers, "Message-ID")
    auth_res_h = _get_header(headers, "Authentication-Results")

    received_all = _get_headers_all(headers, "Received")
    to_h = _get_header(headers, "To")
    cc_h = _get_header(headers, "Cc")
    bcc_h = _get_header(headers, "Bcc")

    from_name, from_addr = _email_name_addr(from_h)
    _, reply_addr = _email_name_addr(reply_to_h)
    _, ret_addr = _email_name_addr(return_path_h)

    text, links = _extract_text_and_links(msg.get("payload", {}))
    attachments = _extract_attachments(msg.get("payload", {}))

    meta = {
        "gmail_message_id": msg.get("id"),
        "thread_id": msg.get("threadId"),
        "internal_date": msg.get("internalDate"),
        "snippet": msg.get("snippet", ""),
        "subject": subject,
        "from_raw": from_h,
        "from_name": from_name,
        "from_addr": from_addr,
        "from_domain": _domain_from_email(from_addr),
        "reply_to_raw": reply_to_h,
        "reply_to_addr": reply_addr,
        "reply_to_domain": _domain_from_email(reply_addr),
        "return_path_raw": return_path_h,
        "return_path_addr": ret_addr,
        "return_path_domain": _domain_from_email(ret_addr),
        "message_id": message_id_h,
        "message_id_domain": _message_id_domain(message_id_h),
        "auth_results_raw": auth_res_h,
        "auth_results": _parse_auth_results(auth_res_h),
        "received_hops": len(received_all),
        "received_lines": received_all,
        "private_ips_in_received": _find_private_ips_in_received(received_all),
        "to_addrs": _split_recipients(to_h),
        "cc_addrs": _split_recipients(cc_h),
        "bcc_addrs": _split_recipients(bcc_h),
        "links": links,
        "attachments": attachments,
        "text": (text or "")[:8000],
    }

    findings = []
    rule_sender_identity(meta, findings)
    rule_authentication(meta, findings)
    rule_received_chain(meta, findings)
    rule_links(meta, findings)
    rule_content(meta, findings)
    rule_attachments(meta, findings)
    rule_behavior(meta, findings)
    apply_combo_rules(meta, findings)
    apply_allowlist_adjustment(meta, findings)

    risk, category_breakdown = _score_with_caps(findings)
    level = _level(risk)

    reasons = [f["title"] for f in sorted(findings, key=lambda x: x["score"], reverse=True)[:5]]

    return {
        "risk": risk,
        "level": level,
        "reasons": reasons,
        "category_breakdown": category_breakdown,
        "from": {"name": from_name, "addr": from_addr, "domain": meta["from_domain"]},
        "reply_to": {"addr": reply_addr, "domain": meta["reply_to_domain"]},
        "return_path": {"addr": ret_addr, "domain": meta["return_path_domain"]},
        "auth": meta["auth_results"],
        "received_hops": meta["received_hops"],
        "links": links[:12],
        "attachments": attachments[:10],
        "findings": findings,
        "meta": {
            "gmail_message_id": meta["gmail_message_id"],
            "thread_id": meta["thread_id"],
            "internal_date": meta["internal_date"],
            "subject": subject,
            "snippet": meta["snippet"],
            "text_excerpt": meta["text"][:2500],
        }
    }