"""Heuristic phishing email detector for `.eml` files."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from engines.alert_schema import Alert, AlertSeverity, AlertSource, Evidence, Indicator
from engines.mitre_mapping import techniques_for_signals


PHISHING_THRESHOLD = 20

AUTH_FAILURE_RE = re.compile(
    r"\b(spf|dkim|dmarc|compauth)\s*=\s*(fail|softfail|temperror|permerror|none)\b",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>'\")]+", re.IGNORECASE)
RAW_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

BRAND_TERMS = {
    "amazon",
    "apple",
    "bradesco",
    "dhl",
    "fedex",
    "gmail",
    "google",
    "icloud",
    "livelo",
    "microsoft",
    "netflix",
    "opensea",
    "outlook",
    "paypal",
    "ups",
}
FREE_EMAIL_DOMAINS = {
    "aol.com",
    "gmail.com",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "outlook.com",
    "proton.me",
    "yahoo.com",
}
RISKY_ATTACHMENT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".exe",
    ".hta",
    ".iso",
    ".js",
    ".lnk",
    ".msi",
    ".scr",
    ".vbs",
    ".zip",
}
URGENCY_TERMS = {
    "account",
    "confirm",
    "expire",
    "expiring",
    "immediate",
    "invoice",
    "liberacao",
    "liberação",
    "login",
    "offer",
    "password",
    "refund",
    "saldo",
    "signin",
    "suspended",
    "transaction",
    "unusual",
    "verify",
}
RISKY_MARKET_TERMS = {
    "bank drop",
    "bankdrop",
    "cards",
    "cpanel",
    "fresh rdp",
    "leads",
    "mailer",
    "rdp",
    "shells",
    "smtp",
    "web-mails",
    "whm",
}
CRYPTO_TERMS = {"airdrop", "btc", "crypto", "ether", "eth", "nft", "opensea", "token", "wallet"}


@dataclass(frozen=True)
class HeuristicResult:
    triggered: bool
    weight: float
    reason: str
    indicator: str | None = None
    signal: str = "phishing_link"


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data.strip())

    def text(self) -> str:
        return " ".join(self.parts)


def analyze_email(path: str | Path) -> Alert:
    """Analyze one `.eml` file and return the shared Alert contract."""

    email_path = Path(path)
    return analyze_email_content(email_path.read_bytes(), label=str(email_path))


def analyze_email_content(raw_bytes: bytes, label: str = "live-email.eml") -> Alert:
    """Analyze raw `.eml` bytes from a pasted message or uploaded file."""

    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    return _score_message(message, label)


def _score_message(message: Message | EmailMessage, label: str) -> Alert:
    """Score an already-parsed email message and return the shared Alert contract."""

    parsed = _ParsedEmail.from_message(message)

    heuristic_results = [
        _auth_failures(parsed),
        _brand_display_name_mismatch(parsed),
        _return_path_mismatch(parsed),
        _reply_to_mismatch(parsed),
        _risky_attachments(parsed),
        _urgency_language(parsed),
        _suspicious_links(parsed),
        _free_provider_or_subject_brand_mismatch(parsed),
        _relay_obfuscation(parsed),
        _risky_market_or_crypto_language(parsed),
    ]
    triggered = [result for result in heuristic_results if result.triggered]
    score = min(100, int(round(sum(result.weight for result in triggered))))
    severity = _severity_for_score(score)
    classification = "PHISHING" if score >= PHISHING_THRESHOLD else "SAFE"

    evidence = [
        Evidence(
            name=_slugify(result.reason),
            score=int(round(result.weight)),
            description=result.reason,
            location=result.indicator or "email",
        )
        for result in triggered
    ]
    indicators = _indicators_for(parsed, triggered)

    return Alert(
        source=AlertSource.PHISHING_EMAIL,
        title=f"{classification}: {parsed.subject or label}",
        severity=severity,
        score=score,
        summary=_summary_for(classification, score, triggered),
        recommended_actions=_recommended_actions_for(classification),
        mitre_techniques=techniques_for_signals([result.signal for result in triggered]),
        indicators=indicators,
        evidence=evidence,
        raw_event={
            "classification": classification,
            "path": label,
            "subject": parsed.subject,
            "from": parsed.from_header,
            "return_path": parsed.return_path,
            "reply_to": parsed.reply_to,
            "links": parsed.links,
            "attachments": parsed.attachments,
            "threshold": PHISHING_THRESHOLD,
        },
    )


@dataclass(frozen=True)
class _ParsedEmail:
    subject: str
    from_header: str
    from_name: str
    from_email: str
    from_domain: str
    return_path: str
    return_path_domain: str
    reply_to: str
    reply_to_domain: str
    auth_results: str
    received_spf: str
    body_text: str
    links: list[str]
    link_hosts: list[str]
    attachments: list[str]

    @classmethod
    def from_message(cls, message: Message | EmailMessage) -> "_ParsedEmail":
        from_header = _header(message, "From")
        from_name, from_email = _first_address(from_header)
        return_path = _header(message, "Return-Path").strip("<>")
        _, return_email = _first_address(return_path)
        reply_to = _header(message, "Reply-To")
        _, reply_email = _first_address(reply_to)
        body_text = _extract_body_text(message)
        links = _extract_links(message, body_text)

        return cls(
            subject=_header(message, "Subject"),
            from_header=from_header,
            from_name=from_name,
            from_email=from_email,
            from_domain=_domain_from_email(from_email),
            return_path=return_path,
            return_path_domain=_domain_from_email(return_email or return_path),
            reply_to=reply_to,
            reply_to_domain=_domain_from_email(reply_email),
            auth_results=" ".join(message.get_all("Authentication-Results", [])),
            received_spf=" ".join(message.get_all("Received-SPF", [])),
            body_text=body_text,
            links=links,
            link_hosts=[_host_from_url(link) for link in links],
            attachments=_attachments(message),
        )


def _auth_failures(parsed: _ParsedEmail) -> HeuristicResult:
    auth_text = f"{parsed.auth_results} {parsed.received_spf}"
    matches = [f"{name}={value}" for name, value in AUTH_FAILURE_RE.findall(auth_text)]
    return HeuristicResult(
        bool(matches),
        16,
        f"Authentication checks contain weak or failed results: {', '.join(matches[:4])}",
        indicator=matches[0] if matches else None,
        signal="phishing_link",
    )


def _brand_display_name_mismatch(parsed: _ParsedEmail) -> HeuristicResult:
    brands = _brands_in(parsed.from_name)
    mismatches = [brand for brand in brands if brand not in parsed.from_domain]
    return HeuristicResult(
        bool(mismatches),
        18,
        f"Display name references {', '.join(mismatches)} but sender domain is {parsed.from_domain}",
        indicator=parsed.from_header,
        signal="phishing_link",
    )


def _return_path_mismatch(parsed: _ParsedEmail) -> HeuristicResult:
    mismatch = bool(
        parsed.return_path_domain
        and parsed.from_domain
        and _registered_domain(parsed.return_path_domain)
        != _registered_domain(parsed.from_domain)
    )
    return HeuristicResult(
        mismatch,
        12,
        f"Return-Path domain {parsed.return_path_domain} differs from From domain {parsed.from_domain}",
        indicator=parsed.return_path,
        signal="phishing_link",
    )


def _reply_to_mismatch(parsed: _ParsedEmail) -> HeuristicResult:
    mismatch = bool(
        parsed.reply_to_domain
        and parsed.from_domain
        and _registered_domain(parsed.reply_to_domain) != _registered_domain(parsed.from_domain)
    )
    return HeuristicResult(
        mismatch,
        12,
        f"Reply-To domain {parsed.reply_to_domain} differs from From domain {parsed.from_domain}",
        indicator=parsed.reply_to,
        signal="phishing_link",
    )


def _risky_attachments(parsed: _ParsedEmail) -> HeuristicResult:
    risky = [
        name
        for name in parsed.attachments
        if Path(name).suffix.lower() in RISKY_ATTACHMENT_EXTENSIONS
    ]
    return HeuristicResult(
        bool(risky),
        22,
        f"Message includes risky attachment type: {', '.join(risky[:3])}",
        indicator=risky[0] if risky else None,
        signal="phishing_attachment",
    )


def _urgency_language(parsed: _ParsedEmail) -> HeuristicResult:
    text = _normalize(f"{parsed.subject} {parsed.body_text}")
    hits = sorted(term for term in URGENCY_TERMS if term in text)
    return HeuristicResult(
        len(hits) >= 2,
        10,
        f"Subject/body contain social-engineering terms: {', '.join(hits[:5])}",
        indicator=", ".join(hits[:5]) if hits else None,
        signal="user_execution",
    )


def _suspicious_links(parsed: _ParsedEmail) -> HeuristicResult:
    raw_ip_hosts = [host for host in parsed.link_hosts if _is_ip_address(host)]
    many_links = len(parsed.links) >= 8
    external_hosts = {
        _registered_domain(host)
        for host in parsed.link_hosts
        if host and _registered_domain(host) != _registered_domain(parsed.from_domain)
    }

    triggered = bool(raw_ip_hosts or many_links or len(external_hosts) >= 3)
    details = []
    if raw_ip_hosts:
        details.append(f"raw IP URL host {raw_ip_hosts[0]}")
    if many_links:
        details.append(f"{len(parsed.links)} links")
    if len(external_hosts) >= 3:
        details.append(f"{len(external_hosts)} external link domains")

    return HeuristicResult(
        triggered,
        14,
        f"Suspicious link pattern detected: {', '.join(details)}",
        indicator=parsed.links[0] if parsed.links else None,
        signal="phishing_link",
    )


def _free_provider_or_subject_brand_mismatch(parsed: _ParsedEmail) -> HeuristicResult:
    subject_brands = _brands_in(parsed.subject)
    from_domain = _registered_domain(parsed.from_domain)
    is_free_provider = from_domain in FREE_EMAIL_DOMAINS
    subject_mismatch = [brand for brand in subject_brands if brand not in parsed.from_domain]
    triggered = bool((is_free_provider and (subject_brands or _crypto_terms(parsed))) or subject_mismatch)

    reasons = []
    if is_free_provider:
        reasons.append(f"free sender provider {from_domain}")
    if subject_mismatch:
        reasons.append(f"subject brand mismatch: {', '.join(subject_mismatch)}")
    if _crypto_terms(parsed):
        reasons.append("crypto/transaction lure language")

    return HeuristicResult(
        triggered,
        12,
        f"Sender identity mismatch: {'; '.join(reasons)}",
        indicator=parsed.from_header,
        signal="phishing_link",
    )


def _relay_obfuscation(parsed: _ParsedEmail) -> HeuristicResult:
    return_domain = parsed.return_path_domain
    looks_like_host = bool(return_domain and "." not in return_domain)
    bounce_relay = bool(return_domain and re.search(r"\b(bounce|bounces|relay|ubuntu|localhost)\b", return_domain))
    triggered = looks_like_host or bounce_relay

    return HeuristicResult(
        triggered,
        8,
        f"Return-Path appears to use relay or host obfuscation: {return_domain}",
        indicator=parsed.return_path,
        signal="phishing_link",
    )


def _risky_market_or_crypto_language(parsed: _ParsedEmail) -> HeuristicResult:
    text = _normalize(f"{parsed.subject} {parsed.body_text}")
    risky_hits = sorted(term for term in RISKY_MARKET_TERMS if term in text)
    crypto_hits = sorted(term for term in CRYPTO_TERMS if term in text)
    triggered = bool(risky_hits or len(crypto_hits) >= 2)
    hits = risky_hits[:5] or crypto_hits[:5]

    return HeuristicResult(
        triggered,
        20,
        f"Message contains risky marketplace or crypto lure terms: {', '.join(hits)}",
        indicator=", ".join(hits) if hits else None,
        signal="user_execution",
    )


def _summary_for(classification: str, score: int, triggered: list[HeuristicResult]) -> str:
    if classification == "SAFE":
        return f"Email scored {score}/100, below the phishing threshold of {PHISHING_THRESHOLD}."

    top_reasons = "; ".join(result.reason for result in triggered[:3])
    return f"Email scored {score}/100 and matched phishing heuristics: {top_reasons}."


def _recommended_actions_for(classification: str) -> list[str]:
    if classification == "SAFE":
        return ["Allow message", "No analyst action required unless new evidence appears"]

    return [
        "Quarantine the message",
        "Extract and block malicious indicators",
        "Review recipient mailbox activity for follow-on compromise",
    ]


def _severity_for_score(score: int) -> AlertSeverity:
    if score >= 80:
        return AlertSeverity.CRITICAL
    if score >= 60:
        return AlertSeverity.HIGH
    if score >= 35:
        return AlertSeverity.MEDIUM
    if score >= PHISHING_THRESHOLD:
        return AlertSeverity.LOW
    return AlertSeverity.INFO


def _indicators_for(parsed: _ParsedEmail, results: list[HeuristicResult]) -> list[Indicator]:
    indicators: list[Indicator] = []
    seen: set[tuple[str, str]] = set()

    def add(indicator_type: str, value: str, description: str) -> None:
        if not value:
            return
        key = (indicator_type, value)
        if key not in seen:
            indicators.append(Indicator(indicator_type, value, description))
            seen.add(key)

    add("email", parsed.from_email, "Sender address")
    add("domain", parsed.from_domain, "Sender domain")
    for host in parsed.link_hosts[:10]:
        add("domain", host, "Linked host")
    for result in results:
        if result.indicator:
            add("signal", result.indicator, result.reason)

    return indicators


def _extract_body_text(message: Message | EmailMessage) -> str:
    chunks: list[str] = []
    for part in _text_parts(message):
        content_type = part.get_content_type()
        text = _decode_part(part)
        if content_type == "text/html":
            extractor = _HTMLTextExtractor()
            extractor.feed(text)
            text = extractor.text()
        chunks.append(text)
    return "\n".join(chunk for chunk in chunks if chunk)


def _extract_links(message: Message | EmailMessage, body_text: str) -> list[str]:
    html_links: list[str] = []
    for part in _text_parts(message):
        if part.get_content_type() == "text/html":
            html_links.extend(re.findall(r"""href=["']([^"']+)["']""", _decode_part(part), re.IGNORECASE))

    links = html_links + URL_RE.findall(body_text)
    deduped: list[str] = []
    for link in links:
        cleaned = link.rstrip(".,;]")
        if cleaned.startswith("http") and cleaned not in deduped:
            deduped.append(cleaned)
    return deduped


def _text_parts(message: Message | EmailMessage) -> Iterable[Message | EmailMessage]:
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "text" and not part.get_filename():
                yield part
    elif message.get_content_maintype() == "text":
        yield message


def _decode_part(part: Message | EmailMessage) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        return raw_payload if isinstance(raw_payload, str) else ""

    charset = part.get_content_charset() or "utf-8"
    for candidate in (charset, "utf-8", "latin-1", "cp1252"):
        try:
            return payload.decode(candidate, errors="replace")
        except LookupError:
            continue
    return payload.decode("utf-8", errors="replace")


def _attachments(message: Message | EmailMessage) -> list[str]:
    filenames: list[str] = []
    for part in message.walk():
        filename = part.get_filename()
        if filename:
            filenames.append(filename)
    return filenames


def _header(message: Message | EmailMessage, key: str) -> str:
    value = message.get(key)
    return str(value or "")


def _first_address(value: str) -> tuple[str, str]:
    addresses = getaddresses([value])
    if not addresses:
        return "", ""
    display_name, email_address = addresses[0]
    return display_name or "", email_address.lower()


def _domain_from_email(value: str) -> str:
    if not value:
        return ""
    candidate = value.strip().strip("<>").lower()
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    return candidate.strip(" .")


def _host_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _registered_domain(host: str) -> str:
    labels = [label for label in (host or "").lower().split(".") if label]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return labels[0] if labels else ""


def _brands_in(text: str) -> list[str]:
    normalized = _normalize(text)
    return sorted(brand for brand in BRAND_TERMS if re.search(rf"\b{re.escape(brand)}\b", normalized))


def _crypto_terms(parsed: _ParsedEmail) -> list[str]:
    text = _normalize(f"{parsed.subject} {parsed.from_name} {parsed.body_text}")
    return sorted(term for term in CRYPTO_TERMS if term in text)


def _is_ip_address(host: str) -> bool:
    if not RAW_IP_RE.match(host or ""):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _normalize(value: str) -> str:
    normalized = value.lower()
    normalized = normalized.replace("ç", "c").replace("ã", "a").replace("á", "a")
    normalized = normalized.replace("é", "e").replace("í", "i").replace("ó", "o")
    normalized = normalized.replace("ú", "u")
    return normalized


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return slug[:64] or "heuristic_signal"
