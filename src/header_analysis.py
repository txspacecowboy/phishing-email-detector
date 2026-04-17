import email
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class HeaderFinding:
    score: int
    reason: str


def analyze_headers(msg: email.message.Message) -> list[HeaderFinding]:
    findings = []

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")

    from_addr = _extract_address(from_header)
    reply_addr = _extract_address(reply_to)
    return_addr = _extract_address(return_path)

    if reply_addr and from_addr and _domain(reply_addr) != _domain(from_addr):
        findings.append(HeaderFinding(25, f"Reply-To domain '{_domain(reply_addr)}' differs from From domain '{_domain(from_addr)}'"))

    if return_addr and from_addr and _domain(return_addr) != _domain(from_addr):
        findings.append(HeaderFinding(15, f"Return-Path domain '{_domain(return_addr)}' differs from From domain '{_domain(from_addr)}'"))

    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        if "spf=fail" in auth_results.lower():
            findings.append(HeaderFinding(30, "SPF check failed"))
        elif "spf=softfail" in auth_results.lower():
            findings.append(HeaderFinding(15, "SPF soft fail"))
        if "dkim=fail" in auth_results.lower():
            findings.append(HeaderFinding(25, "DKIM signature failed"))
        if "dmarc=fail" in auth_results.lower():
            findings.append(HeaderFinding(30, "DMARC policy failed"))

    display_name = _extract_display_name(from_header)
    trusted_brands = ["paypal", "amazon", "microsoft", "apple", "google", "bank", "chase", "wells fargo", "netflix"]
    if display_name:
        for brand in trusted_brands:
            if brand in display_name.lower() and brand not in (from_addr or "").lower():
                findings.append(HeaderFinding(35, f"Display name impersonates '{brand}' but sending domain doesn't match"))
                break

    if from_addr and re.search(r'\d{4,}', _domain(from_addr) or ""):
        findings.append(HeaderFinding(10, "Sending domain contains many numbers (suspicious pattern)"))

    received_headers = msg.get_all("Received", [])
    if len(received_headers) == 0:
        findings.append(HeaderFinding(20, "No Received headers present"))

    return findings


def _extract_address(header: str) -> Optional[str]:
    match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', header)
    return match.group(0).lower() if match else None


def _extract_display_name(from_header: str) -> Optional[str]:
    match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
    return match.group(1).strip() if match else None


def _domain(address: str) -> Optional[str]:
    parts = address.split("@")
    return parts[1].lower() if len(parts) == 2 else None
