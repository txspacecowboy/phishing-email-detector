import re
import socket
from dataclasses import dataclass
from typing import Optional

try:
    import dns.resolver
    import dns.resolver as _dns_resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


@dataclass
class DnsFinding:
    score: int
    reason: str


def analyze_dns(msg) -> list[DnsFinding]:
    if not DNS_AVAILABLE:
        return [DnsFinding(0, "dnspython not installed — live DNS checks skipped (pip install dnspython)")]

    findings = []
    from_header = msg.get("From", "")
    sending_domain = _extract_domain(from_header)
    if not sending_domain:
        return findings

    findings += _check_spf(sending_domain)
    findings += _check_dmarc(sending_domain)

    selector = _extract_dkim_selector(msg)
    if selector:
        findings += _check_dkim(sending_domain, selector)

    return findings


def _check_spf(domain: str) -> list[DnsFinding]:
    findings = []
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        spf_records = [
            r.to_text().strip('"')
            for rdata in answers
            for r in rdata.strings
            if b"v=spf1" in r
        ]
        if not spf_records:
            findings.append(DnsFinding(20, f"No SPF record found for '{domain}'"))
        else:
            spf = spf_records[0]
            if "-all" not in spf and "~all" not in spf:
                findings.append(DnsFinding(15, f"SPF record for '{domain}' has no hard/soft fail policy"))
            elif "~all" in spf and "-all" not in spf:
                findings.append(DnsFinding(5, f"SPF for '{domain}' uses softfail (~all) instead of hardfail (-all)"))
    except dns.resolver.NXDOMAIN:
        findings.append(DnsFinding(25, f"Domain '{domain}' does not exist (NXDOMAIN)"))
    except dns.resolver.Timeout:
        findings.append(DnsFinding(0, f"DNS timeout checking SPF for '{domain}'"))
    except Exception:
        pass
    return findings


def _check_dmarc(domain: str) -> list[DnsFinding]:
    findings = []
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=5)
        dmarc_records = [
            r.to_text().strip('"')
            for rdata in answers
            for r in rdata.strings
            if b"v=DMARC1" in r
        ]
        if not dmarc_records:
            findings.append(DnsFinding(20, f"No DMARC record found for '{domain}'"))
        else:
            dmarc = dmarc_records[0]
            if "p=none" in dmarc:
                findings.append(DnsFinding(10, f"DMARC policy for '{domain}' is 'none' (monitoring only, no enforcement)"))
            elif "p=quarantine" in dmarc:
                pass  # acceptable
            elif "p=reject" in dmarc:
                pass  # strong policy, good sign
    except dns.resolver.NXDOMAIN:
        findings.append(DnsFinding(20, f"No DMARC record for '{domain}'"))
    except dns.resolver.Timeout:
        findings.append(DnsFinding(0, f"DNS timeout checking DMARC for '{domain}'"))
    except Exception:
        pass
    return findings


def _check_dkim(domain: str, selector: str) -> list[DnsFinding]:
    findings = []
    dkim_domain = f"{selector}._domainkey.{domain}"
    try:
        dns.resolver.resolve(dkim_domain, "TXT", lifetime=5)
    except dns.resolver.NXDOMAIN:
        findings.append(DnsFinding(20, f"DKIM key missing for selector '{selector}' on '{domain}'"))
    except dns.resolver.Timeout:
        pass
    except Exception:
        pass
    return findings


def _extract_domain(from_header: str) -> Optional[str]:
    match = re.search(r'@([\w.-]+)', from_header)
    return match.group(1).lower() if match else None


def _extract_dkim_selector(msg) -> Optional[str]:
    dkim_sig = msg.get("DKIM-Signature", "")
    match = re.search(r'\bs=([^;]+)', dkim_sig)
    return match.group(1).strip() if match else None
