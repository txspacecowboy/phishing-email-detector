import email
import email.policy
from dataclasses import dataclass, field
from typing import Optional

from header_analysis import analyze_headers, HeaderFinding
from url_analysis import analyze_urls, UrlFinding
from content_analysis import analyze_content, ContentFinding
from dns_analysis import analyze_dns, DnsFinding
from virustotal import analyze_urls_vt, VtFinding


@dataclass
class AnalysisResult:
    raw_score: int
    risk_level: str
    header_findings: list[HeaderFinding] = field(default_factory=list)
    url_findings: list[UrlFinding] = field(default_factory=list)
    content_findings: list[ContentFinding] = field(default_factory=list)
    dns_findings: list[DnsFinding] = field(default_factory=list)
    vt_findings: list[VtFinding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        scored = (
            [f for f in self.header_findings if f.score > 0]
            + [f for f in self.url_findings if f.score > 0]
            + [f for f in self.content_findings if f.score > 0]
            + [f for f in self.dns_findings if f.score > 0]
            + [f for f in self.vt_findings if f.score > 0]
        )
        return len(scored)


def analyze_email(raw_email: str, vt_api_key: Optional[str] = None, live_dns: bool = False) -> AnalysisResult:
    msg = email.message_from_string(raw_email, policy=email.policy.default)
    body = _extract_body(msg)

    header_findings = analyze_headers(msg)
    url_findings = analyze_urls(body)
    content_findings = analyze_content(body)
    dns_findings = analyze_dns(msg) if live_dns else []
    vt_findings = analyze_urls_vt(body, vt_api_key) if vt_api_key else []

    raw_score = (
        sum(f.score for f in header_findings)
        + sum(f.score for f in url_findings)
        + sum(f.score for f in content_findings)
        + sum(f.score for f in dns_findings)
        + sum(f.score for f in vt_findings)
    )
    raw_score = min(raw_score, 100)

    if raw_score >= 70:
        risk_level = "HIGH"
    elif raw_score >= 40:
        risk_level = "MEDIUM"
    elif raw_score >= 15:
        risk_level = "LOW"
    else:
        risk_level = "CLEAN"

    return AnalysisResult(
        raw_score=raw_score,
        risk_level=risk_level,
        header_findings=header_findings,
        url_findings=url_findings,
        content_findings=content_findings,
        dns_findings=dns_findings,
        vt_findings=vt_findings,
    )


def _extract_body(msg: email.message.Message) -> str:
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ("text/plain", "text/html"):
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            body_parts.append(str(msg.get_payload()))
    return "\n".join(body_parts)
