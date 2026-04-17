import email
import email.policy
from dataclasses import dataclass, field

from header_analysis import analyze_headers, HeaderFinding
from url_analysis import analyze_urls, UrlFinding
from content_analysis import analyze_content, ContentFinding


@dataclass
class AnalysisResult:
    raw_score: int
    risk_level: str
    header_findings: list[HeaderFinding] = field(default_factory=list)
    url_findings: list[UrlFinding] = field(default_factory=list)
    content_findings: list[ContentFinding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.header_findings) + len(self.url_findings) + len(self.content_findings)


def analyze_email(raw_email: str) -> AnalysisResult:
    msg = email.message_from_string(raw_email, policy=email.policy.default)
    body = _extract_body(msg)

    header_findings = analyze_headers(msg)
    url_findings = analyze_urls(body)
    content_findings = analyze_content(body)

    raw_score = (
        sum(f.score for f in header_findings)
        + sum(f.score for f in url_findings)
        + sum(f.score for f in content_findings)
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
