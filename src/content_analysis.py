import re
from dataclasses import dataclass


@dataclass
class ContentFinding:
    score: int
    reason: str


URGENCY_PHRASES = [
    (r'\bact\s+now\b', 10, "Urgency phrase: 'act now'"),
    (r'\bimmediately\b', 8, "Urgency phrase: 'immediately'"),
    (r'\bwithin\s+\d+\s+hours?\b', 10, "Time pressure phrase"),
    (r'\bexpires?\s+(today|soon|in \d+)\b', 10, "Expiration pressure"),
    (r'\burgent\b', 8, "Urgency keyword: 'urgent'"),
    (r'\blast\s+chance\b', 10, "Urgency phrase: 'last chance'"),
    (r'\baccount\s+(will\s+be\s+)?(suspended|closed|terminated|deactivated)\b', 20, "Account suspension threat"),
    (r'\byour\s+account\s+has\s+been\s+(locked|compromised|suspended)\b', 25, "Account compromise claim"),
]

CREDENTIAL_PHRASES = [
    (r'\bverify\s+your\s+(account|identity|email|password)\b', 20, "Credential verification request"),
    (r'\bconfirm\s+your\s+(account|identity|details|information)\b', 15, "Confirmation request"),
    (r'\benter\s+your\s+password\b', 25, "Direct password request"),
    (r'\bupdate\s+your\s+(billing|payment|credit\s+card)\b', 20, "Payment info request"),
    (r'\bprovide\s+your\s+(personal|account|banking)\s+information\b', 20, "Personal info request"),
    (r'\bsocial\s+security\s+number\b', 30, "SSN request"),
]

FINANCIAL_LURES = [
    (r'\byou\s+have\s+(won|been\s+selected)\b', 20, "Prize/lottery lure"),
    (r'\bclaim\s+your\s+(prize|reward|gift|winning)\b', 20, "Reward claim lure"),
    (r'\bunclaimed\s+(funds|money|refund)\b', 15, "Unclaimed funds lure"),
    (r'\bfree\s+gift\b', 10, "Free gift lure"),
    (r'\blottery\b', 15, "Lottery mention"),
    (r'\binheritance\b', 20, "Inheritance scam pattern"),
]

ATTACHMENT_WARNINGS = [
    (r'\bopen\s+the\s+attached?\b', 15, "Prompts to open attachment"),
    (r'\bdownload\s+the\s+attached?\b', 15, "Prompts to download attachment"),
    (r'\bsee\s+attached\s+(invoice|document|receipt|file)\b', 10, "Suspicious attachment reference"),
]


def analyze_content(text: str) -> list[ContentFinding]:
    findings = []
    text_lower = text.lower()

    for pattern, score, reason in URGENCY_PHRASES:
        if re.search(pattern, text_lower):
            findings.append(ContentFinding(score, reason))

    for pattern, score, reason in CREDENTIAL_PHRASES:
        if re.search(pattern, text_lower):
            findings.append(ContentFinding(score, reason))

    for pattern, score, reason in FINANCIAL_LURES:
        if re.search(pattern, text_lower):
            findings.append(ContentFinding(score, reason))

    for pattern, score, reason in ATTACHMENT_WARNINGS:
        if re.search(pattern, text_lower):
            findings.append(ContentFinding(score, reason))

    upper_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if upper_ratio > 0.4 and len(text) > 50:
        findings.append(ContentFinding(10, f"Excessive capitalization ({upper_ratio:.0%} uppercase)"))

    exclamation_count = text.count("!")
    if exclamation_count >= 3:
        findings.append(ContentFinding(5, f"Excessive exclamation marks ({exclamation_count})"))

    return findings
