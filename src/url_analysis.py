import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class UrlFinding:
    score: int
    reason: str
    url: str = ""


SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
    "rb.gy", "cutt.ly", "tiny.cc", "is.gd", "buff.ly", "rebrand.ly",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".work", ".gq", ".ml", ".cf",
    ".tk", ".ga", ".men", ".download", ".stream", ".racing",
}

HOMOGLYPH_PATTERNS = [
    (r'[0o]{2,}', "repeated 0/o substitution"),
    (r'rn', "possible 'm' homoglyph (rn)"),
    (r'paypa1', "PayPal homoglyph"),
    (r'go{2,}gle', "Google homoglyph"),
    (r'micros0ft', "Microsoft homoglyph"),
    (r'arnazon', "Amazon homoglyph"),
]

URL_PATTERN = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)


def analyze_urls(text: str) -> list[UrlFinding]:
    findings = []
    urls = URL_PATTERN.findall(text)

    if not urls:
        return findings

    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
        except Exception:
            continue

        if re.match(r'\d{1,3}(\.\d{1,3}){3}', hostname):
            findings.append(UrlFinding(30, "URL uses raw IP address instead of domain name", url))

        if hostname in SHORTENERS:
            findings.append(UrlFinding(20, f"URL shortener '{hostname}' hides true destination", url))

        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                findings.append(UrlFinding(15, f"Suspicious TLD '{tld}'", url))
                break

        subdomain_count = hostname.count(".")
        if subdomain_count >= 4:
            findings.append(UrlFinding(15, f"Excessive subdomains ({subdomain_count} dots) in URL", url))

        for pattern, desc in HOMOGLYPH_PATTERNS:
            if re.search(pattern, hostname, re.IGNORECASE):
                findings.append(UrlFinding(35, f"Possible homoglyph attack: {desc}", url))
                break

        if len(url) > 200:
            findings.append(UrlFinding(10, "Unusually long URL (obfuscation technique)", url))

        if "%" in url and re.search(r'%[0-9a-fA-F]{2}', url):
            encoded_count = len(re.findall(r'%[0-9a-fA-F]{2}', url))
            if encoded_count > 5:
                findings.append(UrlFinding(15, f"Heavy URL encoding ({encoded_count} encoded chars)", url))

    return findings
