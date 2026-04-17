import base64
import hashlib
import time
from dataclasses import dataclass
from typing import Optional
import re

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

VT_API_BASE = "https://www.virustotal.com/api/v3"
# Free tier: 4 requests/minute, 500/day
_REQUEST_INTERVAL = 15.0
_last_request_time: float = 0.0

URL_PATTERN = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)


@dataclass
class VtFinding:
    score: int
    reason: str
    url: str = ""


def analyze_urls_vt(text: str, api_key: str) -> list[VtFinding]:
    if not REQUESTS_AVAILABLE:
        return [VtFinding(0, "requests library not installed (pip install requests)")]

    findings = []
    urls = list(set(URL_PATTERN.findall(text)))[:10]  # cap at 10 unique URLs

    for url in urls:
        result = _check_url(url, api_key)
        if result:
            findings.append(result)

    return findings


def _check_url(url: str, api_key: str) -> Optional[VtFinding]:
    global _last_request_time

    elapsed = time.time() - _last_request_time
    if elapsed < _REQUEST_INTERVAL:
        time.sleep(_REQUEST_INTERVAL - elapsed)

    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()

    try:
        _last_request_time = time.time()
        resp = requests.get(
            f"{VT_API_BASE}/urls/{url_id}",
            headers=headers,
            timeout=10,
        )

        if resp.status_code == 404:
            # URL not in VT database yet — submit it
            submit = requests.post(
                f"{VT_API_BASE}/urls",
                headers=headers,
                data={"url": url},
                timeout=10,
            )
            _last_request_time = time.time()
            if submit.status_code != 200:
                return None
            return VtFinding(0, f"URL submitted to VirusTotal for first-time analysis (no cached result)", url)

        if resp.status_code == 401:
            return VtFinding(0, "VirusTotal API key is invalid or expired")

        if resp.status_code != 200:
            return None

        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        if malicious >= 3:
            score = min(40 + malicious * 2, 60)
            return VtFinding(score, f"VirusTotal: {malicious}/{total} engines flagged URL as MALICIOUS", url)
        elif malicious >= 1 or suspicious >= 3:
            return VtFinding(20, f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections", url)

    except requests.exceptions.Timeout:
        return VtFinding(0, f"VirusTotal request timed out for URL", url)
    except requests.exceptions.ConnectionError:
        return VtFinding(0, "VirusTotal unreachable (no internet connection?)")
    except Exception:
        pass

    return None
