"""Verify ownership by finding the expected meta tag on the homepage."""
import re
import requests

from app.config import settings

META_TAG_PATTERN = re.compile(
    r'<meta[^>]+name=["\']securescan-verification["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def check_meta_tag(domain: str, expected_token: str) -> bool:
    url = f"https://{domain}/"
    headers = {"User-Agent": settings.http_user_agent}
    try:
        resp = requests.get(url, headers=headers, timeout=settings.http_timeout_seconds)
        resp.raise_for_status()
    except requests.RequestException:
        return False

    match = META_TAG_PATTERN.search(resp.text)
    if not match:
        return False
    return match.group(1).strip() == expected_token.strip()
