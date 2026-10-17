"""Verify ownership by fetching the verification file from the site root."""
import requests

from app.config import settings


def check_file_token(domain: str, expected_token: str) -> bool:
    url = f"https://{domain}/securescan-verify.txt"
    headers = {"User-Agent": settings.http_user_agent}
    try:
        resp = requests.get(url, headers=headers, timeout=settings.http_timeout_seconds)
        resp.raise_for_status()
    except requests.RequestException:
        return False

    return resp.text.strip() == expected_token.strip()
