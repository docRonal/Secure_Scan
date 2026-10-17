"""Verify domain ownership using the _securescan DNS TXT record."""
import dns.resolver


def check_dns_txt(domain: str, expected_token: str) -> bool:
    """Return true only when the expected token is present in DNS TXT."""
    record_name = f"_securescan.{domain}"
    try:
        answers = dns.resolver.resolve(record_name, "TXT", lifetime=5.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return False

    expected_token = expected_token.strip()
    for rdata in answers:
        txt_value = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        if txt_value.strip() == expected_token:
            return True
    return False
