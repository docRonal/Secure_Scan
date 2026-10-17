from app.models import VerificationMethod
from .dns_verify import check_dns_txt
from .meta_tag_verify import check_meta_tag
from .file_token_verify import check_file_token


def verify_asset(domain: str, token: str, method: VerificationMethod) -> bool:
    """Dispatch ownership checks to the selected verification method."""
    if method == VerificationMethod.dns_txt:
        return check_dns_txt(domain, token)
    if method == VerificationMethod.meta_tag:
        return check_meta_tag(domain, token)
    if method == VerificationMethod.file_token:
        return check_file_token(domain, token)
    raise ValueError(f"Unknown verification method: {method}")
