from .headers_check import HeadersChecker
from .tls_check import TLSChecker
from .tech_fingerprint import TechFingerprintChecker
from .outdated_components import OutdatedComponentsChecker
from .cookie_security_check import CookieSecurityChecker
from .cors_check import CORSChecker
from .exposed_paths_check import ExposedPathsChecker
from .email_security_check import EmailSecurityChecker
from .http_methods_check import HTTPMethodsChecker
from .html_content_check import HTMLContentChecker
from .robots_disclosure_check import RobotsDisclosureChecker
from .subdomain_takeover_check import SubdomainTakeoverChecker

PASSIVE_SCANNERS = [
    HeadersChecker,
    TLSChecker,
    TechFingerprintChecker,
    OutdatedComponentsChecker,
    CookieSecurityChecker,
    CORSChecker,
    ExposedPathsChecker,
    EmailSecurityChecker,
    HTTPMethodsChecker,
    HTMLContentChecker,
    RobotsDisclosureChecker,
    SubdomainTakeoverChecker,
]
