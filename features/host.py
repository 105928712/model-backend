# host.py
# 2026 Joey Manani & Anchorfish Team
# Host structure extractors

from urllib.parse import urlsplit

from .base import Feature
from .utils import get_host, is_ip


class HasAtSymbol(Feature):
    """@ in the URL means browsers ignore everything before it - classic redirect trick."""
    name = "has_at_symbol"
    description = "Whether the URL contains an @ symbol."

    def extract(self, url: str) -> bool:
        return "@" in url


class IsIPHost(Feature):
    """Legit sites publish domain names, not raw IPs."""
    name = "is_ip_host"
    description = "Whether the host is a raw IP address instead of a domain"

    def extract(self, url: str) -> bool:
        return is_ip(get_host(url))


class HasNonStandardPort(Feature):
    name = "has_non_standard_port"
    description = "Whether the URL specifies a port other than 80 or 443."

    def extract(self, url: str) -> bool:
        try:
            port = urlsplit(url).port
        except ValueError:
            return False
        return port is not None and port not in (80, 443)


class HttpsInHostname(Feature):
    """e.g. https-paypal-login.com - stuffing "https" into the domain to look secure."""
    name = "https_in_hostname"
    description = "Whether the literal string 'https' appears in the hostname"

    def extract(self, url: str) -> bool:
        return "https" in get_host(url)


class DomainHasPunycode(Feature):
    name = "domain_has_punycode"
    description = "Whether any label of the host is punycode (xn--)"

    def extract(self, url: str) -> bool:
        host = get_host(url)
        return any(label.startswith("xn--") for label in host.split("."))

class HostLength(Feature):

    name = "host_length"
    description = "The length of the host"

    def extract(self, url: str) -> int:
        return len(get_host(url))
