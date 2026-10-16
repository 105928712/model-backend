# utils.py
# 2026 Joey Manani & Anchorfish Team
# Shared helpers

import ipaddress
import re
from collections import Counter
from functools import lru_cache
from math import log2
from urllib.parse import urlsplit

from publicsuffixlist import PublicSuffixList

psl = PublicSuffixList(only_icann=True)  # ignore private suffixes (github.io etc.)
WWW_LABEL = re.compile(r"www\d*")        # www, www1, www2...
WWW_PREFIX = re.compile(r"^www\d*\.", re.IGNORECASE)
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")  # http://, https://, hxxp://...
ESCAPED = re.compile(r"\\([%'])")        # \% and \' -> % and '


def normalise_url(url: str) -> str:
    """Strip whitespace and add http:// if the URL doesn't start with a scheme."""
    url = url.strip()
    # anchored match: "site.com/?next=http://x" has "://" in it but still no scheme of its own
    if not SCHEME.match(url):
        url = "http://" + url
    return url

def is_readable(url):
    """Check if a URL is readable and normal"""
    url = url.strip()
    if url == "":
        return False
    if not url.isprintable():
        return False
    if "�" in url:  # byte that wasn't valid UTF8, the URL is bad
        return False
    for char in url:
        if char.isspace():
            return False

    full_url = normalise_url(url)
    host = get_host(full_url)
    if not host:
        return False
    if is_ip(host):
        return True
    if psl.publicsuffix(host, accept_unknown=False):
        return True
    return False

def canonical_url(url: str) -> str:
    """Write every source's URLs the same way: no scheme, no leading www., no trailing /

    https://www.example.com/ -> example.com, but http://a.com/x/ -> a.com/x/ (that slash is part of the path).
    
    
    Dataset benign URLs have no scheme or www. while malicious ones often do;
    the model could learn which dataset a URL came from instead of
    whether it is phishing or not. big bias fix

    Same idea for how a source stored its URLs: one wrapped them in '...' and escaped % as \\%,
    others copied & out of HTML as &amp;. Neither is part of the real URL. Just storage quirk
    """
    url = url.strip()
    if len(url) >= 2 and (url[0] == url[-1] == "'"): # check first char = last char = ' (quote wrap check)
        url = url[1:-1]

    # only &amp; html.unescape would also turn real query params like "&copy=2" into "©=2" - we dont want this
    url = ESCAPED.sub(r"\1", url)
    while "&amp;" in url:  # some were escaped twice (&amp;amp;)
        url = url.replace("&amp;", "&");

    url = SCHEME.sub("", url, count=1)
    labels = get_subdomain_labels("http://" + url)
    # only strip www when it is a subdomain ("www.com" is a real domain and stays as it is)
    if labels and WWW_LABEL.fullmatch(labels[0]):
        url = WWW_PREFIX.sub("", url, count=1)
    parts = split_url("http://" + url)
    if url.endswith("/") and parts and parts.path == "/" and not parts.query and not parts.fragment:
        url = url[:-1]
    return url


@lru_cache(maxsize=1024)
def split_url(url: str):
    """urlsplit that returns None instead of raising on malformed URLs (e.g. "http://[::1")."""
    try:
        return urlsplit(url)
    except ValueError:
        return None


def shannon_entropy(data: str) -> float:
    """H(X) = -sum(p(x) * log2(p(x)))"""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * log2(c / n) for c in Counter(data).values())


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@lru_cache(maxsize=1024)
def get_host(url: str) -> str:
    """Lowercase hostname, trailing dot removed, unicode converted to punycode."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return ""
    if not host:
        return ""
    host = host.rstrip(".")
    try:
        host = host.encode("idna").decode("ascii") # convert to punycode
    except UnicodeError:
        pass
    return host


@lru_cache(maxsize=1024)
def get_subdomain_labels(url: str) -> tuple:
    """Subdomain labels, e.g. ('www', 'login') for www.login.example.com."""
    host = get_host(url)
    if not host or is_ip(host):
        return ()
    registrable = psl.privatesuffix(host)
    if not registrable or registrable == host:
        return ()
    return tuple[str, ...](host[: -len(registrable) - 1].split("."))


@lru_cache(maxsize=1024)
def get_tld(url: str) -> str:
    """Public suffix of the host, e.g. 'co.uk'. Empty for IP hosts and hosts that can't be parsed."""
    host = get_host(url)
    if not host or is_ip(host):
        return ""
    return psl.publicsuffix(host) or ""  # None for broken hosts like "a..b.com"


@lru_cache(maxsize=1024)
def get_root_label(url: str) -> str:
    """Registrable name without its suffix, e.g. 'example' for login.example.co.uk."""
    tld = get_tld(url)
    registrable = psl.privatesuffix(get_host(url)) if tld else None
    return registrable[: -len(tld) - 1] if registrable else ""
