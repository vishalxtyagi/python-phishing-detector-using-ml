"""URL feature extraction for phishing detection."""
import re
import math
import socket
import ipaddress
from typing import Optional, Tuple
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

SHORTENING_SERVICES = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|"
    r"cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|"
    r"snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|"
    r"fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|"
    r"bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|po\.st|bc\.vc|"
    r"twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|"
    r"scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net",
    re.IGNORECASE,
)

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".pw", ".cc", ".su",
    ".top", ".click", ".link", ".work", ".loan", ".win", ".review",
    ".trade", ".racing", ".date", ".faith", ".party", ".stream",
}

SPECIAL_CHARS_PATTERN = re.compile(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]")
DIGIT_PATTERN = re.compile(r"\d")


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def is_ip_address(hostname: str) -> bool:
    """Return True if hostname is an IP address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def get_domain_age(domain: str) -> Tuple[Optional[int], Optional[int]]:
    """
    Return (age_days, registration_length_days) using python-whois.
    Returns (None, None) on failure to avoid blocking the scan.
    """
    try:
        import whois
        import datetime

        w = whois.whois(domain)
        if w is None:
            return None, None

        creation = w.creation_date
        expiration = w.expiration_date

        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiration, list):
            expiration = expiration[0]

        now = datetime.datetime.now()
        age_days = (now - creation).days if creation else None
        reg_length = (expiration - now).days if expiration else None
        return age_days, reg_length
    except Exception:
        return None, None


def extract_url_features(url: str, fetch_domain_age: bool = False) -> dict:
    """
    Extract phishing-relevant features from a URL.

    Returns a flat dict matching URLFeatures schema.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full_domain = parsed.netloc or ""

    # Remove www. prefix for subdomain counting
    domain_parts = hostname.replace("www.", "").split(".")
    tld = "." + domain_parts[-1] if domain_parts else ""

    # Subdomains: parts beyond the registrable domain (name + tld)
    subdomain_count = max(0, len(domain_parts) - 2)

    # URL depth (number of path segments)
    url_depth = len([p for p in path.split("/") if p])

    # Digit ratio in full URL
    digits = len(DIGIT_PATTERN.findall(url))
    digit_ratio = digits / len(url) if url else 0.0

    # Domain age
    age_days, reg_length = None, None
    if fetch_domain_age and hostname:
        age_days, reg_length = get_domain_age(hostname)

    return {
        "url_length": len(url),
        "entropy": round(calculate_entropy(url), 4),
        "special_char_count": len(SPECIAL_CHARS_PATTERN.findall(url)),
        "subdomain_count": subdomain_count,
        "has_https": parsed.scheme == "https",
        "has_ip_address": is_ip_address(hostname),
        "has_at_symbol": "@" in url,
        "has_double_slash": bool(re.search(r"https?://[^\s]*//", url)),
        "has_prefix_suffix": "-" in full_domain,
        "uses_shortener": bool(SHORTENING_SERVICES.search(url)),
        "domain_age_days": age_days,
        "registration_length_days": reg_length,
        "has_suspicious_tld": tld.lower() in SUSPICIOUS_TLDS,
        "digit_ratio": round(digit_ratio, 4),
        "url_depth": url_depth,
    }


def url_features_to_ml_vector(features: dict) -> list:
    """
    Convert URL feature dict to a numeric vector for ML prediction.
    Order must match the training feature order.
    """
    return [
        features["url_length"],
        features["entropy"],
        features["special_char_count"],
        features["subdomain_count"],
        1 if features["has_https"] else 0,
        1 if features["has_ip_address"] else 0,
        1 if features["has_at_symbol"] else 0,
        1 if features["has_double_slash"] else 0,
        1 if features["has_prefix_suffix"] else 0,
        1 if features["uses_shortener"] else 0,
        features["domain_age_days"] if features["domain_age_days"] is not None else -1,
        features["registration_length_days"] if features["registration_length_days"] is not None else -1,
        1 if features["has_suspicious_tld"] else 0,
        features["digit_ratio"],
        features["url_depth"],
    ]
