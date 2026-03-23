"""HTML feature extraction for phishing detection."""
import re
import logging
from typing import Optional
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

SUSPICIOUS_JS_PATTERNS = re.compile(
    r"(eval\s*\(|document\.write\s*\(|window\.location\s*=|"
    r"unescape\s*\(|String\.fromCharCode\s*\()",
    re.IGNORECASE,
)


def extract_html_features(url: str, html: str) -> dict:
    """
    Extract phishing-relevant features from a page's HTML.

    Args:
        url:  The page URL (used to determine external vs internal links).
        html: Raw HTML content as a string.

    Returns:
        A flat dict matching HTMLFeatures schema.
    """
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
    except Exception as exc:
        logger.warning("BeautifulSoup parse error: %s", exc)
        return _empty_html_features()

    base_domain = urlparse(url).netloc or ""

    # ----- Forms & password fields ------------------------------------------------
    forms = soup.find_all("form")
    form_count = len(forms)
    has_password_field = bool(soup.find("input", {"type": re.compile(r"^password$", re.I)}))

    external_form_actions = 0
    for form in forms:
        action = form.get("action", "")
        if action:
            action_domain = urlparse(urljoin(url, action)).netloc
            if action_domain and action_domain != base_domain:
                external_form_actions += 1

    # ----- iFrames ----------------------------------------------------------------
    iframe_count = len(soup.find_all("iframe"))

    # ----- Hidden elements -------------------------------------------------------
    hidden_count = len(soup.find_all(
        lambda tag: (
            tag.get("style", "").lower().find("display:none") != -1
            or tag.get("style", "").lower().find("display: none") != -1
            or tag.get("type", "").lower() == "hidden"
        )
    ))

    # ----- Links & external ratio ------------------------------------------------
    all_links = [a.get("href", "") for a in soup.find_all("a", href=True)]
    total_links = len(all_links)
    external_links = 0
    for href in all_links:
        parsed = urlparse(href)
        if parsed.scheme in ("http", "https"):
            link_domain = parsed.netloc
            if link_domain and link_domain != base_domain:
                external_links += 1

    external_link_ratio = (external_links / total_links) if total_links > 0 else 0.0

    # ----- Meta-redirects & JS redirects -----------------------------------------
    redirect_count = len(soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}))
    scripts = soup.find_all("script")
    for script in scripts:
        content = script.string or ""
        if "window.location" in content or "location.replace" in content or "location.href" in content:
            redirect_count += 1

    # ----- Suspicious JS ---------------------------------------------------------
    has_suspicious_scripts = False
    for script in scripts:
        content = script.string or ""
        if SUSPICIOUS_JS_PATTERNS.search(content):
            has_suspicious_scripts = True
            break

    # ----- Favicon ---------------------------------------------------------------
    has_favicon = any(
        "icon" in " ".join(link.get("rel", [])).lower()
        for link in soup.find_all("link")
    )

    # ----- Title / brand mismatch -------------------------------------------------
    title_tag = soup.find("title")
    title_text = title_tag.get_text(strip=True).lower() if title_tag else ""
    # Heuristic: title mentions a well-known brand but domain doesn't match
    KNOWN_BRANDS = [
        "paypal", "amazon", "google", "facebook", "microsoft", "apple",
        "netflix", "instagram", "twitter", "linkedin", "bank", "chase",
        "wellsfargo", "citibank", "ebay", "dropbox",
    ]
    title_brand_mismatch = False
    import re as _re
    for brand in KNOWN_BRANDS:
        if _re.search(r'\b' + brand + r'\b', title_text):
            # Check if brand appears as an exact subdomain/domain component
            domain_parts = base_domain.lower().replace("www.", "").split(".")
            if brand not in domain_parts:
                title_brand_mismatch = True
                break

    return {
        "has_password_field": has_password_field,
        "form_count": form_count,
        "external_form_actions": external_form_actions,
        "iframe_count": iframe_count,
        "hidden_element_count": hidden_count,
        "external_link_ratio": round(external_link_ratio, 4),
        "redirect_count": redirect_count,
        "has_suspicious_scripts": has_suspicious_scripts,
        "has_favicon": has_favicon,
        "title_brand_mismatch": title_brand_mismatch,
    }


def _empty_html_features() -> dict:
    return {
        "has_password_field": False,
        "form_count": 0,
        "external_form_actions": 0,
        "iframe_count": 0,
        "hidden_element_count": 0,
        "external_link_ratio": 0.0,
        "redirect_count": 0,
        "has_suspicious_scripts": False,
        "has_favicon": False,
        "title_brand_mismatch": False,
    }


def html_features_to_ml_vector(features: dict) -> list:
    """
    Convert HTML feature dict to a numeric vector for ML prediction.
    Order must match the training feature order.
    """
    return [
        1 if features["has_password_field"] else 0,
        features["form_count"],
        features["external_form_actions"],
        features["iframe_count"],
        features["hidden_element_count"],
        features["external_link_ratio"],
        features["redirect_count"],
        1 if features["has_suspicious_scripts"] else 0,
        1 if features["has_favicon"] else 0,
        1 if features["title_brand_mismatch"] else 0,
    ]
