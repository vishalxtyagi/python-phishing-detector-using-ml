"""
Risk scorer: converts raw ML probability + features into a 0–100 score
with human-readable explanations.
"""
from typing import List, Optional
from ..models.schemas import RiskExplanation


def compute_risk_score(probability: float) -> int:
    """Convert a probability in [0, 1] to an integer risk score in [0, 100]."""
    return min(100, max(0, round(probability * 100)))


def get_risk_level(score: int) -> str:
    """Return a human-readable risk level for a given score."""
    if score < 30:
        return "safe"
    if score < 65:
        return "suspicious"
    return "phishing"


def build_explanations(
    url_features: dict,
    html_features: Optional[dict],
) -> List[RiskExplanation]:
    """
    Generate a list of RiskExplanation objects describing *why* a URL
    was flagged, based on individual feature values.
    """
    explanations: List[RiskExplanation] = []
    hf = html_features or {}

    # --- URL-based signals -------------------------------------------------------
    if url_features.get("has_ip_address"):
        explanations.append(RiskExplanation(
            factor="IP Address in URL",
            severity="high",
            description="The URL uses an IP address instead of a domain name, which is a common phishing tactic.",
        ))

    if url_features.get("has_at_symbol"):
        explanations.append(RiskExplanation(
            factor="'@' Symbol in URL",
            severity="high",
            description="The '@' symbol in a URL causes browsers to ignore everything before it, hiding the real destination.",
        ))

    if url_features.get("uses_shortener"):
        explanations.append(RiskExplanation(
            factor="URL Shortening Service",
            severity="high",
            description="URL shorteners are frequently used by phishers to obscure the true destination.",
        ))

    if url_features.get("has_suspicious_tld"):
        explanations.append(RiskExplanation(
            factor="Suspicious Top-Level Domain",
            severity="medium",
            description="This URL uses a TLD commonly associated with free or low-cost domains favoured by phishers.",
        ))

    if url_features.get("has_prefix_suffix"):
        explanations.append(RiskExplanation(
            factor="Hyphen in Domain",
            severity="medium",
            description="Hyphens in the domain are rarely used by legitimate sites and often indicate a spoofed brand.",
        ))

    url_length = url_features.get("url_length", 0)
    if url_length > 75:
        explanations.append(RiskExplanation(
            factor="Unusually Long URL",
            severity="low" if url_length < 100 else "medium",
            description=f"The URL is {url_length} characters long. Phishers often use long URLs to bury suspicious parts.",
        ))

    if url_features.get("has_double_slash"):
        explanations.append(RiskExplanation(
            factor="Double Slash Redirect",
            severity="medium",
            description="The URL contains '//' outside of the protocol section, suggesting a redirect.",
        ))

    subdomain_count = url_features.get("subdomain_count", 0)
    if subdomain_count > 2:
        explanations.append(RiskExplanation(
            factor="Excessive Subdomains",
            severity="medium",
            description=f"The URL has {subdomain_count} subdomains. Legitimate sites rarely use more than two.",
        ))

    if not url_features.get("has_https", True):
        explanations.append(RiskExplanation(
            factor="No HTTPS",
            severity="medium",
            description="The URL does not use HTTPS. Legitimate sites almost always use encrypted connections.",
        ))

    age = url_features.get("domain_age_days")
    if age is not None and age < 30:
        explanations.append(RiskExplanation(
            factor="Newly Registered Domain",
            severity="high",
            description=f"This domain was registered only {age} days ago. Fresh domains are a common indicator of phishing.",
        ))

    entropy = url_features.get("entropy", 0.0)
    if entropy > 4.5:
        explanations.append(RiskExplanation(
            factor="High URL Entropy",
            severity="low",
            description=f"The URL has high entropy ({entropy:.2f}), suggesting it may be randomly generated.",
        ))

    # --- HTML-based signals ------------------------------------------------------
    if hf.get("title_brand_mismatch"):
        explanations.append(RiskExplanation(
            factor="Brand Name Mismatch",
            severity="high",
            description="The page title mentions a well-known brand, but the domain does not match that brand.",
        ))

    if hf.get("external_form_actions", 0) > 0:
        explanations.append(RiskExplanation(
            factor="External Form Action",
            severity="high",
            description="One or more forms on this page submit data to an external domain, which is a classic phishing pattern.",
        ))

    if hf.get("iframe_count", 0) > 0:
        explanations.append(RiskExplanation(
            factor="Hidden iFrames",
            severity="medium",
            description=f"The page contains {hf['iframe_count']} iFrame(s), often used to embed malicious content.",
        ))

    if hf.get("has_suspicious_scripts"):
        explanations.append(RiskExplanation(
            factor="Suspicious JavaScript",
            severity="medium",
            description="The page contains JavaScript patterns associated with malicious activity (eval, document.write, etc.).",
        ))

    if hf.get("external_link_ratio", 0) > 0.7:
        explanations.append(RiskExplanation(
            factor="High External Link Ratio",
            severity="low",
            description=f"Over {int(hf['external_link_ratio'] * 100)}% of links point to external domains.",
        ))

    # Sort by severity
    severity_order = {"high": 0, "medium": 1, "low": 2}
    explanations.sort(key=lambda e: severity_order.get(e.severity, 3))

    return explanations
