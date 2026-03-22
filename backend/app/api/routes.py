"""FastAPI route definitions for the phishing detection API."""
import asyncio
import logging
import time
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, BackgroundTasks

from ..models.schemas import (
    ScanURLRequest,
    ScanHTMLRequest,
    BatchScanRequest,
    ScanResult,
    BatchScanResult,
    URLFeatures,
    HTMLFeatures,
)
from ..core.url_analyzer import extract_url_features
from ..core.html_analyzer import extract_html_features
from ..core.ml_model import PhishingModel
from ..core.scorer import compute_risk_score, get_risk_level, build_explanations

logger = logging.getLogger(__name__)
router = APIRouter()

# HTTP client shared across requests
_http_client: Optional[httpx.AsyncClient] = None


def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=True,
            headers={"User-Agent": "PhishingDetector/1.0 (security scan)"},
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )
    return _http_client


async def fetch_html(url: str) -> Optional[str]:
    """Fetch HTML content from a URL, returning None on error."""
    try:
        client = get_http_client()
        resp = await client.get(url)
        return resp.text
    except Exception as exc:
        logger.warning("Failed to fetch HTML from %s: %s", url, exc)
        return None


async def _scan_single(url: str, fetch_html_flag: bool) -> ScanResult:
    """Core scan logic used by /scan-url and /batch-scan."""
    start = time.monotonic()
    model = PhishingModel.get_instance()

    try:
        # URL feature extraction (fast, no network calls)
        url_feat_dict = extract_url_features(url, fetch_domain_age=False)

        # Optionally fetch and analyse HTML
        html_feat_dict: Optional[dict] = None
        html: Optional[str] = None

        if fetch_html_flag:
            html = await fetch_html(url)
            if html:
                html_feat_dict = extract_html_features(url, html)

        # ML prediction
        probability, is_phishing = model.predict(url_feat_dict, html_feat_dict)
        risk_score = compute_risk_score(probability)
        risk_level = get_risk_level(risk_score)
        explanations = build_explanations(url_feat_dict, html_feat_dict)

        elapsed = (time.monotonic() - start) * 1000

        return ScanResult(
            url=url,
            risk_score=risk_score,
            risk_level=risk_level,
            is_phishing=is_phishing,
            confidence=round(abs(probability - 0.5) * 2, 4),
            phishing_probability=round(probability, 4),
            url_features=URLFeatures(**url_feat_dict),
            html_features=HTMLFeatures(**html_feat_dict) if html_feat_dict else None,
            explanations=explanations,
            scan_duration_ms=round(elapsed, 2),
        )

    except Exception as exc:
        logger.exception("Error scanning URL %s", url)
        elapsed = (time.monotonic() - start) * 1000
        return ScanResult(
            url=url,
            risk_score=0,
            risk_level="safe",
            is_phishing=False,
            confidence=0.0,
            phishing_probability=0.0,
            scan_duration_ms=round(elapsed, 2),
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scan-url", response_model=ScanResult, tags=["Scanning"])
async def scan_url(request: ScanURLRequest) -> ScanResult:
    """
    Scan a single URL for phishing.

    Extracts URL features and optionally fetches the page HTML for deeper
    analysis.  Returns a risk score (0–100) with explanations.
    """
    return await _scan_single(request.url, request.fetch_html)


@router.post("/scan-html", response_model=ScanResult, tags=["Scanning"])
async def scan_html(request: ScanHTMLRequest) -> ScanResult:
    """
    Analyse a URL + raw HTML for phishing without making any HTTP requests.

    Useful for browser extension integrations that can supply the current
    page's HTML directly.
    """
    start = time.monotonic()
    model = PhishingModel.get_instance()

    try:
        url_feat_dict = extract_url_features(request.url, fetch_domain_age=False)
        html_feat_dict = extract_html_features(request.url, request.html)

        probability, is_phishing = model.predict(url_feat_dict, html_feat_dict)
        risk_score = compute_risk_score(probability)
        risk_level = get_risk_level(risk_score)
        explanations = build_explanations(url_feat_dict, html_feat_dict)

        elapsed = (time.monotonic() - start) * 1000
        return ScanResult(
            url=request.url,
            risk_score=risk_score,
            risk_level=risk_level,
            is_phishing=is_phishing,
            confidence=round(abs(probability - 0.5) * 2, 4),
            phishing_probability=round(probability, 4),
            url_features=URLFeatures(**url_feat_dict),
            html_features=HTMLFeatures(**html_feat_dict),
            explanations=explanations,
            scan_duration_ms=round(elapsed, 2),
        )
    except Exception as exc:
        logger.exception("Error in scan-html for URL %s", request.url)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/batch-scan", response_model=BatchScanResult, tags=["Scanning"])
async def batch_scan(request: BatchScanRequest) -> BatchScanResult:
    """
    Scan multiple URLs concurrently.

    Limited to 50 URLs per request.  Set ``fetch_html=false`` for fastest
    results (URL-only analysis).
    """
    if not request.urls:
        raise HTTPException(status_code=400, detail="No URLs provided.")

    start = time.monotonic()

    tasks = [_scan_single(url, request.fetch_html) for url in request.urls]
    results = await asyncio.gather(*tasks)

    elapsed = (time.monotonic() - start) * 1000
    phishing_count = sum(1 for r in results if r.is_phishing)

    return BatchScanResult(
        results=list(results),
        total_scanned=len(results),
        phishing_count=phishing_count,
        scan_duration_ms=round(elapsed, 2),
    )
