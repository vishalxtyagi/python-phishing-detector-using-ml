"""Pydantic models for API request/response validation."""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, HttpUrl, Field


class ScanURLRequest(BaseModel):
    url: str = Field(..., description="URL to scan for phishing",
                     json_schema_extra={"example": "https://example.com"})
    fetch_html: bool = Field(
        default=True,
        description="Whether to fetch and analyze the page HTML"
    )


class ScanHTMLRequest(BaseModel):
    url: str = Field(..., description="URL the HTML was fetched from")
    html: str = Field(..., description="Raw HTML content to analyze")


class BatchScanRequest(BaseModel):
    urls: List[str] = Field(
        ...,
        description="List of URLs to scan",
        max_length=50
    )
    fetch_html: bool = Field(
        default=False,
        description="Whether to fetch and analyze HTML for each URL (slower)"
    )


class URLFeatures(BaseModel):
    url_length: int
    entropy: float
    special_char_count: int
    subdomain_count: int
    has_https: bool
    has_ip_address: bool
    has_at_symbol: bool
    has_double_slash: bool
    has_prefix_suffix: bool
    uses_shortener: bool
    domain_age_days: Optional[int] = None
    registration_length_days: Optional[int] = None
    has_suspicious_tld: bool
    digit_ratio: float
    url_depth: int


class HTMLFeatures(BaseModel):
    has_password_field: bool
    form_count: int
    external_form_actions: int
    iframe_count: int
    hidden_element_count: int
    external_link_ratio: float
    redirect_count: int
    has_suspicious_scripts: bool
    has_favicon: bool
    title_brand_mismatch: bool


class RiskExplanation(BaseModel):
    factor: str
    severity: str  # "high", "medium", "low"
    description: str


class ScanResult(BaseModel):
    url: str
    risk_score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    risk_level: str = Field(..., description="'safe', 'suspicious', or 'phishing'")
    is_phishing: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    phishing_probability: float = Field(..., ge=0.0, le=1.0)
    url_features: Optional[URLFeatures] = None
    html_features: Optional[HTMLFeatures] = None
    explanations: List[RiskExplanation] = []
    scan_duration_ms: Optional[float] = None
    error: Optional[str] = None


class BatchScanResult(BaseModel):
    results: List[ScanResult]
    total_scanned: int
    phishing_count: int
    scan_duration_ms: float
