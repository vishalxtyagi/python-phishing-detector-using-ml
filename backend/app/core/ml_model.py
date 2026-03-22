"""
ML model wrapper for phishing detection.

Loads a pre-trained XGBoost model (or falls back to a heuristic scorer)
and provides a predict() method that returns a phishing probability.

The model is trained by ml/train.py.  If no model file exists at startup
the module falls back to rule-based scoring so the API still works.
"""
import os
import logging
import pickle
from typing import Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

MODEL_PATH = os.environ.get(
    "MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "ml", "model.pkl"),
)

# Feature names – must match the order produced by
# url_features_to_ml_vector() + html_features_to_ml_vector()
URL_FEATURE_NAMES = [
    "url_length", "entropy", "special_char_count", "subdomain_count",
    "has_https", "has_ip_address", "has_at_symbol", "has_double_slash",
    "has_prefix_suffix", "uses_shortener", "domain_age_days",
    "registration_length_days", "has_suspicious_tld", "digit_ratio", "url_depth",
]
HTML_FEATURE_NAMES = [
    "has_password_field", "form_count", "external_form_actions",
    "iframe_count", "hidden_element_count", "external_link_ratio",
    "redirect_count", "has_suspicious_scripts", "has_favicon",
    "title_brand_mismatch",
]
ALL_FEATURE_NAMES = URL_FEATURE_NAMES + HTML_FEATURE_NAMES


class PhishingModel:
    """Singleton wrapper around the XGBoost phishing classifier."""

    _instance: Optional["PhishingModel"] = None

    def __init__(self):
        self._model = None
        self._load_model()

    @classmethod
    def get_instance(cls) -> "PhishingModel":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_model(self):
        model_path = os.path.abspath(MODEL_PATH)
        if os.path.exists(model_path):
            try:
                with open(model_path, "rb") as f:
                    self._model = pickle.load(f)
                logger.info("Phishing model loaded from %s", model_path)
                return
            except Exception as exc:
                logger.warning("Could not load model from %s: %s", model_path, exc)
        logger.warning(
            "No model file found at %s – using heuristic fallback.", model_path
        )

    def predict(
        self,
        url_features: dict,
        html_features: Optional[dict] = None,
    ) -> Tuple[float, bool]:
        """
        Predict phishing probability for a URL.

        Returns:
            (probability, is_phishing) where probability is in [0, 1].
        """
        if html_features is None:
            html_features = {}

        if self._model is not None:
            return self._predict_with_model(url_features, html_features)
        return self._heuristic_predict(url_features, html_features)

    def _predict_with_model(
        self, url_features: dict, html_features: dict
    ) -> Tuple[float, bool]:
        """Use the loaded XGBoost model."""
        from .url_analyzer import url_features_to_ml_vector
        from .html_analyzer import html_features_to_ml_vector

        url_vec = url_features_to_ml_vector(url_features)
        html_vec = html_features_to_ml_vector(html_features) if html_features else [0] * len(HTML_FEATURE_NAMES)
        feature_vec = np.array([url_vec + html_vec])

        try:
            proba = float(self._model.predict_proba(feature_vec)[0][1])
        except AttributeError:
            # Model without predict_proba (e.g. plain classifier)
            pred = int(self._model.predict(feature_vec)[0])
            proba = 1.0 if pred == 1 else 0.0

        return proba, proba >= 0.5

    def _heuristic_predict(
        self, url_features: dict, html_features: dict
    ) -> Tuple[float, bool]:
        """
        Rule-based heuristic fallback when no ML model is available.

        Combines several weighted signals into a probability estimate.
        """
        score = 0.0
        max_score = 0.0

        def add(weight: float, condition: bool):
            nonlocal score, max_score
            max_score += weight
            if condition:
                score += weight

        # URL signals
        add(0.15, url_features.get("has_ip_address", False))
        add(0.10, url_features.get("has_at_symbol", False))
        add(0.08, url_features.get("has_double_slash", False))
        add(0.07, url_features.get("has_prefix_suffix", False))
        add(0.12, url_features.get("uses_shortener", False))
        add(0.08, url_features.get("has_suspicious_tld", False))
        add(0.06, url_features.get("url_length", 0) > 75)
        add(0.05, url_features.get("subdomain_count", 0) > 2)
        add(0.05, url_features.get("entropy", 0) > 4.5)
        add(0.04, not url_features.get("has_https", True))
        age = url_features.get("domain_age_days")
        add(0.10, age is not None and age < 30)

        # HTML signals
        add(0.12, html_features.get("title_brand_mismatch", False))
        add(0.08, html_features.get("external_form_actions", 0) > 0)
        add(0.06, html_features.get("iframe_count", 0) > 0)
        add(0.05, html_features.get("has_suspicious_scripts", False))
        add(0.04, html_features.get("external_link_ratio", 0) > 0.7)

        probability = score / max_score if max_score > 0 else 0.0
        return probability, probability >= 0.5
