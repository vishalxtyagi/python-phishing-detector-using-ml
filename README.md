# Phishing Website Detector

A production-grade real-time phishing detection system built with FastAPI, XGBoost, and a Chrome Extension.

---

## Architecture

```
python-phishing-detector-using-ml/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application entry point
│   │   ├── api/routes.py        # API endpoints
│   │   ├── core/
│   │   │   ├── url_analyzer.py  # URL feature extraction
│   │   │   ├── html_analyzer.py # HTML feature extraction
│   │   │   ├── ml_model.py      # XGBoost model wrapper + heuristic fallback
│   │   │   └── scorer.py        # Risk scoring & explanations
│   │   └── models/schemas.py    # Pydantic request/response models
│   ├── ml/
│   │   └── train.py             # Model training script
│   ├── tests/
│   │   └── test_phishing_detector.py
│   ├── requirements.txt
│   └── Dockerfile
├── extension/                   # Chrome Extension (Manifest v3)
│   ├── manifest.json
│   ├── popup.html / popup.js
│   ├── background.js
│   └── content.js
├── docker-compose.yml
└── Training Dataset.arff        # Original training data
```

---

## Features

- **URL Analysis** – length, entropy, special characters, subdomain count, HTTPS, IP address, shorteners, suspicious TLDs, domain age
- **HTML Analysis** – password fields, external form actions, iFrames, hidden elements, external link ratio, redirects, suspicious JS, brand mismatch
- **Machine Learning** – XGBoost classifier with heuristic fallback when no model is trained
- **Risk Scoring** – 0–100 score with human-readable explanations sorted by severity
- **Async API** – concurrent scans, fast response times
- **Chrome Extension** – scans the current tab and shows a risk badge

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/health` | Health check |
| `POST` | `/api/v1/scan-url` | Scan a URL (optionally fetches HTML) |
| `POST` | `/api/v1/scan-html` | Scan URL + raw HTML (no outbound request) |
| `POST` | `/api/v1/batch-scan` | Scan up to 50 URLs concurrently |

Interactive docs: `http://localhost:8000/docs`

---

## Quick Start

### Option 1 – Docker Compose (recommended)

```bash
docker-compose up --build
```

API will be available at `http://localhost:8000`.

### Option 2 – Local development

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Train the ML model (optional but recommended)

```bash
cd backend
python ml/train.py
# Model saved to backend/ml/model.pkl
# Restart the API to pick up the new model.
```

---

## Chrome Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `extension/` folder
4. Make sure the API is running at `http://localhost:8000`
5. Click the shield icon on any page to see its risk score

> To point the extension at a remote API, click **configure** in the popup and enter the URL.

---

## API Usage Examples

**Scan a URL:**
```bash
curl -X POST http://localhost:8000/api/v1/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-login.tk/secure", "fetch_html": true}'
```

**Batch scan:**
```bash
curl -X POST http://localhost:8000/api/v1/batch-scan \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://google.com", "http://bit.ly/phish"], "fetch_html": false}'
```

**Response example:**
```json
{
  "url": "http://paypal-login.tk/secure",
  "risk_score": 82,
  "risk_level": "phishing",
  "is_phishing": true,
  "confidence": 0.64,
  "phishing_probability": 0.82,
  "explanations": [
    {"factor": "Suspicious Top-Level Domain", "severity": "medium", "description": "..."},
    {"factor": "Hyphen in Domain", "severity": "medium", "description": "..."}
  ]
}
```

---

## Running Tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_PATH` | `backend/ml/model.pkl` | Path to trained XGBoost model |
| `ALLOWED_ORIGINS` | `*` | Comma-separated CORS origins |
