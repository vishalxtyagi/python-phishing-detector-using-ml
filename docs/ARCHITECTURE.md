# 🏗️ PhishGuard — Architecture Deep Dive

This document provides a detailed technical view of every component in the system.

---

## Component Diagram

```mermaid
C4Context
  title PhishGuard — System Context

  Person(user, "End User", "Browses the web using Chrome")
  Person(dev, "Developer", "Integrates PhishGuard API into apps")

  System(ext, "Chrome Extension", "Scans every page visited,\nshows a risk badge")
  System(api, "FastAPI Backend", "Stateless REST API,\nextracts features & scores URLs")

  System_Ext(arff, "UCI Dataset", "11,055 labelled phishing URLs\n(offline training only)")

  Rel(user, ext, "Sees risk badge")
  Rel(dev, api, "POST /scan-url", "HTTPS/JSON")
  Rel(ext, api, "POST /scan-html", "localhost:8000")
  Rel(arff, api, "train.py → model.pkl", "offline")
```

---

## Data Flow — Single URL Scan

```mermaid
sequenceDiagram
    autonumber
    participant C  as Chrome Extension
    participant BG as background.js
    participant API as FastAPI /scan-html
    participant UA  as url_analyzer
    participant HA  as html_analyzer
    participant ML  as XGBoost Model
    participant SC  as scorer

    C  ->> BG:  User opens tab
    BG ->> BG:  executeScript → capture outerHTML
    BG ->> API: POST { url, html }
    API ->> UA: extract_url_features(url)
    UA -->> API: 15 URL features
    API ->> HA: extract_html_features(url, html)
    HA -->> API: 10 HTML features
    API ->> ML: predict([25-feature vector])
    ML -->> API: probability (0.0 – 1.0)
    API ->> SC: compute_risk_score(probability)
    SC ->> SC: build_explanations(url_feats, html_feats)
    SC -->> API: { risk_score, risk_level, explanations }
    API -->> C:  ScanResult JSON
    C  ->> C:   Render colour-coded badge + explanations
```

---

## Feature Engineering

### URL Features (15)

```mermaid
mindmap
  root((URL Features))
    Structure
      url_length
      url_depth
      subdomain_count
    Content
      entropy
      digit_ratio
      special_char_count
    Indicators
      has_ip_address
      has_at_symbol
      has_double_slash
      has_prefix_suffix
      uses_shortener
    TLS / Security
      has_https
      has_suspicious_tld
    Domain
      domain_age_days
      registration_length_days
```

### HTML Features (10)

```mermaid
mindmap
  root((HTML Features))
    Forms
      has_password_field
      external_form_actions
    Navigation
      external_link_ratio
      has_redirects
    Obfuscation
      iframe_count
      hidden_element_count
      has_suspicious_scripts
    Identity
      title_brand_mismatch
      has_favicon
      right_click_disabled
```

---

## ML Model Pipeline

```mermaid
flowchart LR
    subgraph Offline["🏋️ Offline Training"]
        ARFF["Training Dataset.arff\n11,055 URLs"]
        SPLIT["80 / 20 split\nstratified"]
        XGB["XGBoost\n300 estimators\nmax_depth=6\nlr=0.1"]
        PKL["model.pkl"]
        ARFF --> SPLIT --> XGB --> PKL
    end

    subgraph Runtime["⚡ Runtime Inference"]
        VEC["25-feature vector\n[url + html]"]
        PRED["model.predict_proba()\n→ P(phishing)"]
        SCORE["Risk Score 0–100"]
        VEC --> PRED --> SCORE
    end

    PKL -.->|"loaded at startup"| PRED

    subgraph Fallback["🔄 Heuristic Fallback"]
        HF["Weighted sum of\nhigh-signal features\n(no model.pkl required)"]
    end

    PKL -.->|"missing"| HF
    HF --> SCORE
```

---

## Risk Score Thresholds

```mermaid
xychart-beta
    title "Risk Score Distribution by Category"
    x-axis ["Safe (0–29)", "Suspicious (30–64)", "Phishing (65–100)"]
    y-axis "% of URLs in dataset" 0 --> 60
    bar [42, 18, 40]
```

---

## Deployment Topology

```mermaid
flowchart TD
    subgraph Docker["🐳 docker-compose"]
        API["api container\npython:3.12-slim\nport 8000\n/health healthcheck"]
    end

    subgraph Client["Client Layer"]
        EXT["Chrome Extension"]
        CURL["curl / SDK"]
        WEB["Web App"]
    end

    EXT & CURL & WEB -->|"HTTP/JSON"| API

    style Docker fill:#2496ED,color:#fff
    style Client fill:#1E293B,color:#fff
```
