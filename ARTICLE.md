# I Built a Real-Time Phishing Detector with XGBoost and a Chrome Extension — Here's What I Learned

> *Cross-posted on dev.to and LinkedIn. 5-minute read.*

---

## The Problem That Keeps Me Up at Night

Every 39 seconds, a phishing attack succeeds somewhere on the planet.

Banks lose millions. People lose savings. And the scariest part? **Most victims consider themselves tech-savvy.** The difference between a legitimate PayPal page and a convincing fake is often just a hyphen in the domain name — `paypal-secure-login.tk` vs `paypal.com`.

I wanted to build something that would catch that hyphen *before* you typed your password.

---

## What I Built

**PhishGuard** — a real-time phishing detection system with three layers:

```
🌐 Chrome Extension  →  ⚡ FastAPI Backend  →  🤖 XGBoost Model
  (scans every tab)       (< 50 ms API)       (97% accuracy)
```

When you visit any page, the extension silently:
1. Captures the full page HTML
2. Sends it to the local API
3. Gets back a risk score (0–100)
4. Displays a colour-coded badge with a plain-English explanation

No black-box "blocked" messages. Just *why* a URL is dangerous.

---

## The Architecture (Plain English)

Here's the entire system on a napkin:

```
User opens tab
    ↓
Extension grabs HTML via Chrome's scripting API
    ↓
POST { url, html } → FastAPI backend
    ↓
Extract 25 features:
  • 15 from the URL alone (fast, no network needed)
  • 10 from the page HTML
    ↓
XGBoost predicts P(phishing)
    ↓
Risk score (0–100) + human-readable explanations
    ↓
Badge: 🟢 Safe / 🟡 Suspicious / 🔴 Phishing
```

The whole round-trip: **~12 ms for URL-only, ~80 ms with HTML analysis.**

---

## The 25 Features That Matter

I spent a lot of time curating features from the [UCI Phishing Websites dataset](https://archive.ics.uci.edu/ml/datasets/Phishing+Websites) (11,055 labelled URLs).

**The features that carry the most weight:**

| Feature | Why it matters |
|---------|---------------|
| IP address in hostname | `http://192.168.1.1/paypal` — legitimate sites use domain names |
| `@` symbol in URL | Browser ignores everything *before* `@`, so `paypal.com@evil.com` lands on `evil.com` |
| URL shortener used | `bit.ly/abc` obscures the real destination — classic phishing trick |
| Brand name in title but not domain | Page says "PayPal Login" but domain is `paypal-secure.tk` |
| External form action | Form submits your password to a *different* domain |
| Newly registered domain | Phishing sites are typically < 30 days old |
| Suspicious TLD | `.tk`, `.ml`, `.ga`, `.cf` — free domains favoured by attackers |

**Shannon entropy** was a surprise — randomly generated domains like `xn--kcry6tjko.com` have measurably higher entropy than legitimate ones.

---

## Why XGBoost?

I evaluated three approaches:

| Approach | Accuracy | Latency | Explainability |
|----------|----------|---------|----------------|
| Rule-based only | ~82% | ~1 ms | ✅ Full |
| Random Forest | ~95% | ~15 ms | Partial |
| **XGBoost** | **~97%** | **~10 ms** | ✅ Via SHAP |

XGBoost won because it:
- Handles missing values (domain age WHOIS can fail) gracefully
- Trains in under 2 minutes on 11k samples
- Produces calibrated probabilities (essential for a 0–100 score)

I also built a **heuristic fallback** — if no model file is present, the system still works using a weighted sum of high-signal features. You can use the API right away, train the model later.

---

## The Chrome Extension: MV3 Was Tricky

Chrome's Manifest v3 migration removed a lot of tricks. The key challenge: **how do you get the full page HTML from a service worker** (which has no DOM access)?

The solution:

```javascript
// background.js (service worker)
chrome.scripting.executeScript(
  { target: { tabId: msg.tabId }, func: () => document.documentElement.outerHTML },
  (results) => sendResponse(results[0].result)
);
```

The `scripting.executeScript` API injects a tiny function into the page's context, grabs the HTML, and returns it to the service worker — which then fires the API call. Clean, fast, no content script gymnastics needed.

---

## What a "Risk Score 87" Actually Means

This was the feature I cared most about. Saying "this is phishing" isn't useful if users don't understand why.

Every scan returns a sorted list of explanations:

```
🔴 Brand Name Mismatch
   "The page title says PayPal but the domain is paypal-login.tk"

🔴 External Form Action  
   "Your password would be sent to evil-collector.ru"

🟡 Suspicious TLD (.tk)
   "Free domains favoured by phishers"

🟡 Hyphen in Domain
   "Legitimate PayPal uses paypal.com, not paypal-login.tk"
```

Non-technical users immediately understand *why* to be suspicious. That's the whole point.

---

## The Numbers

| Metric | Value |
|--------|-------|
| Training samples | 11,055 URLs |
| Test accuracy | ~97% |
| False positive rate | ~3% |
| API latency (URL-only) | ~12 ms |
| API latency (with HTML) | ~80 ms |
| Batch scan (50 URLs) | ~350 ms |
| Feature count | 25 |
| Lines of tested code | ~800 |

---

## What I'd Do Differently

**1. Add a feedback loop**  
Users should be able to mark a result as wrong. Over time, this builds a fine-tuning dataset specific to newer phishing patterns.

**2. HTTPS isn't a safety signal anymore**  
60%+ of phishing sites now use HTTPS. I included it as a feature but gave it low weight — the real signals are in the URL structure and HTML content.

**3. Real-time model updates**  
Phishing campaigns evolve weekly. Ideally, the model would be retrained on a rolling window of fresh data, not a static 2014 dataset.

---

## Try It Yourself

```bash
git clone https://github.com/vishalxtyagi/python-phishing-detector-using-ml
cd python-phishing-detector-using-ml
docker-compose up --build

# Test it
curl -X POST http://localhost:8000/api/v1/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure-login.tk/account", "fetch_html": false}'
```

Then load the `extension/` folder as an unpacked Chrome extension.

---

## Final Thoughts

The most important lesson: **explainability beats accuracy** in security tools.

A 97% accurate black box won't change user behaviour. A 92% accurate system that clearly explains *"this form submits your password to Russia"* will.

Build for humans first.

---

*If you found this useful, ⭐ the repo and share it with someone who clicks links too fast.*

---

**Tags:** `#Python` `#MachineLearning` `#XGBoost` `#FastAPI` `#Security` `#ChromeExtension` `#OpenSource` `#CyberSecurity` `#WebDev`
