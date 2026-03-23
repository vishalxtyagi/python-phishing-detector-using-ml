/* popup.js – drives the extension popup UI */
const DEFAULT_API = "http://localhost:8000";

const $loading    = document.getElementById("loading");
const $error      = document.getElementById("error-msg");
const $result     = document.getElementById("result");
const $statusBar  = document.getElementById("status-bar");
const $circle     = document.getElementById("score-circle");
const $label      = document.getElementById("risk-label");
const $list       = document.getElementById("explanations");
const $toggleApi  = document.getElementById("toggle-api");
const $apiInput   = document.getElementById("api-url-input");

// ---- API URL settings -------------------------------------------------------
chrome.storage.local.get(["apiUrl"], ({ apiUrl }) => {
  $apiInput.value = apiUrl || DEFAULT_API;
});

$toggleApi.addEventListener("click", () => {
  const visible = $apiInput.style.display === "block";
  $apiInput.style.display = visible ? "none" : "block";
  if (visible) {
    // Save when hiding
    chrome.storage.local.set({ apiUrl: $apiInput.value.trim() || DEFAULT_API });
  }
});

// ---- Main scan --------------------------------------------------------------
function getApiUrl(cb) {
  chrome.storage.local.get(["apiUrl"], ({ apiUrl }) => cb(apiUrl || DEFAULT_API));
}

function showError(msg) {
  $loading.style.display = "none";
  $result.style.display  = "none";
  $error.style.display   = "block";
  $error.textContent     = msg;
}

function showResult(data) {
  $loading.style.display = "none";
  $error.style.display   = "none";
  $result.style.display  = "block";

  const score = data.risk_score;
  $circle.textContent = score;

  // Colour the circle
  if (score < 30) {
    $circle.style.borderColor = "#198754";
    $circle.style.color       = "#198754";
  } else if (score < 65) {
    $circle.style.borderColor = "#fd7e14";
    $circle.style.color       = "#fd7e14";
  } else {
    $circle.style.borderColor = "#dc3545";
    $circle.style.color       = "#dc3545";
  }

  const levelMap = { safe: "✅ Safe", suspicious: "⚠️ Suspicious", phishing: "🚨 Phishing" };
  $label.textContent = levelMap[data.risk_level] || data.risk_level;

  $list.innerHTML = "";
  (data.explanations || []).forEach(({ factor, severity, description }) => {
    const li = document.createElement("li");
    li.className = `sev-${severity}`;
    li.innerHTML = `<strong>${factor}</strong><br>${description}`;
    $list.appendChild(li);
  });

  if (!data.explanations || data.explanations.length === 0) {
    const li = document.createElement("li");
    li.className = "sev-low";
    li.textContent = "No suspicious signals detected.";
    $list.appendChild(li);
  }
}

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (!tab || !tab.url) { showError("Cannot access current tab URL."); return; }

  const url = tab.url;
  $statusBar.textContent = url;

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    showError("Only HTTP/HTTPS pages can be scanned.");
    return;
  }

  // Ask background to get the page HTML (avoids CORS issues)
  chrome.runtime.sendMessage({ type: "GET_HTML", tabId: tab.id }, (html) => {
    getApiUrl((apiBase) => {
      const endpoint = html
        ? `${apiBase}/api/v1/scan-html`
        : `${apiBase}/api/v1/scan-url`;

      const body = html
        ? JSON.stringify({ url, html })
        : JSON.stringify({ url, fetch_html: false });

      fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
      })
        .then((r) => r.json())
        .then(showResult)
        .catch((err) => showError(`API error: ${err.message}`));
    });
  });
});
