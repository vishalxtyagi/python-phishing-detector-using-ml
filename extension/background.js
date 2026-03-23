/* background.js – service worker for the Chrome extension */

/**
 * Listen for GET_HTML messages from the popup.
 * We inject a content script that returns the full page HTML,
 * then forward it back to the popup.
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type !== "GET_HTML") return false;

  chrome.scripting.executeScript(
    {
      target: { tabId: msg.tabId },
      func: () => document.documentElement.outerHTML,
    },
    (results) => {
      if (chrome.runtime.lastError || !results || !results[0]) {
        sendResponse(null);
      } else {
        sendResponse(results[0].result);
      }
    }
  );

  // Return true to keep the message channel open for async sendResponse
  return true;
});
