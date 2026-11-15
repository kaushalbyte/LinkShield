const urlInput = document.getElementById("urlInput");
const scanbtn = document.getElementById("scanbtn");
const apiStatus = document.getElementById("apiStatus");
const googleAttribution = document.getElementById("googleAttribution");
const apiBaseURL = (document.querySelector('meta[name="api-base-url"]')?.content || "")
  .trim().replace(/\/+$/, "");
let latestRequest = 0;
let activeController;
let resultExpiryTimer;

document.getElementById("urlForm").addEventListener("submit", event => {
  event.preventDefault();
  scanbtn.click();
});

scanbtn.addEventListener("click", async () => {
  const requestId = ++latestRequest;
  activeController?.abort();
  clearTimeout(resultExpiryTimer);
  document.getElementById("result").hidden = true;
  googleAttribution.hidden = true;
  apiStatus.textContent = "";
  const userurl = urlInput.value.trim();
  if (userurl == "") {
    alert("Please enter a URL to check.");
    return;
  }

  let url;
  try {
    url = new URL(userurl);
  } catch {
    alert("Invalid URL! Please enter a complete URL.");
    return;
  }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
      alert("Only HTTP and HTTPS URLs are supported!");
      return;
    }
    if (userurl.length > 4096 || url.username || url.password) {
      alert("Use a URL of 4096 characters or fewer without an embedded username or password.");
      return;
    }

    const result = analyzeSecurity(url);
    showResult(url, result);

    console.log("Risk Score:", result.score);
    console.log("Security Warnings:", result.warnings);
    const warnings = result.warnings;

    console.log("Security warnings:", warnings);

    if (warnings.length === 0) {
      console.log("No heuristic warnings detected.");
    } else {
      warnings.forEach(function (warning, index) {
        console.log(`${index + 1}. ${warning}`);
      });
    }
  apiStatus.textContent = "Checking Google Safe Browsing... The free server may take a minute to wake up.";
  const controller = new AbortController();
  activeController = controller;
  const timeout = setTimeout(() => controller.abort(), 90000);

  try {
    const response = await fetch(`${apiBaseURL}/api/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url.href }),
      signal: controller.signal,
    });
    if (requestId !== latestRequest) return;
    if (!response.ok) {
      if (response.status === 400) throw new Error("INVALID_URL");
      if (response.status === 413) throw new Error("TOO_LARGE");
      if (response.status === 429) throw new Error("RATE_LIMITED");
      if (response.status === 403 || response.status === 404) throw new Error("BACKEND_CONFIG");
      throw new Error("THREAT_SERVICE");
    }
    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("BACKEND_RESPONSE");
    }
    if (requestId !== latestRequest) return;
    if (!data || data.success !== true || data.url !== url.href ||
        typeof data.isThreat !== "boolean" || !Array.isArray(data.threats) ||
        data.isThreat !== (data.threats.length > 0) || !Number.isFinite(data.expiresAt)) {
      throw new Error("BACKEND_RESPONSE");
    }

    const expireResult = () => {
      if (requestId !== latestRequest) return;
      apiStatus.textContent = "Database result expired. Scan again for an up-to-date check.";
      googleAttribution.hidden = true;
      document.getElementById("resultTitle").textContent = "";
      document.getElementById("resultIcon").textContent = result.score >= 30 ? "!" : "✓";
    };
    if (data.expiresAt <= Date.now()) {
      expireResult();
      return;
    }
    if (data.isThreat) {
      apiStatus.textContent = "Google Safe Browsing flagged this URL as potentially harmful. Its information may be incomplete or incorrect.";
      document.getElementById("resultTitle").textContent = "Potential Threat Reported";
      document.getElementById("resultIcon").textContent = "!";
      googleAttribution.hidden = false;
    } else {
      apiStatus.textContent = "Google Safe Browsing: No known threat match found. Safety is not guaranteed.";
    }
    resultExpiryTimer = setTimeout(expireResult, Math.min(data.expiresAt - Date.now(), 1800000));
  } catch (error) {
    if (requestId !== latestRequest) return;
    const messages = {
      INVALID_URL: "The backend rejected this URL. Check its format.",
      TOO_LARGE: "The request is too large. Use a shorter URL.",
      RATE_LIMITED: "Too many scans. Wait a minute before trying again.",
      BACKEND_CONFIG: "Backend configuration error. The database check is unavailable.",
      BACKEND_RESPONSE: "The backend returned an invalid response. The database check is unavailable.",
      THREAT_SERVICE: "The external threat service is unavailable. No database verdict was received.",
    };
    apiStatus.textContent = (error.name === "AbortError"
      ? "The database check timed out. Please try again."
      : messages[error.message] || "Cannot connect to the backend. Check your connection and try again.") +
      " Only local checks completed.";
  } finally {
    clearTimeout(timeout);
    if (requestId === latestRequest) activeController = undefined;
  }
});
function showResult(url, result) {
  const resultBox = document.getElementById("result");
  const resultIcon = document.getElementById("resultIcon");
  const resultTitle = document.getElementById("resultTitle");
  const resultURL = document.getElementById("resultURL");
  const riskScore = document.getElementById("riskScore");
  const warningList = document.getElementById("warningList");
  const lowRisk = document.getElementById("low-Risk");
  const moderateRisk = document.getElementById("moderate-Risk");
  const highRisk = document.getElementById("high-Risk");

  lowRisk.style.visibility = "hidden";
  moderateRisk.style.visibility = "hidden";
  highRisk.style.visibility = "hidden";
  resultTitle.textContent = "";

  resultURL.textContent = url.href;
  riskScore.textContent = `Risk Score: ${result.score}/100`;
  warningList.innerHTML = "";
  result.warnings.forEach(function (warning) {
    const li = document.createElement("li");
    li.textContent = warning;
    warningList.appendChild(li);
  });
  if (result.score >= 60) {
    highRisk.style.visibility = "visible";

    resultIcon.textContent = "!";
  } else if (result.score >= 30) {
    moderateRisk.style.visibility = "visible";
    resultIcon.textContent = "!";
  } else {
    lowRisk.style.visibility = "visible";
    resultIcon.textContent = "✓";
  }
  if (result.warnings.length === 0) {
    const li = document.createElement("li");
    li.textContent =
      "No heuristic warnings detected. Safety is not guaranteed.";
    warningList.appendChild(li);
  }

  resultBox.hidden = false;
}
