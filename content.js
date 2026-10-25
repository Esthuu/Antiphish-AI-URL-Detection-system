(function () {

  const url = window.location.href;
  const hostname = window.location.hostname.toLowerCase();
  let score = 0;
  let reasons = [];

  // Rule 1: IP address
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 3;
    reasons.push("IP address used instead of domain name");
  }

  // Rule 2: Long URL
  if (url.length > 100) {
    score += 1;
    reasons.push("Unusually long URL");
  }

  // Rule 3: No HTTPS
  if (!url.startsWith("https://")) {
    score += 2;
    reasons.push("Website does not use HTTPS");
  }

  // Rule 4: @ symbol
  if (url.indexOf("@") !== -1) {
    score += 3;
    reasons.push("URL contains '@' symbol");
  }

  // Rule 5: Too many subdomains
  if (hostname.split(".").length > 4) {
    score += 1;
    reasons.push("Excessive number of subdomains");
  }

  // Rule 6: Hyphen
  if (hostname.indexOf("-") !== -1) {
    score += 1;
    reasons.push("Hyphenated domain name detected");
  }

  // Rule 7: Suspicious keywords
  const suspiciousKeywords = [
    "login", "verify", "update", "secure",
    "account", "confirm", "signin",
    "password", "reset", "bank"
  ];

  suspiciousKeywords.forEach(function (word) {
    if (url.toLowerCase().indexOf(word) !== -1) {
      score += 1;
      reasons.push("Suspicious keyword detected: " + word);
    }
  });

  // Rule 8: Risky TLDs
  const riskyTLDs = [".tk", ".ml", ".ga", ".cf", ".gq"];
  riskyTLDs.forEach(function (tld) {
    if (hostname.endsWith(tld)) {
      score += 2;
      reasons.push("High-risk top-level domain detected");
    }
  });

  // Rule 9: Password field
  if (document.querySelector("input[type='password']")) {
    score += 2;
    reasons.push("Password input field detected");
  }

  // Rule 10: External form action
  document.querySelectorAll("form").forEach(function (form) {
    if (form.action && form.action.indexOf(hostname) === -1) {
      score += 2;
      reasons.push("Form submits data to external domain");
    }
  });

  // Rule 11: Hidden iframe
  document.querySelectorAll("iframe").forEach(function (frame) {
    const style = window.getComputedStyle(frame);
    if (style.display === "none" || frame.width === "0" || frame.height === "0") {
      score += 1;
      reasons.push("Hidden iframe detected");
    }
  });

  // Rule 12: Missing favicon
  if (!document.querySelector("link[rel~='icon']")) {
    score += 1;
    reasons.push("Website does not contain a favicon");
  }

  // Trusted domains
  const trustedDomains = ["google.com", "github.com", "microsoft.com", "apple.com", "openai.com"];
  trustedDomains.forEach(function (domain) {
    if (hostname.endsWith(domain)) {
      score = Math.max(score - 3, 0);
    }
  });

  // Risk level
  let riskLevel = "LOW";
  if (score >= 8) riskLevel = "HIGH";
  else if (score >= 4) riskLevel = "MEDIUM";

  // Banner
  const banner = document.createElement("div");
  banner.style.position = "fixed";
  banner.style.top = "0";
  banner.style.left = "0";
  banner.style.width = "100%";
  banner.style.padding = "12px";
  banner.style.fontSize = "15px";
  banner.style.fontWeight = "bold";
  banner.style.zIndex = "99999";
  banner.style.textAlign = "center";
  banner.style.color = "white";

  banner.style.backgroundColor =
    riskLevel === "HIGH" ? "#b71c1c" :
    riskLevel === "MEDIUM" ? "#f57f17" :
    "#2e7d32";

  banner.innerHTML =
    "Phishing Risk Level: " + riskLevel +
    "<br><small>" + reasons.join(" | ") + "</small>";

  document.body.prepend(banner);

})();
