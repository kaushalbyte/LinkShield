function analyzeSecurity(url) {
    const warnings = [];
    let score = 0;
     if (url.protocol !== "https:") {
        warnings.push("This URL does not use HTTPS.");
        score += 15;
    }
   const ipPattern =
        /^(\d{1,3}\.){3}\d{1,3}$/;
if (ipPattern.test(url.hostname)) {
    warnings.push("This URL uses an IP address instead of a domain name.");
    score += 25;
}
    const suspiciousWords = [
        "verify-account",
        "reset-password",
        "urgent-login",
        "confirm-identity"
    ];
        const urlText =
        (url.pathname + url.search).toLowerCase();

    const foundWords = suspiciousWords.filter(function(word) {
        return urlText.includes(word);
    });
      if (foundWords.length > 0) {
        score += 20;
        warnings.push(
            "Potentially suspicious wording: " +
            foundWords.join(", ")
            
        );
    }
     if (url.href.length > 150) {
        warnings.push("This URL is unusually long.");
        score += 10;
    }
    const hostnameParts = url.hostname.split(".");

    if (hostnameParts.length > 4) {
        warnings.push("This URL contains many hostname labels.");
        score += 10;
    }

    return{
        warnings: warnings,
        score:Math.min(score, 100)
    };
}