from urllib.parse import urlparse
import ipaddress
import re


# Suspicious keywords
SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "password",
    "account",
    "banking",
    "secure",
    "signin",
    "wallet",
    "confirm"
]


# Known URL shortening services
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly"
}


# Main URL analysis function
def analyze_url(raw_url):

    url = raw_url.strip()

    # Check empty or excessively long URL
    if not url or len(url) > 2048:

        return {
            "score": 0,
            "status": "Invalid URL",
            "reasons": ["Enter a valid URL."]
        }

    # Check invalid control characters
    if any(ord(char) < 32 for char in url):

        return {
            "score": 0,
            "status": "Invalid URL",
            "reasons": [
                "URL contains invalid characters."
            ]
        }

    # Add HTTPS if scheme is missing
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    # Parse URL
    try:

        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname or not parsed.netloc:
            raise ValueError("Invalid hostname")

        # Reject embedded credentials
        if parsed.username or parsed.password:
            raise ValueError("Embedded credentials")

        host = hostname.lower().rstrip(".")

        # Basic domain validation
        if not host or "." not in host:
            raise ValueError("Invalid domain")

    except ValueError:

        return {
            "score": 0,
            "status": "Invalid URL",
            "reasons": [
                "The URL format is invalid or contains embedded credentials."
            ]
        }

    # Initialize risk score
    score = 0
    reasons = []

    # Function to add risk points
    def flag(points, message):

        nonlocal score

        score += points
        reasons.append(message)

    # 1. Check HTTPS
    if parsed.scheme.lower() != "https":

        flag(
            15,
            "The URL does not use HTTPS."
        )

    # 2. Check IP address instead of domain
    try:

        ipaddress.ip_address(host)

        flag(
            30,
            "The website uses an IP address instead of a domain."
        )

    except ValueError:
        pass

    # 3. Check punycode domains
    if "xn--" in host:

        flag(
            25,
            "The domain contains encoded international characters."
        )

    # 4. Check excessive subdomains
    if len(host.split(".")) > 4:

        flag(
            15,
            "The URL contains an unusually large number of subdomains."
        )

    # 5. Check suspicious keywords
    for word in SUSPICIOUS_WORDS:

        if word in url.lower():

            flag(
                5,
                f"Suspicious keyword detected: {word}"
            )

            break

    # 6. Check URL shortening services
    if host in SHORTENERS:

        flag(
            20,
            "The URL uses a link-shortening service."
        )

    # 7. Check unusual URL length
    if len(url) > 100:

        flag(
            10,
            "The URL is unusually long."
        )

    # 8. Check multiple hyphens in domain
    if host.count("-") >= 3:

        flag(
            10,
            "The domain contains many hyphens."
        )

    # Calculate final risk score
    score = min(score, 100)

    # Determine risk status
    if score >= 50:

        status = "High Risk"

    elif score >= 20:

        status = "Suspicious"

    else:

        status = "Low Risk"

    # Default observation
    if not reasons:

        reasons.append(
            "No suspicious patterns were detected by these checks."
        )

    # Return analysis results
    return {
        "score": score,
        "status": status,
        "reasons": reasons
    }