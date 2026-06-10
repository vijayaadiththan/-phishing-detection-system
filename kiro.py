#!/usr/bin/env python3
"""
Kiro: A Phishing Detection CLI Tool
Analyzes URLs to detect phishing and impersonation attempts.
"""

import sys
import re
from urllib.parse import urlparse, urlunparse
import requests
from typing import Tuple, List, Dict

# ANSI Color codes for terminal output
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

# Pre-scan whitelist of known, trusted domains
WHITELIST = {
    "google.com",
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "youtube.com",
    "linkedin.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "gmail.com",
    "outlook.com",
    "reddit.com",
    "pinterest.com",
}

# Known phishing URL shorteners
SUSPICIOUS_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "short.link",
    "ow.ly",
    "goo.gl",
    "tiny.cc",
}

# Common brands for homograph detection (typosquatting patterns)
BRAND_KEYWORDS = {
    "google",
    "facebook",
    "amazon",
    "apple",
    "microsoft",
    "netflix",
    "paypal",
    "bank",
    "ebay",
    "twitter",
    "linkedin",
    "instagram",
}


def print_banner() -> None:
    """Display the Kiro banner on startup."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════╗
║           KIRO v1.0               ║
║    Phishing Detection Tool        ║
╚═══════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)


def clean_url(url: str) -> str:
    """
    Clean and normalize URL input.
    Adds http:// if missing.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def is_ip_address(domain: str) -> bool:
    """
    Detect if the domain is an IP address instead of a domain name.
    Returns True if domain appears to be an IP address.
    """
    # Simple IPv4 pattern
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, domain):
        # Validate octets are 0-255
        octets = domain.split(".")
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    # IPv6 detection (simplified)
    if ":" in domain:
        return True
    
    return False


def is_suspicious_shortener(domain: str) -> bool:
    """
    Check if domain is a known suspicious URL shortener.
    """
    domain_lower = domain.lower()
    return any(shortener in domain_lower for shortener in SUSPICIOUS_SHORTENERS)


def detect_homograph_attack(domain: str) -> bool:
    """
    Detect homograph/typosquatting attacks.
    Flags domains that attempt to impersonate legitimate brands.
    Uses fuzzy matching to catch common typos and character substitutions.
    """
    domain_lower = domain.lower()
    domain_parts = domain_lower.split(".")
    
    for keyword in BRAND_KEYWORDS:
        for part in domain_parts:
            # Skip exact matches (these are safe)
            if part == keyword:
                continue
            
            # Check if keyword appears in part (e.g., "google" in "my-google")
            if keyword in part:
                return True
            
            # Remove common separators and check for typos
            part_cleaned = part.replace("-", "").replace("_", "")
            
            # Skip if it's the exact keyword after cleaning
            if part_cleaned == keyword:
                continue
            
            # Check if the cleaned part starts with or closely resembles the keyword
            # This catches "g00gle-login" -> "g00glelogin" -> check similarity with "google"
            if len(part_cleaned) >= len(keyword) - 1:  # Allow for variations
                # Check if first X characters match the keyword length
                prefix = part_cleaned[:len(keyword)]
                similarity = calculate_levenshtein_similarity(prefix, keyword)
                if similarity >= 0.65:  # 65% similarity threshold
                    return True
            
            # Also check full similarity for shorter matches
            similarity = calculate_levenshtein_similarity(part_cleaned, keyword)
            if similarity >= 0.70:  # 70% similarity threshold
                return True
    
    return False


def calculate_levenshtein_similarity(s1: str, s2: str) -> float:
    """
    Calculate string similarity using Levenshtein distance.
    Returns a value between 0 and 1 (1 = identical).
    """
    if len(s1) == 0 or len(s2) == 0:
        return 0.0 if len(s1) != len(s2) else 1.0
    
    # Compute Levenshtein distance using dynamic programming
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    
    # Initialize first row and column
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    
    # Fill the DP table
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(
                    dp[i - 1][j],      # deletion
                    dp[i][j - 1],      # insertion
                    dp[i - 1][j - 1]   # substitution
                )
    
    # Convert distance to similarity (0 to 1)
    distance = dp[m][n]
    max_len = max(m, n)
    similarity = 1 - (distance / max_len)
    return max(0.0, similarity)


def is_on_whitelist(domain: str) -> bool:
    """
    Check if domain is on the pre-scan whitelist.
    Fixes Error 1: Prevents false positives on legitimate sites.
    """
    domain_lower = domain.lower()
    
    # Remove 'www.' prefix for comparison
    if domain_lower.startswith("www."):
        domain_lower = domain_lower[4:]
    
    return domain_lower in WHITELIST


def parse_url(url: str) -> Tuple[bool, Dict]:
    """
    Parse and extract components from a URL.
    Returns (success: bool, data: dict)
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove 'www.' prefix for analysis
        if domain.startswith("www."):
            domain_without_www = domain[4:]
        else:
            domain_without_www = domain
        
        return True, {
            "full_url": url,
            "domain": domain,
            "domain_clean": domain_without_www,
            "scheme": parsed.scheme,
            "path": parsed.path,
        }
    except Exception as e:
        return False, {"error": str(e)}


def scan_url(url: str) -> Tuple[str, List[str]]:
    """
    Scan a URL for phishing threats.
    Returns (verdict: str, reasons: List[str])
    """
    reasons = []
    
    # Clean the URL
    url = clean_url(url)
    
    # Parse the URL
    success, data = parse_url(url)
    if not success:
        return "UNKNOWN", [f"Unable to parse URL: {data.get('error', 'Unknown error')}"]
    
    domain = data["domain_clean"]
    
    # Pre-scan whitelist check (Fix for Error 1)
    if is_on_whitelist(domain):
        return "SAFE", ["Domain is on the trusted whitelist."]
    
    # Threat detection
    
    # Check for IP addresses
    if is_ip_address(domain):
        reasons.append("URL uses an IP address instead of a domain name (suspicious).")
    
    # Check for suspicious URL shorteners
    if is_suspicious_shortener(data["domain"]):
        reasons.append("URL uses a known shortener service (potential phishing tactic).")
    
    # Check for homograph/typosquatting attacks
    if detect_homograph_attack(domain):
        reasons.append("Domain resembles a legitimate brand (possible homograph/typosquatting attack).")
    
    # Determine verdict
    if reasons:
        return "SUSPICIOUS", reasons
    else:
        return "SAFE", ["No known phishing indicators detected."]


def print_verdict(url: str, verdict: str, reasons: List[str]) -> None:
    """
    Print a color-coded verdict with reasoning.
    """
    if verdict == "SAFE":
        color = Colors.GREEN
    elif verdict == "SUSPICIOUS":
        color = Colors.RED
    else:
        color = Colors.YELLOW
    
    print(f"\n{color}{Colors.BOLD}[{verdict}]{Colors.RESET} {url}")
    print(f"{color}{'─' * 60}{Colors.RESET}")
    
    for i, reason in enumerate(reasons, 1):
        print(f"  {i}. {reason}")
    
    print(f"{color}{'─' * 60}{Colors.RESET}\n")


def interactive_loop() -> None:
    """
    Main interactive CLI loop.
    Fixes Error 2: Handles empty input gracefully without crashing.
    """
    print_banner()
    
    while True:
        try:
            # Interactive prompt (Fix for Error 2)
            user_input = input(f"{Colors.CYAN}kiro [User] >> {Colors.RESET}").strip()
            
            # Handle empty input
            if not user_input:
                print(f"{Colors.YELLOW}⚠ Please enter a URL.{Colors.RESET}\n")
                continue
            
            # Handle exit commands
            if user_input.lower() in ["exit", "quit", "q"]:
                print(f"{Colors.CYAN}Goodbye!{Colors.RESET}")
                sys.exit(0)
            
            # Scan the URL
            verdict, reasons = scan_url(user_input)
            print_verdict(user_input, verdict, reasons)
        
        except KeyboardInterrupt:
            print(f"\n{Colors.CYAN}Goodbye!{Colors.RESET}")
            sys.exit(0)
        except Exception as e:
            print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}\n")


def main() -> None:
    """Entry point for the Kiro CLI tool."""
    interactive_loop()


if __name__ == "__main__":
    main()
