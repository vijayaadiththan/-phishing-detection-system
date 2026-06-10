#!/usr/bin/env python3
"""Debug script to test the detection logic."""

from kiro import calculate_levenshtein_similarity, detect_homograph_attack

# Test the Levenshtein similarity directly
test_cases = [
    ("g00gle", "google"),
    ("gogle", "google"),
    ("googel", "google"),
    ("facebook", "facebook"),
    ("facebk", "facebook"),
]

print("=== Levenshtein Similarity Tests ===\n")
for s1, s2 in test_cases:
    similarity = calculate_levenshtein_similarity(s1, s2)
    print(f"{s1:15} vs {s2:15} → Similarity: {similarity:.2f}")

print("\n=== Domain Homograph Detection ===\n")
test_domains = [
    "g00gle-login",
    "g00gle",
    "gogle",
    "facebook-verify",
    "paypal-confirm",
    "google",
    "facebook",
]

for domain in test_domains:
    is_homograph = detect_homograph_attack(domain)
    print(f"{domain:20} → Homograph: {is_homograph}")

# Deep dive into g00gle-login
print("\n=== Deep Dive: g00gle-login ===\n")
domain = "g00gle-login"
parts = domain.lower().split(".")
print(f"Domain parts after split by '.': {parts}")

for part in parts:
    part_cleaned = part.replace("-", "").replace("_", "")
    print(f"  Part: '{part}' → Cleaned: '{part_cleaned}'")
    
    # Check against google
    prefix = part_cleaned[:len("google")]
    sim_prefix = calculate_levenshtein_similarity(prefix, "google")
    sim_full = calculate_levenshtein_similarity(part_cleaned, "google")
    print(f"    Prefix '{prefix}' vs 'google': {sim_prefix:.2f}")
    print(f"    Full '{part_cleaned}' vs 'google': {sim_full:.2f}")

