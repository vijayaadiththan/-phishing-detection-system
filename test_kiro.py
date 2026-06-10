#!/usr/bin/env python3
"""
Test script for Kiro phishing detection tool.
Tests core functionality without requiring interactive input.
"""

import sys
from kiro import scan_url, is_on_whitelist, is_ip_address, is_suspicious_shortener, detect_homograph_attack

def run_tests():
    """Run test cases for Kiro."""
    print("=" * 70)
    print("KIRO TEST SUITE")
    print("=" * 70)
    
    # Test cases: (url, expected_verdict, description)
    test_cases = [
        # Whitelist tests (Error 1 fix)
        ("https://google.com", "SAFE", "Whitelist: google.com should be SAFE"),
        ("https://www.facebook.com", "SAFE", "Whitelist: facebook.com with www should be SAFE"),
        ("facebook.com", "SAFE", "Whitelist: facebook.com without protocol should be SAFE"),
        
        # IP address tests
        ("http://192.168.1.1", "SUSPICIOUS", "IP address should be SUSPICIOUS"),
        ("http://127.0.0.1:8080", "SUSPICIOUS", "Localhost IP should be SUSPICIOUS"),
        
        # URL shortener tests
        ("http://bit.ly/abc123", "SUSPICIOUS", "bit.ly shortener should be SUSPICIOUS"),
        ("https://tinyurl.com/xyz", "SUSPICIOUS", "tinyurl.com should be SUSPICIOUS"),
        
        # Homograph/typosquatting tests
        ("http://gogle.com", "SUSPICIOUS", "Typo of google should be SUSPICIOUS"),
        ("http://facebok.com", "SUSPICIOUS", "Typo of facebook should be SUSPICIOUS"),
        ("http://amaz0n.com", "SUSPICIOUS", "Fake amazon domain should be SUSPICIOUS"),
        
        # Safe legitimate URLs
        ("https://github.com", "SAFE", "github.com should be SAFE"),
        ("https://stackoverflow.com", "SAFE", "stackoverflow.com should be SAFE"),
    ]
    
    passed = 0
    failed = 0
    
    for url, expected_verdict, description in test_cases:
        verdict, reasons = scan_url(url)
        status = "✓ PASS" if verdict == expected_verdict else "✗ FAIL"
        
        if verdict == expected_verdict:
            passed += 1
        else:
            failed += 1
        
        print(f"\n{status}")
        print(f"  Description: {description}")
        print(f"  URL: {url}")
        print(f"  Expected: {expected_verdict}, Got: {verdict}")
        print(f"  Reasons: {reasons}")
    
    # Summary
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {passed} passed, {failed} failed out of {len(test_cases)} tests")
    print("=" * 70)
    
    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
