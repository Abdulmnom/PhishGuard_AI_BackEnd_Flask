#!/usr/bin/env python3
"""
Test script for the Flask Scanner API
"""
import requests
import json

API_BASE_URL = "http://localhost:5000"

def test_url_scanner():
    """Test the URL scanner endpoint"""
    print("Testing URL Scanner...")
    
    test_urls = [
        "https://www.google.com",
        "https://httpbin.org/status/200",
        "https://example.com",
        "invalid-url",
        "https://suspicious-login-site.com/verify-account"
    ]
    
    for url in test_urls:
        print(f"\nTesting URL: {url}")
        try:
            response = requests.post(
                f"{API_BASE_URL}/api/scan/url",
                json={"url": url},
                timeout=10
            )
            print(f"Status Code: {response.status_code}")
            print(f"Response: {json.dumps(response.json(), indent=2)}")
        except Exception as e:
            print(f"Error: {e}")

def test_email_scanner():
    """Test the email scanner endpoint"""
    print("\n" + "="*50)
    print("Testing Email Scanner...")
    
    test_emails = [
        "test@gmail.com",
        "user@example.com",
        "invalid-email",
        "test@10minutemail.com",  # Disposable email
        "admin@nonexistentdomain12345.com"
    ]
    
    for email in test_emails:
        print(f"\nTesting Email: {email}")
        try:
            response = requests.post(
                f"{API_BASE_URL}/api/scan/email",
                json={"email": email},
                timeout=10
            )
            print(f"Status Code: {response.status_code}")
            print(f"Response: {json.dumps(response.json(), indent=2)}")
        except Exception as e:
            print(f"Error: {e}")

def test_health_check():
    """Test the health check endpoint"""
    print("\n" + "="*50)
    print("Testing Health Check...")
    
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Flask Scanner API Test Suite")
    print("="*50)
    print("Make sure the Flask app is running on http://localhost:5000")
    print("="*50)
    
    test_health_check()
    test_url_scanner()
    test_email_scanner()
    
    print("\n" + "="*50)
    print("Test suite completed!")
