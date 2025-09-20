import re
import socket
import dns.resolver
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from email_validator import validate_email, EmailNotValidError
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Built-in list of common disposable email domains
DISPOSABLE_EMAIL_DOMAINS = {
    '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'tempmail.org',
    'yopmail.com', 'throwaway.email', 'temp-mail.org', 'getnada.com',
    'maildrop.cc', 'sharklasers.com', 'guerrillamailblock.com', 'pokemail.net',
    'spam4.me', 'bccto.me', 'chacuo.net', 'dispostable.com', 'fakeinbox.com',
    'mailnesia.com', 'mytrashmail.com', 'tempail.com', 'trashmail.com'
}

# Suspicious keywords for URL analysis
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'account', 'verify', 'secure', 'update', 'suspended',
    'urgent', 'click', 'winner', 'prize', 'free', 'offer', 'limited',
    'paypal', 'amazon', 'microsoft', 'google', 'apple', 'bank', 'credit'
]

def validate_url_format(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except Exception:
        return False

def get_dns_records(domain):
    """Get DNS A records for a domain"""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(rdata) for rdata in answers]
    except Exception as e:
        logger.warning(f"DNS resolution failed for {domain}: {e}")
        return []

def analyze_suspicious_content(url, content, content_type):
    """Analyze content for suspicious patterns"""
    suspicious_score = 0
    reasons = []
    
    # Check URL for suspicious patterns
    url_lower = url.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            suspicious_score += 1
            reasons.append(f"Suspicious keyword in URL: {keyword}")
    
    # Check for suspicious URL patterns
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):  # IP address instead of domain
        suspicious_score += 2
        reasons.append("URL uses IP address instead of domain")
    
    if len(re.findall(r'[.-]', urlparse(url).netloc)) > 3:  # Too many subdomains/hyphens
        suspicious_score += 1
        reasons.append("URL has suspicious subdomain structure")
    
    # Analyze content if it's HTML
    if content and 'text/html' in content_type.lower():
        content_lower = content.lower()
        
        # Check for suspicious keywords in content
        keyword_matches = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in content_lower)
        if keyword_matches > 3:
            suspicious_score += keyword_matches
            reasons.append(f"Multiple suspicious keywords in content ({keyword_matches})")
        
        # Check for forms (potential phishing)
        if '<form' in content_lower and ('password' in content_lower or 'login' in content_lower):
            suspicious_score += 2
            reasons.append("Contains login/password form")
    
    return {
        'is_suspicious': suspicious_score > 2,
        'score': suspicious_score,
        'reasons': reasons
    }

def get_mx_records(domain):
    """Get MX records for a domain"""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [str(rdata) for rdata in answers]
    except Exception:
        return []

def get_a_aaaa_records(domain):
    """Get A and AAAA records for a domain"""
    records = []
    
    # Get A records
    try:
        answers = dns.resolver.resolve(domain, 'A')
        records.extend([str(rdata) for rdata in answers])
    except Exception:
        pass
    
    # Get AAAA records
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        records.extend([str(rdata) for rdata in answers])
    except Exception:
        pass
    
    return records

def is_disposable_email(domain):
    """Check if email domain is in disposable email list"""
    return domain.lower() in DISPOSABLE_EMAIL_DOMAINS

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    """URL scanner endpoint"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        
        # Validate URL format
        if not validate_url_format(url):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Get DNS records
        dns_records = get_dns_records(domain)
        
        # Initialize response data
        response_data = {
            'reachable': False,
            'status_code': None,
            'content_type': None,
            'content_length': None,
            'dns_records': dns_records,
            'suspicious': None
        }
        
        # Perform HTTP GET request
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(
                url,
                timeout=5,
                allow_redirects=True,
                max_redirects=5,
                headers=headers,
                stream=True
            )
            
            response_data['reachable'] = True
            response_data['status_code'] = response.status_code
            response_data['content_type'] = response.headers.get('content-type', '')
            response_data['content_length'] = response.headers.get('content-length')
            
            # Read only first 2000 bytes
            content = ''
            if response.headers.get('content-type', '').startswith('text/'):
                content = response.content[:2000].decode('utf-8', errors='ignore')
            
            # Analyze for suspicious content
            response_data['suspicious'] = analyze_suspicious_content(
                url, content, response_data['content_type']
            )
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"HTTP request failed for {url}: {e}")
            response_data['suspicious'] = analyze_suspicious_content(url, '', '')
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Error in URL scanner: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/scan/email', methods=['POST'])
def scan_email():
    """Email scanner endpoint"""
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({'error': 'Email is required'}), 400
        
        email = data['email'].strip()
        
        # Validate email format
        try:
            valid = validate_email(email)
            email_address = valid.email
            domain = email_address.split('@')[1]
            valid_format = True
        except EmailNotValidError:
            return jsonify({
                'valid_format': False,
                'domain': None,
                'has_mx': False,
                'mx_records': [],
                'resolved_ips': [],
                'is_disposable': False
            }), 200
        
        # Get MX records
        mx_records = get_mx_records(domain)
        has_mx = len(mx_records) > 0
        
        # If no MX records, try A/AAAA records
        resolved_ips = []
        if not has_mx:
            resolved_ips = get_a_aaaa_records(domain)
        
        # Check if disposable email
        is_disposable = is_disposable_email(domain)
        
        response_data = {
            'valid_format': valid_format,
            'domain': domain,
            'has_mx': has_mx,
            'mx_records': mx_records,
            'resolved_ips': resolved_ips,
            'is_disposable': is_disposable
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Error in email scanner: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
