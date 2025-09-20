# Flask Scanner API

A Python Flask API with two POST endpoints for URL and email scanning.

## Features

### URL Scanner (`/api/scan/url`)
- Validates URL format
- Resolves DNS A records
- Performs HTTP GET with 5-second timeout and max 3 redirects
- Reads only first 2000 bytes of content
- Returns reachability, status code, content type, content length, DNS records
- Provides suspicious content analysis based on keywords and patterns
- Safe defaults - does not download or execute binaries

### Email Scanner (`/api/scan/email`)
- Validates email format using email-validator
- Extracts domain from email
- Looks up MX records; if none found, looks up A/AAAA records
- Checks against built-in disposable email domain list
- Does NOT attempt SMTP delivery or probing

## Installation

1. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r flask_requirements.txt
```

## Running the Application

1. Start the Flask server:
```bash
python flask_scanner_app.py
```

The API will be available at `http://localhost:5000`

2. Test the API:
```bash
python test_scanner_api.py
```

## API Endpoints

### Health Check
```
GET /health
```

Response:
```json
{
  "status": "healthy"
}
```

### URL Scanner
```
POST /api/scan/url
Content-Type: application/json

{
  "url": "https://example.com"
}
```

Response:
```json
{
  "reachable": true,
  "status_code": 200,
  "content_type": "text/html; charset=UTF-8",
  "content_length": "1256",
  "dns_records": ["93.184.216.34"],
  "suspicious": {
    "is_suspicious": false,
    "score": 0,
    "reasons": []
  }
}
```

### Email Scanner
```
POST /api/scan/email
Content-Type: application/json

{
  "email": "test@example.com"
}
```

Response:
```json
{
  "valid_format": true,
  "domain": "example.com",
  "has_mx": true,
  "mx_records": ["0 ."],
  "resolved_ips": [],
  "is_disposable": false
}
```

## Error Handling

The API returns appropriate HTTP status codes:
- `200`: Success
- `400`: Bad Request (invalid input)
- `500`: Internal Server Error

Error responses include an error message:
```json
{
  "error": "URL is required"
}
```

## Security Features

- URL validation prevents malformed URLs
- HTTP requests have timeouts and redirect limits
- Only reads first 2000 bytes of content
- Does not download or execute binaries
- Email validation prevents malformed emails
- No SMTP probing to avoid being intrusive
- Built-in disposable email detection

## Suspicious Content Analysis

The URL scanner analyzes content for suspicious patterns:
- Suspicious keywords in URL and content
- IP addresses instead of domain names
- Complex subdomain structures
- Login/password forms in HTML content
- Multiple suspicious keywords

## Dependencies

- Flask: Web framework
- requests: HTTP client
- dnspython: DNS resolution
- email-validator: Email format validation
- Werkzeug: WSGI utilities

## Example Usage with curl

Test URL scanner:
```bash
curl -X POST http://localhost:5000/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'
```

Test email scanner:
```bash
curl -X POST http://localhost:5000/api/scan/email \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com"}'
```
