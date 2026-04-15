"""
Configuration file for Tomcat Security Compliance Scanner
"""

VERSION = "1.0.0"
DEFAULT_TIMEOUT = 10
USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'

DEFAULT_WEBAPPS = [
    '/docs/',
    '/examples/',
    '/host-manager/',
    '/manager/',
]

MANAGER_PATHS = [
    '/manager/html',
    '/manager/status',
    '/host-manager/html',
]

SECURITY_HEADERS = {
    'X-Frame-Options': 'Prevents clickjacking',
    'X-Content-Type-Options': 'Prevents MIME sniffing',
    'X-XSS-Protection': 'XSS protection (legacy)',
    'Strict-Transport-Security': 'Enforces HTTPS (HSTS)',
    'Content-Security-Policy': 'Mitigates XSS and injection',
}

ALLOWED_IPS = [
    '127\\.0\\.0\\.1',  # IPv4 localhost
    '::1',              # IPv6 localhost
    '0:0:0:0:0:0:0:1',  # IPv6 localhost
]

DENIED_IPS = [
    #none yet but i can add later
]


class ScannerConfig:
    """Configuration class for scanner settings"""
    def __init__(self):
        self.timeout = DEFAULT_TIMEOUT
        self.verify_ssl = False  # Set to True in production with valid certs
        self.user_agent = USER_AGENT
        self.verbose = False
        self.local_tomcat_path = "/opt/tomcat"  # Default Tomcat installation path