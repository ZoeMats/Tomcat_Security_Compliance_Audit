"""
Apache Tomcat Security Compliance Scanner
Main scanner class with 4 compliance checks
"""
import requests
import urllib3
from .config import ScannerConfig, VERSION
from .checks import SecurityChecks
from .reporter import Reporter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TomcatComplianceScanner:
    def __init__(self, target_url, verbose=False, local_tomcat_path=None):
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.config = ScannerConfig()
        self.config.verbose = verbose
        
        if local_tomcat_path:
            self.config.local_tomcat_path = local_tomcat_path
        
        # Setup HTTP session
        self.session = requests.Session()
        self.session.verify = self.config.verify_ssl
        self.session.timeout = self.config.timeout
        self.session.headers.update({
            'User-Agent': self.config.user_agent
        })
        
        self.checks = SecurityChecks(
            self.session, 
            self.target_url, 
            verbose,
            self.config.local_tomcat_path
        )
        self.reporter = Reporter()
        self.reporter.initialize(target_url)
    
    def log(self, message):
        if self.verbose:
            print(f"[VERBOSE] {message}")
    
    def verify_connectivity(self):
        self.log(f"Checking connectivity to {self.target_url}")
        try:
            response = self.session.get(self.target_url, timeout=10)
            self.log(f"HTTP response from target: {response.status_code}")
            return True
        except Exception as e:
            print(f"[ERROR] Cannot connect to target: {str(e)}")
            return False
    
    def run_scan(self):
        from datetime import datetime
        
        print(f"\n[*] Apache Tomcat Security Compliance Scanner v{VERSION}")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Local Tomcat Path: {self.config.local_tomcat_path}")
        print(f"[*] Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 70)
        
        if not self.verify_connectivity():
            print("[-] Could not connect to target. Exiting.")
            return None
        
        print("[+] Target accessible, starting compliance checks...\n")
        
        check_methods = [
            ('Information Leakage Prevention', self.checks.check_information_leakage),
            ('HTTPS Enforcement', self.checks.check_https_enforcement),
            ('Manager/Host-Manager Access Controls', self.checks.check_manager_access),
            ('Password Encryption (tomcat-users.xml)', self.checks.check_password_encryption),
        ]
        
        for check_name, check_method in check_methods:
            try:
                result = check_method()
                self.reporter.add_check(
                    check_name,
                    result['status'],
                    result['details'],
                    result['recommendation']
                )
            except Exception as e:
                self.reporter.add_check(
                    check_name,
                    'UNKNOWN',
                    f"Error running check: {str(e)}",
                    "Manually verify this security control"
                )
        
        return self.reporter.results
    
    def print_results(self):
        """Print results to terminal"""
        self.reporter.print_results(verbose=self.verbose)
    
    def save_results(self, output_file):
        """Save results as log files"""
        if output_file.endswith('.json'):
            self.reporter.save_json(output_file)
            txt_file = output_file.replace('.json', '.txt')
            self.reporter.save_text(txt_file)
        else:
            self.reporter.save_json(output_file + '.json')
            self.reporter.save_text(output_file + '.txt')