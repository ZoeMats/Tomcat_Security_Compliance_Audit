import requests
import xml.etree.ElementTree as ET
import re
import os
from pathlib import Path
from .config import (
    DEFAULT_WEBAPPS,
    MANAGER_PATHS,
    SECURITY_HEADERS,
    ALLOWED_IPS,
    DENIED_IPS
)


class SecurityChecks:
    def __init__(self, session, target_url, verbose=False, local_tomcat_path=None):
        self.session = session
        self.target_url = target_url
        self.verbose = verbose
        self.local_tomcat_path = local_tomcat_path or "/opt/tomcat"

    def log(self, message):
        if self.verbose:
            print(f"[VERBOSE] {message}")

    def check_information_leakage(self):
        """
        Check for information disclosure vulnerabilities
        - Default webapps accessibility
        - Version disclosure in headers
        - Error message details
        """
        self.log("Starting information leakage check...")
        
        issues = []
        warnings = []
        
        accessible_webapps = []
        for webapp in DEFAULT_WEBAPPS:
            url = f"{self.target_url}{webapp}"
            try:
                response = self.session.get(url, allow_redirects=False, timeout=5)
                if response.status_code == 200:
                    accessible_webapps.append(webapp)
                    self.log(f"Found accessible webapp: {webapp}")
            except Exception as e:
                self.log(f"Error checking {webapp}: {str(e)}")
        
        if accessible_webapps:
            issues.append(f"Default webapps accessible: {', '.join(accessible_webapps)}")
        
        try:
            response = self.session.get(self.target_url, timeout=5)
            server_header = response.headers.get('Server', '')
            
            if re.search(r'Tomcat/[\d.]+|Apache/[\d.]+', server_header, re.IGNORECASE):
                warnings.append(f"Version disclosure in Server header: {server_header}")
                self.log(f"Server header reveals version: {server_header}")
            
            error_response = self.session.get(f"{self.target_url}/nonexistent-page-12345", timeout=5)
            if 'Apache Tomcat' in error_response.text or 'Tomcat/' in error_response.text:
                warnings.append("Verbose error pages reveal Tomcat version")
                
        except Exception as e:
            self.log(f"Error checking headers: {str(e)}")
    
        if issues:
            status = 'NON-COMPLIANT'
        elif warnings:
            status = 'PARTIAL'
        else:
            status = 'COMPLIANT'
        
        all_findings = issues + warnings
        
        if status != 'COMPLIANT':
            return {
                'status': status,
                'details': '\n  '.join([''] + [f"- {finding}" for finding in all_findings]),
                'reccomendation': 'Remove or restrict access to default webapps (/docs, /examples). Configure server.xml to suppress version information. Customize error pages to avoid information disclosure.'
            }
        
        return {
            'status': 'COMPLIANT',
            'details': 'No information leakage detected',
            'recommendation': 'none'
        }

    def check_https_enforcement(self):
            self.log("Checking HTTPS enforcement...")
            
            is_https = self.target_url.startswith('https://')
            
            if not is_https:
                self.log("Target URL is HTTP, not HTTPS")
                return {
                    'status': 'NON-COMPLIANT',
                    'details': '\n  - Target is not using HTTPS',
                    'recommendation': 'Enable HTTPS with valid certificates. Configure HTTPS connector in server.xml with proper SSL/TLS settings.'
                }
            
            self.log("Target is using HTTPS")
            return {
                'status': 'COMPLIANT',
                'details': 'HTTPS is enabled',
                'recommendation': ''
            }
            
    def check_manager_access(self):
            self.log("Checking manager application access controls...")
            
            issues = []
            warnings = []
            
            manager_apps = {
                'manager': f"{self.local_tomcat_path}/webapps/manager/META-INF/context.xml",
                'host-manager': f"{self.local_tomcat_path}/webapps/host-manager/META-INF/context.xml"
            }
            
            #check which webapps actually exist
            existing_apps = {}
            for app_name, context_path in manager_apps.items():
                webapp_dir = os.path.dirname(os.path.dirname(context_path))
                if os.path.exists(webapp_dir):
                    existing_apps[app_name] = context_path
                    self.log(f"Found {app_name} webapp at {webapp_dir}")
                else:
                    self.log(f"{app_name} webapp not installed - skipping")
            
            if not existing_apps:
                self.log("No manager applications found - this is acceptable")
                return {
                    'status': 'COMPLIANT',
                    'details': 'No manager applications are installed (reduced attack surface)',
                    'recommendation': ''
                }
            
            for app_name, context_path in existing_apps.items():
                self.log(f"Checking {app_name} context.xml at {context_path}")
                
                if os.path.exists(context_path):
                    try:
                        tree = ET.parse(context_path)
                        root = tree.getroot()
                        
                        #Find Valve elements with RemoteAddrValve
                        valves = root.findall(".//Valve[@className='org.apache.catalina.valves.RemoteAddrValve']")
                        
                        if not valves:
                            issues.append(f"{app_name}: No IP filtering configured (RemoteAddrValve not found)")
                            self.log(f"No RemoteAddrValve found in {app_name}")
                            continue
                        
                        for valve in valves:
                            allowed = valve.get('allow', '')
                            denied = valve.get('deny', '')
                            
                            self.log(f"{app_name} - Allowed: {allowed}, Denied: {denied}")
                            
                            if allowed:
                                configured_ips = set(ip.strip() for ip in allowed.split('|'))
                                expected_ips = set(ALLOWED_IPS)
                                
                                if configured_ips != expected_ips:
                                    warnings.append(
                                        f"{app_name}: Allowed IPs differ from expected.\n"
                                        f"      Expected: {', '.join(expected_ips)}\n"
                                        f"      Configured: {', '.join(configured_ips)}"
                                    )
                            else:
                                warnings.append(f"{app_name}: No 'allow' attribute configured")
                            
                            #resiricti and verify ips
                            if DENIED_IPS:
                                if denied:
                                    configured_denied = set(ip.strip() for ip in denied.split('|'))
                                    expected_denied = set(DENIED_IPS)
                                    
                                    if configured_denied != expected_denied:
                                        warnings.append(
                                            f"{app_name}: Denied IPs differ from expected.\n"
                                            f"      Expected: {', '.join(expected_denied)}\n"
                                            f"      Configured: {', '.join(configured_denied)}"
                                        )
                            
                    except ET.ParseError as e:
                        issues.append(f"{app_name}: Unable to parse context.xml - {str(e)}")
                    except Exception as e:
                        issues.append(f"{app_name}: Error reading context.xml - {str(e)}")
                else:
                    issues.append(f"{app_name}: context.xml not found at {context_path}")
            
            if issues:
                status = 'NON-COMPLIANT'
            elif warnings:
                status = 'PARTIAL'
            else:
                status = 'COMPLIANT'
            
            all_findings = issues + warnings
            
            if status == 'NON-COMPLIANT':
                return {
                    'status': status,
                    'details': '\n  '.join([''] + [f"- {finding}" for finding in all_findings]),
                    'recommendation': f'Configure RemoteAddrValve in context.xml for installed manager apps. Set allow="{"|".join(ALLOWED_IPS)}" to restrict access to trusted IPs only. Consider disabling manager apps if not needed.'
                }
            elif status == 'PARTIAL':
                return {
                    'status': status,
                    'details': '\n  '.join([''] + [f"- {finding}" for finding in all_findings]),
                    'recommendation': 'Review and adjust IP filtering rules to match security requirements. Ensure only authorized IPs can access manager applications.'
                }
            
            return {
                'status': 'COMPLIANT',
                'details': f'Installed manager applications have proper IP-based access controls configured',
                'recommendation': ''
            }

