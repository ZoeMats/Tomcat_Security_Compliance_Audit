"""
Reporter module for Tomcat Security Compliance Scanner
Handles result formatting and export with PARTIAL compliance support
"""
import json
from datetime import datetime


class Reporter:
    def __init__(self):
        self.results = {
            'target': '',
            'scan_time': '',
            'checks': [],
            'summary': {
                'compliant': 0,
                'non_compliant': 0,
                'partial': 0,
                'unknown': 0
            }
        }
    
    def initialize(self, target_url):
        self.results['target'] = target_url
        self.results['scan_time'] = datetime.now().isoformat()
    
    def add_check(self, name, status, details="", recommendation=""):
        check = {
            'name': name,
            'status': status,
            'details': details,
            'recommendation': recommendation
        }
        self.results['checks'].append(check)
        
        status_lower = status.lower()
        if status_lower == 'compliant':
            self.results['summary']['compliant'] += 1
        elif status_lower == 'non-compliant':
            self.results['summary']['non_compliant'] += 1
        elif status_lower == 'partial':
            self.results['summary']['partial'] += 1
        else:
            self.results['summary']['unknown'] += 1
    
    def print_results(self, verbose=False):
            """Print results to terminal with color coding"""
            print("\n" + "=" * 70)
            print("TOMCAT SECURITY COMPLIANCE CHECK RESULTS")
            print("=" * 70)
            
            name_width = 50
            
            for check in self.results['checks']:
                name = check['name']
                status = check['status']
                
                #colour coding for visible nalaysis
                if status == 'COMPLIANT':
                    status_display = f"\033[92m{status}\033[0m"
                elif status == 'NON-COMPLIANT':
                    status_display = f"\033[91m{status}\033[0m"
                elif status == 'PARTIAL':
                    status_display = f"\033[93m{status}\033[0m"
                else:
                    status_display = f"\033[90m{status}\033[0m"
                
                dots = '.' * (name_width - len(name))
                print(f"[CHECK] {name} {dots} {status_display}")
                
                if verbose:
                    if check['details']:
                        print(f"        Details: {check['details']}")
                    if check['recommendation']:
                        print(f"        Recommendation: {check['recommendation']}")
                    print()
            
            print("=" * 70)
            print("SUMMARY")
            print("=" * 70)
            summary = self.results['summary']
            total = sum(summary.values())
            
            print(f"Total Checks:        {total}")
            print(f"Compliant:           \033[92m{summary['compliant']}\033[0m")
            print(f"Partially Compliant: \033[93m{summary['partial']}\033[0m")
            print(f"Non-Compliant:       \033[91m{summary['non_compliant']}\033[0m")
            print(f"Unknown:             \033[90m{summary['unknown']}\033[0m")
            
            if total > 0:
                compliance_score = summary['compliant'] + (summary['partial'] * 0.5)
                rate = (compliance_score / total) * 100
                print(f"\nCompliance Score:    {rate:.1f}%")
            
            print("=" * 70)
            
            if total > 0:
                compliance_score = summary['compliant'] + (summary['partial'] * 0.5)
                rate = (compliance_score / total) * 100
                print(f"\nCompliance Score: {rate:.1f}%")
            
            print("=" * 70)
    
    def save_json(self, output_file):
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[+] JSON results saved to: {output_file}")
    
    def save_text(self, output_file):
        with open(output_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("APACHE TOMCAT SECURITY COMPLIANCE REPORT\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Target:     {self.results['target']}\n")
            f.write(f"Scan Time:  {self.results['scan_time']}\n")
            f.write("=" * 70 + "\n\n")
            
            for check in self.results['checks']:
                f.write(f"CHECK: {check['name']}\n")
                f.write(f"Status: {check['status']}\n")
                
                if check['details']:
                    f.write(f"\nDetails:\n{check['details']}\n")
                
                if check['recommendation']:
                    f.write(f"\nRecommendation:\n{check['recommendation']}\n")
                
                f.write("\n" + "-" * 70 + "\n\n")
            
            f.write("=" * 70 + "\n")
            f.write("SUMMARY\n")
            f.write("=" * 70 + "\n")
            summary = self.results['summary']
            total = sum(summary.values())
            
            f.write(f"Total Checks:        {total}\n")
            f.write(f"Compliant:           {summary['compliant']}\n")
            f.write(f"Partially Compliant: {summary['partial']}\n")
            f.write(f"Non-Compliant:       {summary['non_compliant']}\n")
            f.write(f"Unknown:             {summary['unknown']}\n")
            
            if total > 0:
                compliance_score = summary['compliant'] + (summary['partial'] * 0.5)
                rate = (compliance_score / total) * 100
                f.write(f"\nCompliance Score:    {rate:.1f}%\n")
            
            f.write("=" * 70 + "\n")
        
        print(f"[+] Text report saved to: {output_file}")