##tomcat scan py code ##
"""
Apache Tomcat Security Compliance Scanner - Main Entry Point
"""

import sys
import argparse
from tomcat_scanner import TomcatComplianceScanner
from tomcat_scanner.config import VERSION


def main():
    parser = argparse.ArgumentParser(
        description='Apache Tomcat Security Compliance Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 tomcat-scan.py --target http://192.168.1.100:8080
  python3 tomcat-scan.py --target https://tomcat.example.com --verbose
  python3 tomcat-scan.py --target http://localhost:8080 --export results.json
        """
    )
    
    parser.add_argument(
        '--target',
        type=str,
        required=True,
        help='Target Tomcat server URL (e.g., http://192.168.1.100:8080)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output with details and recommendations'
    )
    
    parser.add_argument(
        '--export',
        type=str,
        metavar='FILE',
        help='Export results to file (e.g., results.json)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {VERSION}'
    )
    
    args = parser.parse_args()
    
    if not args.target.startswith(('http://', 'https://')):
        print("[-] Error: Target must start with http:// or https://")
        sys.exit(1)
    
    try:
        scanner = TomcatComplianceScanner(args.target, verbose=args.verbose)
        results = scanner.run_scan()
        
        if results:
            scanner.print_results()
            
            if args.export:
                scanner.save_results(args.export)
        
        if results:
            if results['summary']['non_compliant'] > 0:
                sys.exit(1)
            else:
                sys.exit(0)
        else:
            sys.exit(2)
            
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()