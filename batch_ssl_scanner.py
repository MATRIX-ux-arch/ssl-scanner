#!/usr/bin/env python3
"""
Batch SSL/TLS Security Scanner
Scans multiple websites and generates individual PDF reports for each.

Usage:
    python batch_ssl_scanner.py websites.txt
    python batch_ssl_scanner.py --urls "google.com,github.com,stackoverflow.com"
"""

import argparse
import sys
import os
import json
from datetime import datetime
from typing import List, Dict, Any
from ssl_scanner import SSLTLSScanner


class BatchSSLScanner:
    """Batch scanner for multiple websites."""
    
    def __init__(self, urls: List[str], output_dir: str = "ssl_reports"):
        """
        Initialize batch scanner.
        
        Args:
            urls: List of URLs to scan
            output_dir: Directory to save PDF reports
        """
        self.urls = urls
        self.output_dir = output_dir
        self.results = []
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def scan_all(self) -> List[Dict[str, Any]]:
        """Scan all URLs and generate reports."""
        print(f"==> Starting batch SSL/TLS scan for {len(self.urls)} websites")
        print("=" * 80)
        
        for i, url in enumerate(self.urls, 1):
            print(f"\n[{i}/{len(self.urls)}] Scanning: {url}")
            print("-" * 50)
            
            try:
                # Create scanner instance
                scanner = SSLTLSScanner(url)
                
                # Run scan
                result = scanner.scan()
                
                if 'error' not in result:
                    # Generate PDF report
                    safe_filename = url.replace('://', '_').replace('/', '_').replace(':', '_')
                    pdf_file = os.path.join(self.output_dir, f"ssl_scan_{safe_filename}.pdf")
                    scanner.generate_pdf_report(pdf_file)
                    
                    # Store result
                    result['pdf_file'] = pdf_file
                    self.results.append(result)
                    
                    print(f"## Completed: {url}")
                else:
                    print(f"## Failed: {url} - {result['error']}")
                    self.results.append({
                        'url': url,
                        'error': result['error'],
                        'status': 'failed'
                    })
                    
            except Exception as e:
                print(f"## Error scanning {url}: {e}")
                self.results.append({
                    'url': url,
                    'error': str(e),
                    'status': 'error'
                })
        
        return self.results
    
    def generate_summary_report(self) -> str:
        """Generate a summary report of all scans."""
        summary_file = os.path.join(self.output_dir, "scan_summary.json")
        
        summary = {
            'scan_date': str(datetime.now()),
            'total_scans': len(self.results),
            'successful_scans': len([r for r in self.results if 'error' not in r]),
            'failed_scans': len([r for r in self.results if 'error' in r]),
            'results': self.results
        }
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        return summary_file
    
    def print_summary(self):
        """Print scan summary to console."""
        successful = [r for r in self.results if 'error' not in r]
        failed = [r for r in self.results if 'error' in r]
        
        print("\n" + "=" * 80)
        print("==> BATCH SCAN SUMMARY")
        print("=" * 80)
        print(f"Total websites scanned: {len(self.results)}")
        print(f"Successful scans: {len(successful)}")
        print(f"Failed scans: {len(failed)}")
        
        if successful:
            total_vulns = sum(len(r.get('vulnerabilities', [])) for r in successful)
            critical_vulns = sum(len([v for v in r.get('vulnerabilities', []) if '==>' in v]) for r in successful)
            warnings = sum(len([v for v in r.get('vulnerabilities', []) if '==>' in v]) for r in successful)
            
            print(f"Total vulnerabilities found: {total_vulns}")
            print(f"Critical issues: {critical_vulns}")
            print(f"Warnings: {warnings}")
        
        if failed:
            print(f"\n## Failed scans:")
            for result in failed:
                print(f"  - {result['url']}: {result['error']}")
        
        print(f"\n📁 Reports saved in: {self.output_dir}/")


def load_urls_from_file(filename: str) -> List[str]:
    """Load URLs from a text file (one URL per line)."""
    urls = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):  # Skip empty lines and comments
                    urls.append(url)
    except FileNotFoundError:
        print(f"## File not found: {filename}")
        sys.exit(1)
    except Exception as e:
        print(f"## Error reading file: {e}")
        sys.exit(1)
    
    return urls


def main():
    """Main function for batch scanning."""
    parser = argparse.ArgumentParser(description='Batch SSL/TLS Security Scanner')
    parser.add_argument('file', nargs='?', help='Text file containing URLs (one per line)')
    parser.add_argument('--urls', help='Comma-separated list of URLs to scan')
    parser.add_argument('-o', '--output', default='ssl_reports', help='Output directory for reports')
    parser.add_argument('--summary', action='store_true', help='Generate summary report')
    
    args = parser.parse_args()
    
    # Get URLs
    if args.urls:
        urls = [url.strip() for url in args.urls.split(',')]
    elif args.file:
        urls = load_urls_from_file(args.file)
    else:
        print("==> Please provide either a file with URLs or use --urls option")
        sys.exit(1)
    
    if not urls:
        print("==> No URLs to scan")
        sys.exit(1)
    
    try:
        # Create batch scanner
        batch_scanner = BatchSSLScanner(urls, args.output)
        
        # Run scans
        results = batch_scanner.scan_all()
        
        # Generate summary
        if args.summary:
            summary_file = batch_scanner.generate_summary_report()
            print(f"\n📄 Summary report saved: {summary_file}")
        
        # Print summary
        batch_scanner.print_summary()
        
        print("\n## Batch scan completed!")
        
    except KeyboardInterrupt:
        print("\n## Batch scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"## Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
