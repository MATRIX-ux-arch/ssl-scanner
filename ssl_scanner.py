#!/usr/bin/env python3
"""
SSL/TLS Security Scanner
A comprehensive tool to scan websites for SSL/TLS vulnerabilities and generate PDF reports.

This script uses SSLyze for SSL/TLS analysis and the Cryptography library for certificate inspection.
"""

import argparse
import sys
import socket
import ssl
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

# Third-party imports
from sslyze import (
    Scanner,
    ServerScanRequest,
    SslyzeOutputAsJson,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
    ServerScanResult,
    ServerScanResultAsJson,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


class SSLTLSScanner:
    """A comprehensive SSL/TLS security scanner using SSLyze and Cryptography libraries."""
    
    def __init__(self, target_url: str, port: int = 443):
        """
        Initialize the SSL/TLS scanner.
        
        Args:
            target_url: The target website URL to scan
            port: The port to scan (default: 443 for HTTPS)
        """
        self.target_url = target_url
        self.port = port
        self.hostname = self._extract_hostname(target_url)
        self.scan_results = {}
        self.certificate_info = {}
        self.vulnerabilities = []
        self.recommendations = []
        
    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        return parsed.hostname or url
    
    def _test_connectivity(self) -> bool:
        """Test basic connectivity to the target server."""
        try:
            sock = socket.create_connection((self.hostname, self.port), timeout=10)
            sock.close()
            return True
        except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
            print(f"==> Connection failed: {e}")
            return False
    
    def _get_certificate_info(self) -> Dict[str, Any]:
        """Get detailed certificate information using the Cryptography library."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Extract certificate details
                    subject = {}
                    for name in cert.subject:
                        subject[name.oid._name] = name.value
                    
                    issuer = {}
                    for name in cert.issuer:
                        issuer[name.oid._name] = name.value
                    
                    # Check for extensions
                    extensions = {}
                    for ext in cert.extensions:
                        extensions[ext.oid._name] = ext.value
                    
                    # Check certificate validity
                    now = datetime.now(timezone.utc)
                    is_valid = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
                    days_until_expiry = (cert.not_valid_after_utc - now).days
                    
                    return {
                        'subject': subject,
                        'issuer': issuer,
                        'valid_from': cert.not_valid_before_utc.isoformat(),
                        'valid_until': cert.not_valid_after_utc.isoformat(),
                        'is_valid': is_valid,
                        'days_until_expiry': days_until_expiry,
                        'serial_number': str(cert.serial_number),
                        'version': cert.version.name,
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'extensions': extensions,
                        'public_key': {
                            'key_size': getattr(cert.public_key(), 'key_size', 'Unknown'),
                            'key_type': type(cert.public_key()).__name__
                        }
                    }
        except Exception as e:
            print(f"==> Failed to get certificate info: {e}")
            return {}
    
    def _analyze_certificate_security(self, cert_info: Dict[str, Any]) -> List[str]:
        """Analyze certificate for security issues."""
        issues = []
        
        if not cert_info:
            issues.append("Could not retrieve certificate information")
            return issues
        
        # Check certificate validity
        if not cert_info.get('is_valid', False):
            issues.append("Certificate is not currently valid")
        
        # Check expiration
        days_until_expiry = cert_info.get('days_until_expiry', 0)
        if days_until_expiry < 30:
            issues.append(f"Certificate expires in {days_until_expiry} days")
        elif days_until_expiry < 90:
            issues.append(f"Certificate expires in {days_until_expiry} days (consider renewal)")
        
        # Check key size
        key_size = cert_info.get('public_key', {}).get('key_size', 0)
        if isinstance(key_size, int) and key_size > 0:
            if key_size < 2048:
                issues.append(f"Weak RSA key size: {key_size} bits (minimum 2048 recommended)")
            elif key_size < 3072:
                issues.append(f"Consider upgrading to 3072+ bit RSA key (current: {key_size} bits)")
        
        # Check signature algorithm
        sig_algorithm = cert_info.get('signature_algorithm', '')
        if 'sha1' in sig_algorithm.lower():
            issues.append("Certificate uses weak SHA-1 signature algorithm")
        elif 'sha256' not in sig_algorithm.lower() and 'sha384' not in sig_algorithm.lower():
            issues.append(" Consider using SHA-256 or stronger signature algorithm")
        
        return issues
    
    def run_sslyze_scan(self) -> Dict[str, Any]:
        """Run comprehensive SSL/TLS scan using SSLyze."""
        print(f"Starting SSL/TLS scan for {self.hostname}:{self.port}")
        
        try:
            # Create server network location
            server_location = ServerNetworkLocation(hostname=self.hostname, port=self.port)
            
            # Initialize scanner
            scanner = Scanner()
            
            # Create scan request with all available scan commands
            scan_request = ServerScanRequest(server_location=server_location)
            
            # Queue and process scan
            scanner.queue_scans([scan_request])
            
            # Get results (scanning happens automatically)
            scan_results = list(scanner.get_results())
            
            return self._parse_scan_results(scan_results)
            
        except ServerHostnameCouldNotBeResolved as e:
            print(f"==> Could not resolve hostname: {e}")
            return {'error': 'Hostname resolution failed'}
        except Exception as e:
            print(f"==> SSLyze scan failed: {e}")
            return {'error': str(e)}
    
    def _parse_scan_results(self, scan_results) -> Dict[str, Any]:
        """Parse SSLyze scan results into a structured format."""
        results = {
            'certificate_info': {},
            'cipher_suites': {},
            'vulnerabilities': [],
            'protocols': {},
            'compression': {},
            'session_info': {},
            'http_headers': {},
            'recommendations': []
        }
        
        try:
            if not scan_results:
                return results
            
            # Get the scan result for our target
            target_result = None
            for result in scan_results:
                if result.server_location.hostname == self.hostname:
                    target_result = result
                    break
            
            if not target_result:
                return results
            
            # Parse scan results
            vulnerabilities = []
            certificate_info = {}
            cipher_suites = {}
            
            # Get the scan result
            scan_result = target_result.scan_result
            
            if scan_result:
                # Parse certificate information
                if hasattr(scan_result, 'certificate_deployments') and scan_result.certificate_deployments:
                    cert_deployment = scan_result.certificate_deployments[0]
                    certificate_info = {
                        'subject': str(cert_deployment.certificate.subject),
                        'issuer': str(cert_deployment.certificate.issuer),
                        'valid_from': cert_deployment.certificate.not_valid_before_utc.isoformat(),
                        'valid_until': cert_deployment.certificate.not_valid_after_utc.isoformat(),
                        'key_size': getattr(cert_deployment.certificate.public_key(), 'key_size', 'Unknown')
                    }
                
                # Parse cipher suites
                if hasattr(scan_result, 'accepted_ciphers') or hasattr(scan_result, 'rejected_ciphers'):
                    cipher_suites = {
                        'accepted_ciphers': [str(cipher) for cipher in scan_result.accepted_ciphers] if hasattr(scan_result, 'accepted_ciphers') and scan_result.accepted_ciphers else [],
                        'rejected_ciphers': [str(cipher) for cipher in scan_result.rejected_ciphers] if hasattr(scan_result, 'rejected_ciphers') and scan_result.rejected_ciphers else []
                    }
                
                # Check for Heartbleed vulnerability
                if hasattr(scan_result, 'is_vulnerable_to_heartbleed') and scan_result.is_vulnerable_to_heartbleed:
                    vulnerabilities.append("VULNERABLE to Heartbleed attack")
                
                # Check for compression vulnerability
                if hasattr(scan_result, 'supports_compression') and scan_result.supports_compression:
                    vulnerabilities.append("Server supports compression (CRIME vulnerability risk)")
                
                # Check for CCS Injection vulnerability
                if hasattr(scan_result, 'is_vulnerable_to_ccs_injection') and scan_result.is_vulnerable_to_ccs_injection:
                    vulnerabilities.append("VULNERABLE to CCS Injection attack")
                
                # Check for ROBOT vulnerability
                if hasattr(scan_result, 'robot_result_enum'):
                    if scan_result.robot_result_enum.name == 'VULNERABLE_STRONG_ORACLE':
                        vulnerabilities.append("VULNERABLE to ROBOT attack (strong oracle)")
                    elif scan_result.robot_result_enum.name == 'VULNERABLE_WEAK_ORACLE':
                        vulnerabilities.append("VULNERABLE to ROBOT attack (weak oracle)")
            
            results['certificate_info'] = certificate_info
            results['cipher_suites'] = cipher_suites
            results['vulnerabilities'] = vulnerabilities
            
            # Generate recommendations
            recommendations = []
            if vulnerabilities:
                recommendations.append("Address all identified vulnerabilities immediately")
            if cipher_suites.get('accepted_ciphers'):
                recommendations.append("Review and disable weak cipher suites")
            recommendations.append("Ensure TLS 1.2 or higher is used")
            recommendations.append("Implement HSTS headers")
            recommendations.append("Regular security audits and updates")
            
            results['recommendations'] = recommendations
            
        except Exception as e:
            print(f"==> Error parsing scan results: {e}")
        
        return results
    
    def generate_pdf_report(self, output_file: str = None) -> str:
        """Generate a comprehensive PDF report of the scan results."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"ssl_scan_report_{self.hostname}_{timestamp}.pdf"
        
        doc = SimpleDocTemplate(output_file, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        story.append(Paragraph("SSL/TLS Security Scan Report", title_style))
        story.append(Spacer(1, 12))
        
        # Scan information
        info_style = ParagraphStyle(
            'InfoStyle',
            parent=styles['Normal'],
            fontSize=12,
            spaceAfter=6
        )
        
        story.append(Paragraph(f"<b>Target:</b> {self.hostname}:{self.port}", info_style))
        story.append(Paragraph(f"<b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", info_style))
        story.append(Spacer(1, 20))
        
        # Certificate Information
        story.append(Paragraph("Certificate Information", styles['Heading2']))
        if self.certificate_info:
            cert_data = [
                ['Property', 'Value'],
                ['Subject', self.certificate_info.get('subject', {}).get('commonName', 'Unknown')],
                ['Issuer', self.certificate_info.get('issuer', {}).get('organizationName', 'Unknown')],
                ['Valid From', self.certificate_info.get('valid_from', 'Unknown')],
                ['Valid Until', self.certificate_info.get('valid_until', 'Unknown')],
                ['Key Size', f"{self.certificate_info.get('public_key', {}).get('key_size', 'Unknown')} bits"],
                ['Signature Algorithm', self.certificate_info.get('signature_algorithm', 'Unknown')]
            ]
            
            cert_table = Table(cert_data, colWidths=[2*inch, 4*inch])
            cert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(cert_table)
        else:
            story.append(Paragraph("Certificate information not available", info_style))
        
        story.append(Spacer(1, 20))
        
        # Vulnerabilities
        story.append(Paragraph("Security Issues", styles['Heading2']))
        if self.vulnerabilities:
            for vuln in self.vulnerabilities:
                story.append(Paragraph(f"• {vuln}", info_style))
        else:
            story.append(Paragraph("No major security issues detected", info_style))
        
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Recommendations", styles['Heading2']))
        for rec in self.recommendations:
            story.append(Paragraph(f"• {rec}", info_style))
        
        story.append(Spacer(1, 20))
        
        # Scan Summary
        story.append(Paragraph("Scan Summary", styles['Heading2']))
        summary_data = [
            ['Metric', 'Value'],
            ['Total Vulnerabilities', str(len(self.vulnerabilities))],
            ['Critical Issues', str(len([v for v in self.vulnerabilities if '==>' in v]))],
            ['Warnings', str(len([v for v in self.vulnerabilities if '⚠️' in v]))],
            ['Certificate Valid', 'Yes' if self.certificate_info.get('is_valid', False) else 'No'],
            ['Days Until Expiry', str(self.certificate_info.get('days_until_expiry', 'Unknown'))]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        
        # Build PDF
        doc.build(story)
        return output_file
    
    def scan(self) -> Dict[str, Any]:
        """Run complete SSL/TLS security scan."""
        print(f"==> Starting comprehensive SSL/TLS security scan for {self.target_url}")
        print("=" * 60)
        
        # Test connectivity
        if not self._test_connectivity():
            return {'error': 'Connection failed'}
        
        # Get certificate information
        print("==> Analyzing certificate...")
        self.certificate_info = self._get_certificate_info()
        
        # Analyze certificate security
        cert_issues = self._analyze_certificate_security(self.certificate_info)
        self.vulnerabilities.extend(cert_issues)
        
        # Run SSLyze scan
        print("==> Running SSLyze security scan...")
        sslyze_results = self.run_sslyze_scan()
        
        # Combine results
        self.scan_results = {
            'target': f"{self.hostname}:{self.port}",
            'scan_time': datetime.now().isoformat(),
            'certificate_info': self.certificate_info,
            'sslyze_results': sslyze_results,
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self.recommendations
        }
        
        # Add SSLyze vulnerabilities
        if sslyze_results.get('vulnerabilities'):
            self.vulnerabilities.extend(sslyze_results['vulnerabilities'])
        
        # Add SSLyze recommendations
        if sslyze_results.get('recommendations'):
            self.recommendations.extend(sslyze_results['recommendations'])
        
        # Print summary
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {self.hostname}:{self.port}")
        print(f"Certificate Valid: {'Yes' if self.certificate_info.get('is_valid', False) else 'No'}")
        print(f"Total Issues Found: {len(self.vulnerabilities)}")
        print(f"Critical Issues: {len([v for v in self.vulnerabilities if '==>' in v])}")
        print(f"Warnings: {len([v for v in self.vulnerabilities if '⚠️' in v])}")
        
        if self.vulnerabilities:
            print("\n ISSUES DETECTED:")
            for vuln in self.vulnerabilities:
                print(f"  {vuln}")
        
        return self.scan_results


def main():
    """Main function to run the SSL/TLS scanner."""
    parser = argparse.ArgumentParser(description='SSL/TLS Security Scanner')
    parser.add_argument('url', help='Target website URL to scan')
    parser.add_argument('-p', '--port', type=int, default=443, help='Port to scan (default: 443)')
    parser.add_argument('-o', '--output', help='Output PDF file name')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    
    args = parser.parse_args()
    
    try:
        # Create scanner instance
        scanner = SSLTLSScanner(args.url, args.port)
        
        # Run scan
        results = scanner.scan()
        
        if 'error' in results:
            print(f"==> Scan failed: {results['error']}")
            sys.exit(1)
        
        # Generate PDF report
        if not args.json:
            print("\nGenerating PDF report...")
            pdf_file = scanner.generate_pdf_report(args.output)
            print(f"++ PDF report saved: {pdf_file}")
        
        # Output JSON if requested
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        
        print("\n++ Scan completed successfully!")
        
    except KeyboardInterrupt:
        print("\n==> Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"==> Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
