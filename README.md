# SSL/TLS Security Scanner

A comprehensive Python tool for scanning websites for SSL/TLS vulnerabilities and generating detailed PDF reports. This tool uses the SSLyze library for deep SSL/TLS analysis and the Cryptography library for certificate inspection.

## Features

- **Comprehensive SSL/TLS Analysis**: Scans for major vulnerabilities including Heartbleed, POODLE, BEAST, CRIME, ROBOT, and more
- **Certificate Analysis**: Detailed certificate inspection including validity, key strength, and signature algorithms
- **PDF Report Generation**: Professional PDF reports with detailed findings and recommendations
- **Batch Scanning**: Scan multiple websites at once
- **Multiple Output Formats**: JSON and PDF output options
- **Security Recommendations**: Actionable security recommendations based on scan results

## Installation

1. **Install Python 3.7+** (if not already installed)

2. **Install required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   Or install manually:
   ```bash
   pip install sslyze cryptography reportlab requests urllib3
   ```

## Usage

### Single Website Scan

Scan a single website and generate a PDF report:

```bash
python ssl_scanner.py https://example.com
```

Scan with custom port:

```bash
python ssl_scanner.py https://example.com -p 8443
```

Generate JSON output:

```bash
python ssl_scanner.py https://example.com --json
```

### Batch Website Scanning

Create a text file with URLs (one per line):

```bash
echo "https://google.com
https://github.com
https://stackoverflow.com" > websites.txt
```

Run batch scan:

```bash
python batch_ssl_scanner.py websites.txt
```

Or scan specific URLs directly:

```bash
python batch_ssl_scanner.py --urls "google.com,github.com,stackoverflow.com"
```

## What the Scanner Checks

### SSL/TLS Vulnerabilities
- **Heartbleed**: OpenSSL Heartbleed vulnerability
- **POODLE**: Padding Oracle On Downgraded Legacy Encryption
- **BEAST**: Browser Exploit Against SSL/TLS
- **CRIME**: Compression Ratio Info-leak Made Easy
- **ROBOT**: Return of Bleichenbacher's Oracle Threat
- **CCS Injection**: OpenSSL CCS Injection vulnerability
- **Session Renegotiation**: Insecure session renegotiation
- **Compression**: Compression support (CRIME risk)

### Certificate Analysis
- Certificate validity and expiration
- Key strength (RSA key size)
- Signature algorithm strength
- Certificate chain validation
- OCSP stapling support

### Cipher Suite Analysis
- Supported cipher suites
- Weak cipher detection
- Protocol version support
- Elliptic curve support

### Additional Checks
- HTTP security headers
- Session resumption support
- Early data support
- Fallback SCSV support

## Output

### PDF Reports
The scanner generates comprehensive PDF reports containing:
- Executive summary
- Certificate details
- Vulnerability findings
- Security recommendations
- Detailed scan results

### JSON Output
For programmatic use, the scanner can output results in JSON format with all scan data.

## Example Output

```
==> Starting comprehensive SSL/TLS security scan for https://example.com
================================================================
==> Analyzing certificate...
==> Running SSLyze security scan...

================================================================
 SCAN SUMMARY
================================================================
Target: example.com:443
Certificate Valid: Yes
Total Issues Found: 2
Critical Issues: 0
Warnings: 2

 ISSUES DETECTED:
   Server supports compression (CRIME vulnerability risk)
   Consider using SHA-256 or stronger signature algorithm

 Generating PDF report...
==> PDF report saved: ssl_scan_report_example.com_20241201_143022.pdf

==> Scan completed successfully!
```

## Security Recommendations

The scanner provides actionable recommendations including:
- Disable weak cipher suites
- Upgrade to stronger signature algorithms
- Implement HSTS headers
- Regular security audits
- Certificate renewal planning

## Requirements

- Python 3.7+
- Internet connection for scanning
- Appropriate permissions for network access

## Troubleshooting

### Common Issues

1. **Connection Timeout**: Check if the target website is accessible
2. **Permission Denied**: Ensure you have network access permissions
3. **Module Not Found**: Install required dependencies with `pip install -r requirements.txt`

### SSL/TLS Knowledge

Before using this tool, it's recommended to understand basic SSL/TLS concepts:
- Certificate validation
- Cipher suites and encryption
- Common vulnerabilities
- Security best practices

## Contributing

Feel free to contribute by:
- Reporting bugs
- Suggesting new features
- Improving documentation
- Adding new vulnerability checks

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have permission to scan the target websites. The authors are not responsible for any misuse of this tool.

## License

This project is open source. Please use responsibly and in accordance with applicable laws and regulations.
