"""
Trivy Scanner: scans Docker images for known vulnerabilities using Trivy
"""

import subprocess
import json
import logging
from typing import Dict, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_trivy_scan(image_name: str, timeout: int = 300) -> Dict:
    """
    Run Trivy vulnerability scan on Docker image
    
    Args:
        image_name: Docker image name (e.g., 'nginx:latest')
        timeout: Scan timeout in seconds
        
    Returns:
        Dictionary containing vulnerability results
    """
    logger.info(f"Starting Trivy scan: {image_name}")
    
    result = {
        'scanner': 'trivy',
        'image': image_name,
        'vulnerabilities': [],
        'critical_count': 0,
        'high_count': 0,
        'medium_count': 0,
        'low_count': 0,
        'success': False,
        'error': None
    }
    
    try:
        # Run Trivy scan with JSON output
        cmd = [
            'trivy',
            'image',
            '--format', 'json',
            '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
            '--timeout', f'{timeout}s',
            image_name
        ]
        
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        if process.returncode == 0:
            # Parse JSON output
            trivy_output = json.loads(process.stdout)
            
            # Extract vulnerabilities
            vulnerabilities = []
            for result_item in trivy_output.get('Results', []):
                for vuln in result_item.get('Vulnerabilities', []):
                    severity = vuln.get('Severity', 'UNKNOWN').upper()
                    
                    vuln_data = {
                        'cve_id': vuln.get('VulnerabilityID', ''),
                        'package_name': vuln.get('PkgName', ''),
                        'installed_version': vuln.get('InstalledVersion', ''),
                        'fixed_version': vuln.get('FixedVersion', 'Not Available'),
                        'severity': severity,
                        'cvss_score': vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', 0.0),
                        'description': vuln.get('Description', '')[:200],
                        'title': vuln.get('Title', ''),
                        'references': vuln.get('References', [])[:3]
                    }
                    
                    vulnerabilities.append(vuln_data)
                    
                    # Count by severity
                    if severity == 'CRITICAL':
                        result['critical_count'] += 1
                    elif severity == 'HIGH':
                        result['high_count'] += 1
                    elif severity == 'MEDIUM':
                        result['medium_count'] += 1
                    elif severity == 'LOW':
                        result['low_count'] += 1
            
            result['vulnerabilities'] = vulnerabilities
            result['total_count'] = len(vulnerabilities)
            result['success'] = True
            
            logger.info(f"Trivy scan complete: {result['total_count']} vulnerabilities "
                       f"(C:{result['critical_count']}, H:{result['high_count']}, "
                       f"M:{result['medium_count']}, L:{result['low_count']})")
        else:
            result['error'] = f"Trivy failed: {process.stderr}"
            logger.error(result['error'])
            
    except subprocess.TimeoutExpired:
        result['error'] = f"Trivy scan timeout after {timeout}s"
        logger.error(result['error'])
    except json.JSONDecodeError as e:
        result['error'] = f"Failed to parse Trivy output: {e}"
        logger.error(result['error'])
    except Exception as e:
        result['error'] = f"Trivy scan error: {str(e)}"
        logger.error(result['error'])
    
    return result


if __name__ == "__main__":
    # Test the scanner
    import sys
    
    test_image = sys.argv[1] if len(sys.argv) > 1 else "alpine:latest"
    print(f"Testing Trivy scanner with {test_image}...")
    
    results = run_trivy_scan(test_image)
    
    print(f"\nResults:")
    print(f"Success: {results['success']}")
    print(f"Total Vulnerabilities: {results.get('total_count', 0)}")
    print(f"Critical: {results['critical_count']}")
    print(f"High: {results['high_count']}")
    print(f"Medium: {results['medium_count']}")
    print(f"Low: {results['low_count']}")
    
    if results['error']:
        print(f"Error: {results['error']}")
