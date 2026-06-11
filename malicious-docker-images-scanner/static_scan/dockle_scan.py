"""
Dockle Scanner Module
Checks Docker image configuration against CIS benchmarks
"""

import subprocess
import json
import logging
from typing import Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_dockle_scan(image_name: str, timeout: int = 180) -> Dict:
    """
    Run Dockle configuration scan on Docker image
    
    Args:
        image_name: Docker image name
        timeout: Scan timeout in seconds
        
    Returns:
        Dictionary containing configuration check results
    """
    logger.info(f"Starting Dockle scan: {image_name}")
    
    result = {
        'scanner': 'dockle',
        'image': image_name,
        'issues': [],
        'fatal_count': 0,
        'warn_count': 0,
        'info_count': 0,
        'pass_count': 0,
        'success': False,
        'error': None
    }
    
    try:
        # Run Dockle with JSON output
        cmd = [
            'dockle',
            '--format', 'json',
            '--exit-code', '0',  # Don't fail on findings
            image_name
        ]
        
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        if process.stdout:
            try:
                # Parse JSON output
                dockle_output = json.loads(process.stdout)
                
                issues = []
                
                # Process each severity level
                for severity in ['FATAL', 'WARN', 'INFO']:
                    for detail in dockle_output.get('details', []):
                        if detail.get('level') == severity:
                            issue = {
                                'code': detail.get('code', ''),
                                'level': severity,
                                'title': detail.get('title', ''),
                                'alerts': detail.get('alerts', [])
                            }
                            issues.append(issue)
                            
                            # Count by severity
                            if severity == 'FATAL':
                                result['fatal_count'] += 1
                            elif severity == 'WARN':
                                result['warn_count'] += 1
                            elif severity == 'INFO':
                                result['info_count'] += 1
                
                # Count passed checks
                result['pass_count'] = dockle_output.get('summary', {}).get('pass', 0)
                
                result['issues'] = issues
                result['success'] = True
                
                logger.info(f"Dockle scan complete: {result['fatal_count']} fatal, "
                           f"{result['warn_count']} warnings, {result['info_count']} info")
                
            except json.JSONDecodeError as e:
                result['error'] = f"Failed to parse Dockle output: {e}"
                logger.error(result['error'])
        else:
            result['error'] = f"Dockle produced no output: {process.stderr}"
            logger.error(result['error'])
            
    except subprocess.TimeoutExpired:
        result['error'] = f"Dockle scan timeout after {timeout}s"
        logger.error(result['error'])
    except Exception as e:
        result['error'] = f"Dockle scan error: {str(e)}"
        logger.error(result['error'])
    
    return result


if __name__ == "__main__":
    # Test the scanner
    import sys
    
    test_image = sys.argv[1] if len(sys.argv) > 1 else "alpine:latest"
    print(f"Testing Dockle scanner with {test_image}...")
    
    results = run_dockle_scan(test_image)
    
    print(f"\nResults:")
    print(f"Success: {results['success']}")
    print(f"Fatal: {results['fatal_count']}")
    print(f"Warnings: {results['warn_count']}")
    print(f"Info: {results['info_count']}")
    print(f"Passed: {results['pass_count']}")
    
    if results['issues']:
        print("\nTop Issues:")
        for issue in results['issues'][:5]:
            print(f"  [{issue['level']}] {issue['code']}: {issue['title']}")
    
    if results['error']:
        print(f"Error: {results['error']}")
