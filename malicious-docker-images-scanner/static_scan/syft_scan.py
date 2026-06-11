"""
Syft Scanner generates Software Bill of Materials (SBOM) for Docker images
"""

import subprocess
import json
import logging
from typing import Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_syft_scan(image_name: str, timeout: int = 300) -> Dict:
    """
    Run Syft SBOM generation on Docker image
    
    Args:
        image_name: Docker image name
        timeout: Scan timeout in seconds
        
    Returns:
        Dictionary containing SBOM results
    """
    logger.info(f"Starting Syft scan: {image_name}")
    
    result = {
        'scanner': 'syft',
        'image': image_name,
        'packages': [],
        'total_packages': 0,
        'high_risk_licenses': 0,
        'package_types': {},
        'success': False,
        'error': None
    }
    
    # High-risk licenses to flag
    HIGH_RISK_LICENSES = [
        'GPL', 'AGPL', 'LGPL', 'MPL', 'EPL', 'CDDL', 
        'CPL', 'SSPL', 'OSL', 'AFL'
    ]
    
    try:
        # Run Syft with JSON output
        cmd = [
            'syft',
            'packages',
            '-o', 'json',
            f'docker:{image_name}'
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
            syft_output = json.loads(process.stdout)
            
            packages = []
            package_types = {}
            high_risk_count = 0
            
            for artifact in syft_output.get('artifacts', []):
                pkg_type = artifact.get('type', 'unknown')
                package_types[pkg_type] = package_types.get(pkg_type, 0) + 1
                
                # Extract license info
                licenses = artifact.get('licenses', [])
                license_names = []
                is_high_risk = False
                
                for lic in licenses:
                    if isinstance(lic, dict):
                        lic_value = lic.get('value', '')
                    else:
                        lic_value = str(lic)
                    
                    license_names.append(lic_value)
                    
                    # Check if high-risk
                    for risk_lic in HIGH_RISK_LICENSES:
                        if risk_lic.lower() in lic_value.lower():
                            is_high_risk = True
                            break
                
                if is_high_risk:
                    high_risk_count += 1
                
                pkg_data = {
                    'name': artifact.get('name', 'unknown'),
                    'version': artifact.get('version', 'unknown'),
                    'type': pkg_type,
                    'licenses': license_names,
                    'high_risk_license': is_high_risk,
                    'language': artifact.get('language', ''),
                    'cpes': artifact.get('cpes', [])
                }
                
                packages.append(pkg_data)
            
            result['packages'] = packages
            result['total_packages'] = len(packages)
            result['high_risk_licenses'] = high_risk_count
            result['package_types'] = package_types
            result['success'] = True
            
            logger.info(f"Syft scan complete: {result['total_packages']} packages found, "
                       f"{result['high_risk_licenses']} with high-risk licenses")
        else:
            result['error'] = f"Syft failed: {process.stderr}"
            logger.error(result['error'])
            
    except subprocess.TimeoutExpired:
        result['error'] = f"Syft scan timeout after {timeout}s"
        logger.error(result['error'])
    except json.JSONDecodeError as e:
        result['error'] = f"Failed to parse Syft output: {e}"
        logger.error(result['error'])
    except Exception as e:
        result['error'] = f"Syft scan error: {str(e)}"
        logger.error(result['error'])
    
    return result


if __name__ == "__main__":
    # Test the scanner
    import sys
    
    test_image = sys.argv[1] if len(sys.argv) > 1 else "alpine:latest"
    print(f"Testing Syft scanner with {test_image}...")
    
    results = run_syft_scan(test_image)
    
    print(f"\nResults:")
    print(f"Success: {results['success']}")
    print(f"Total Packages: {results['total_packages']}")
    print(f"High-Risk Licenses: {results['high_risk_licenses']}")
    
    if results['package_types']:
        print("\nPackage Types:")
        for pkg_type, count in results['package_types'].items():
            print(f"  {pkg_type}: {count}")
    
    if results['error']:
        print(f"Error: {results['error']}")
