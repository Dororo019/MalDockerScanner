#!/usr/bin/env python3
"""
ClamAV Scanner: scans Docker images for malware using ClamAV
"""

import subprocess
import tempfile
import shutil
import logging
import sys
import os
from pathlib import Path
from typing import Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_clamav_scan(image_name: str, timeout: int = 600) -> Dict:
    """
    Scan Docker image with ClamAV
    
    Args:
        image_name: Docker image to scan
        timeout: Scan timeout in seconds
        
    Returns:
        Dictionary with scan results
    """
    logger.info(f"[clamav] Scanning {image_name}")
    
    temp_dir = None
    
    try:
        # Create temp directory
        temp_base = os.path.expanduser('~/maldocker_temp')
        Path(temp_base).mkdir(parents=True, exist_ok=True)
        
        temp_dir = tempfile.mkdtemp(prefix='clamav_scan_', dir=temp_base)
        
        # Export container filesystem
        tar_path = Path(temp_dir) / 'image.tar'
        
        try:
            subprocess.run(
                ['docker', 'save', image_name, '-o', str(tar_path)],
                capture_output=True,
                text=True,
                timeout=120,
                check=True
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"[clamav] Docker save failed: {e.stderr}")
            return {
                'success': False,
                'threat_count': 0,
                'threats': [],
                'error': f'Docker save failed: {e.stderr}'
            }
        
        # Extract tar
        extract_dir = Path(temp_dir) / 'extracted'
        extract_dir.mkdir(exist_ok=True)
        
        try:
            subprocess.run(
                ['tar', '-xf', str(tar_path), '-C', str(extract_dir)],
                capture_output=True,
                text=True,
                timeout=120,
                check=True
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"[clamav] Tar extraction failed: {e.stderr}")
            return {
                'success': False,
                'threat_count': 0,
                'threats': [],
                'error': f'Tar extraction failed'
            }
        
        # Run ClamAV scan
        try:
            result = subprocess.run(
                ['clamscan', '-r', '--no-summary', str(extract_dir)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            # Parse ClamAV output
            threats = []
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if 'FOUND' in line:
                        threats.append(line.strip())
            
            threat_count = len(threats)
            logger.info(f"[clamav] {threat_count} hits in {image_name}")
            
            return {
                'success': True,
                'threat_count': threat_count,
                'threats': threats,
                'error': None
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"[clamav] Scan timeout after {timeout}s")
            return {
                'success': False,
                'threat_count': 0,
                'threats': [],
                'error': f'ClamAV scan timeout'
            }
    
    except Exception as e:
        logger.error(f"[clamav] Error: {str(e)}")
        return {
            'success': False,
            'threat_count': 0,
            'threats': [],
            'error': str(e)
        }
    
    finally:
        # Cleanup
        if temp_dir and Path(temp_dir).exists():
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 clamav_scan.py <image_name>")
        sys.exit(1)
    
    image = sys.argv[1]
    
    result = run_clamav_scan(image)
    
    print(f"Success: {result['success']}")
    print(f"Threats Found: {result['threat_count']}")
    if result['error']:
        print(f"Error: {result['error']}")
