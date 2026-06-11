#!/usr/bin/env python3
"""
YARA Scanner - FIXED VERSION
Scans Docker images for malware patterns using YARA rules
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


def run_yara_scan(image_name: str, rules_file: str, timeout: int = 300) -> Dict:
    """
    Scan Docker image with YARA rules
    
    Args:
        image_name: Docker image to scan
        rules_file: Path to YARA rules file
        timeout: Scan timeout in seconds
        
    Returns:
        Dictionary with scan results
    """
    logger.info(f"[yara] Scanning {image_name}")
    
    # Check rules file exists
    if not Path(rules_file).exists():
        logger.error(f"YARA rules file not found: {rules_file}")
        return {
            'success': False,
            'match_count': 0,
            'matches': [],
            'error': f'YARA rules file not found: {rules_file}'
        }
    
    temp_dir = None
    
    try:
        # Create temp directory
        temp_base = os.path.expanduser('~/maldocker_temp')
        Path(temp_base).mkdir(parents=True, exist_ok=True)
        
        temp_dir = tempfile.mkdtemp(prefix='yara_scan_', dir=temp_base)
        
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
            logger.error(f"[yara] Docker save failed: {e.stderr}")
            return {
                'success': False,
                'match_count': 0,
                'matches': [],
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
            logger.error(f"[yara] Tar extraction failed: {e.stderr}")
            return {
                'success': False,
                'match_count': 0,
                'matches': [],
                'error': f'Tar extraction failed'
            }
        
        # Run YARA scan
        try:
            result = subprocess.run(
                ['yara', '-r', rules_file, str(extract_dir)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            # Parse YARA output
            matches = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        matches.append(line.strip())
            
            match_count = len(matches)
            logger.info(f"[yara] {match_count} matches in {image_name}")
            
            return {
                'success': True,
                'match_count': match_count,
                'matches': matches,
                'error': None
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"[yara] Scan timeout after {timeout}s")
            return {
                'success': False,
                'match_count': 0,
                'matches': [],
                'error': f'YARA scan timeout'
            }
    
    except Exception as e:
        logger.error(f"[yara] Error: {str(e)}")
        return {
            'success': False,
            'match_count': 0,
            'matches': [],
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
    if len(sys.argv) < 3:
        print("Usage: python3 yara_scan.py <image_name> <rules_file>")
        sys.exit(1)
    
    image = sys.argv[1]
    rules = sys.argv[2]
    
    result = run_yara_scan(image, rules)
    
    print(f"Success: {result['success']}")
    print(f"Matches: {result['match_count']}")
    if result['error']:
        print(f"Error: {result['error']}")
