"""
Database connection and operations module
Handles all PostgreSQL interactions with error handling
"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_config():
    """Get database configuration from environment variables"""
    return {
        'dbname': os.environ.get('POSTGRES_DB', 'docker_security_db'),
        'user': os.environ.get('POSTGRES_USER', 'Dockersecurity_logs'),
        'password': os.environ.get('POSTGRES_PASSWORD', 'Docker@Sec2026!'),
        'host': os.environ.get('POSTGRES_HOST', 'localhost'),
        'port': int(os.environ.get('POSTGRES_PORT', 5432))
    }

@contextmanager
def get_connection():
    """Context manager for database connections"""
    conn = None
    try:
        config = get_db_config()
        conn = psycopg2.connect(**config)
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

class Database:
    """Database operations handler"""
    
    def __init__(self):
        self.config = get_db_config()
        self._test_connection()
    
    def _test_connection(self):
        """Test database connection on initialization"""
        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            logger.info("✅ Database connection successful")
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            raise
    
    def insert_scan(self, image_name, risk_score, trivy_vulns=0, 
                    clamav_hits=0, yara_hits=0, falco_alerts=0, scan_duration=0):
        """Insert scan result and return scan_id"""
        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO scans 
                        (image_name, risk_score, trivy_vulns, clamav_hits, 
                         yara_hits, falco_alerts, scan_duration)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        RETURNING id;
                        """,
                        (image_name, risk_score, trivy_vulns, clamav_hits, 
                         yara_hits, falco_alerts, scan_duration)
                    )
                    scan_id = cur.fetchone()[0]
            logger.info(f"✅ Scan {scan_id} inserted for image: {image_name}")
            return scan_id
        except Exception as e:
            logger.error(f"❌ Failed to insert scan: {e}")
            raise
    
    def insert_vulnerability(self, scan_id, cve_id, severity, 
                            package_name=None, installed_version=None, 
                            fixed_version=None):
        """Insert vulnerability detail"""
        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO vulnerabilities 
                        (scan_id, cve_id, severity, package_name, 
                         installed_version, fixed_version)
                        VALUES (%s, %s, %s, %s, %s, %s);
                        """,
                        (scan_id, cve_id, severity, package_name, 
                         installed_version, fixed_version)
                    )
        except Exception as e:
            logger.error(f"❌ Failed to insert vulnerability: {e}")
            raise
    
    def insert_malware_hit(self, scan_id, malware_name, file_path, rule_name=None):
        """Insert malware detection detail"""
        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO malware_hits 
                        (scan_id, malware_name, file_path, rule_name)
                        VALUES (%s, %s, %s, %s);
                        """,
                        (scan_id, malware_name, file_path, rule_name)
                    )
        except Exception as e:
            logger.error(f"❌ Failed to insert malware hit: {e}")
            raise
    
    def get_recent_scans(self, limit=20):
        """Get recent scan results"""
        try:
            with get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT * FROM scans 
                        ORDER BY created_at DESC 
                        LIMIT %s;
                        """,
                        (limit,)
                    )
                    return cur.fetchall()
        except Exception as e:
            logger.error(f"❌ Failed to get recent scans: {e}")
            return []
    
    def get_scan_details(self, scan_id):
        """Get complete scan details with vulnerabilities and malware"""
        try:
            with get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    # Get scan info
                    cur.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
                    scan = cur.fetchone()
                    
                    if not scan:
                        return None
                    
                    # Get vulnerabilities
                    cur.execute(
                        "SELECT * FROM vulnerabilities WHERE scan_id = %s",
                        (scan_id,)
                    )
                    scan['vulnerabilities'] = cur.fetchall()
                    
                    # Get malware hits
                    cur.execute(
                        "SELECT * FROM malware_hits WHERE scan_id = %s",
                        (scan_id,)
                    )
                    scan['malware_hits'] = cur.fetchall()
                    
                    return scan
        except Exception as e:
            logger.error(f"❌ Failed to get scan details: {e}")
            return None
    
    def get_statistics(self):
        """Get overall scanning statistics"""
        try:
            with get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT 
                            COUNT(*) as total_scans,
                            AVG(risk_score) as avg_risk_score,
                            MAX(risk_score) as max_risk_score,
                            SUM(trivy_vulns) as total_vulns,
                            SUM(clamav_hits + yara_hits) as total_malware
                        FROM scans;
                        """
                    )
                    return cur.fetchone()
        except Exception as e:
            logger.error(f"❌ Failed to get statistics: {e}")
            return {}

if __name__ == "__main__":
    # Test database connection
    print("Testing database connection...")
    try:
        db = Database()
        stats = db.get_statistics()
        print(f"✅ Database operational. Stats: {stats}")
    except Exception as e:
        print(f"❌ Database test failed: {e}")

