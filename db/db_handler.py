"""
Database Handler for MalDocker Scanner
It provides connection pooling, error handling, and CRUD operations
"""

import psycopg2
from psycopg2 import pool, sql
from psycopg2.extras import RealDictCursor, Json
import logging
import os
from typing import Optional, Dict, List, Any
from contextlib import contextmanager
from dotenv import load_dotenv

#Load environment variables
load_dotenv()

#Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseHandler:
    """Handles all database operations with connection pooling"""
    
    _instance = None
    _connection_pool = None
    
    def __new__(cls):
        """Singleton pattern to ensure single connection pool"""
        if cls._instance is None:
            cls._instance = super(DatabaseHandler, cls).__new__(cls)
            cls._instance._initialize_pool()
        return cls._instance
    
    def _initialize_pool(self):
        """Initialize connection pool"""
        try:
            self._connection_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=10,
                host=os.getenv('DB_HOST', 'localhost'),
                port=os.getenv('DB_PORT', '5432'),
                database=os.getenv('DB_NAME', 'docker_security'),
                user=os.getenv('DB_USER', 'docker_security_logs'),
                password=os.getenv('DB_PASSWORD', ''),
                connect_timeout=10
            )
            logger.info("Database connection pool initialized successfully")
        except psycopg2.Error as e:
            logger.error(f"Failed to initialize connection pool: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = None
        try:
            conn = self._connection_pool.getconn()
            yield conn
            conn.commit()
        except psycopg2.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                self._connection_pool.putconn(conn)
    
    @contextmanager
    def get_cursor(self, cursor_factory=RealDictCursor):
        """Context manager for database cursors"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cursor
            finally:
                cursor.close()
    
    def insert_scan_result(self, scan_data: Dict[str, Any]) -> Optional[int]:
        """
        Insert scan result into database
        
        Args:
            scan_data: Dictionary containing scan results
            
        Returns:
            scan_id if successful, None otherwise
        """
        query = """
            INSERT INTO scan_results (
                image_name, image_tag, scan_timestamp,
                trivy_vulnerabilities, trivy_critical_count, trivy_high_count,
                trivy_medium_count, trivy_low_count,
                clamav_threats_found, clamav_threats,
                yara_matches, yara_rules_matched,
                dockle_warnings, dockle_fatals, dockle_issues,
                syft_packages, syft_high_risk_licenses,
                falco_alerts, falco_events,
                risk_score, risk_level, ml_confidence,
                scan_duration_seconds, scanner_version, notes
            ) VALUES (
                %(image_name)s, %(image_tag)s, %(scan_timestamp)s,
                %(trivy_vulnerabilities)s, %(trivy_critical_count)s, %(trivy_high_count)s,
                %(trivy_medium_count)s, %(trivy_low_count)s,
                %(clamav_threats_found)s, %(clamav_threats)s,
                %(yara_matches)s, %(yara_rules_matched)s,
                %(dockle_warnings)s, %(dockle_fatals)s, %(dockle_issues)s,
                %(syft_packages)s, %(syft_high_risk_licenses)s,
                %(falco_alerts)s, %(falco_events)s,
                %(risk_score)s, %(risk_level)s, %(ml_confidence)s,
                %(scan_duration_seconds)s, %(scanner_version)s, %(notes)s
            )
            RETURNING scan_id;
        """
        
        try:
            with self.get_cursor() as cursor:
                #Convert Python dicts to JSON
                for key in ['trivy_vulnerabilities', 'clamav_threats', 'yara_rules_matched',
                           'dockle_issues', 'syft_packages', 'falco_events']:
                    if key in scan_data and scan_data[key] is not None:
                        scan_data[key] = Json(scan_data[key])
                
                cursor.execute(query, scan_data)
                result = cursor.fetchone()
                scan_id = result['scan_id']
                logger.info(f"Scan result inserted successfully: scan_id={scan_id}")
                return scan_id
        except Exception as e:
            logger.error(f"Failed to insert scan result: {e}")
            return None
    
    def insert_vulnerability_details(self, scan_id: int, vulnerabilities: List[Dict]) -> bool:
        """Insert vulnerability details for a scan"""
        query = """
            INSERT INTO vulnerability_details (
                scan_id, cve_id, severity, cvss_score, package_name,
                installed_version, fixed_version, description,
                exploitability_score, impact_score
            ) VALUES (
                %(scan_id)s, %(cve_id)s, %(severity)s, %(cvss_score)s, %(package_name)s,
                %(installed_version)s, %(fixed_version)s, %(description)s,
                %(exploitability_score)s, %(impact_score)s
            );
        """
        
        try:
            with self.get_cursor() as cursor:
                for vuln in vulnerabilities:
                    vuln['scan_id'] = scan_id
                    cursor.execute(query, vuln)
                logger.info(f"Inserted {len(vulnerabilities)} vulnerability details")
                return True
        except Exception as e:
            logger.error(f"Failed to insert vulnerability details: {e}")
            return False
    
    def get_scan_by_id(self, scan_id: int) -> Optional[Dict]:
        """Retrieve scan result by ID"""
        query = "SELECT * FROM scan_results WHERE scan_id = %s;"
        
        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, (scan_id,))
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"Failed to retrieve scan {scan_id}: {e}")
            return None
    
    def get_recent_scans(self, limit: int = 50) -> List[Dict]:
        """Get recent scan results"""
        query = """
            SELECT scan_id, image_name, image_tag, scan_timestamp,
                   risk_score, risk_level, 
                   trivy_critical_count + trivy_high_count as critical_issues,
                   scan_duration_seconds
            FROM scan_results
            ORDER BY scan_timestamp DESC
            LIMIT %s;
        """
        
        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, (limit,))
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to retrieve recent scans: {e}")
            return []
    
    def get_dashboard_stats(self) -> Optional[Dict]:
        """Get dashboard summary statistics"""
        query = "SELECT * FROM dashboard_summary;"
        
        try:
            with self.get_cursor() as cursor:
                cursor.execute(query)
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"Failed to retrieve dashboard stats: {e}")
            return None
    
    def search_scans(self, image_name: str = None, risk_level: str = None, 
                     days: int = 30) -> List[Dict]:
        """Search scans with filters"""
        conditions = ["scan_timestamp > NOW() - INTERVAL '%s days'"]
        params = [days]
        
        if image_name:
            conditions.append("image_name ILIKE %s")
            params.append(f"%{image_name}%")
        
        if risk_level:
            conditions.append("risk_level = %s")
            params.append(risk_level.upper())
        
        query = f"""
            SELECT * FROM scan_results
            WHERE {' AND '.join(conditions)}
            ORDER BY scan_timestamp DESC;
        """
        
        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, params)
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to search scans: {e}")
            return []
    
    def create_batch_scan(self, batch_name: str, total_images: int) -> Optional[int]:
        """Create a new batch scan record"""
        query = """
            INSERT INTO batch_scans (batch_name, total_images)
            VALUES (%s, %s)
            RETURNING batch_id;
        """
        
        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, (batch_name, total_images))
                result = cursor.fetchone()
                return result['batch_id']
        except Exception as e:
            logger.error(f"Failed to create batch scan: {e}")
            return None
    
    def update_batch_scan(self, batch_id: int, completed: int = 0, 
                         failed: int = 0, status: str = None, 
                         summary: Dict = None) -> bool:
        """Update batch scan progress"""
        updates = []
        params = []
        
        if completed > 0:
            updates.append("completed_images = completed_images + %s")
            params.append(completed)
        
        if failed > 0:
            updates.append("failed_images = failed_images + %s")
            params.append(failed)
        
        if status:
            updates.append("status = %s")
            params.append(status)
        
        if summary:
            updates.append("summary = %s")
            params.append(Json(summary))
        
        if not updates:
            return True
        
        updates.append("end_time = CURRENT_TIMESTAMP")
        params.append(batch_id)
        
        query = f"""
            UPDATE batch_scans 
            SET {', '.join(updates)}
            WHERE batch_id = %s;
        """
        
        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, params)
                return True
        except Exception as e:
            logger.error(f"Failed to update batch scan: {e}")
            return False
    
    def close(self):
        """Close all connections in the pool"""
        if self._connection_pool:
            self._connection_pool.closeall()
            logger.info("Database connection pool closed")


#Convenience function
def get_db() -> DatabaseHandler:
    """Get database handler instance"""
    return DatabaseHandler()


if __name__ == "__main__":
    #Testing database connection
    try:
        db = get_db()
        stats = db.get_dashboard_stats()
        print(f"Database connection successful!")
        print(f"Dashboard stats: {stats}")
    except Exception as e:
        print(f"Database connection failed: {e}")
        print("\nPlease ensure:")
        print("1. PostgreSQL is running")
        print("2. Database 'docker_security' exists")
        print("3. User 'docker_security_logs' has proper permissions")
        print("4. .env file contains correct credentials")

