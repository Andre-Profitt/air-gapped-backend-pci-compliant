#!/usr/bin/env python3
"""
Data Retention and Lifecycle Management
PCI DSS Requirement 3.1 - Data retention and disposal
"""

import os
import json
import logging
import hashlib
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import sqlite3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger('DataRetention')


class RetentionPolicy(Enum):
    """Data retention policies per PCI DSS"""
    TRANSACTION_DATA = 365  # 1 year for transaction data
    AUDIT_LOGS = 2555  # 7 years for audit logs
    CARDHOLDER_DATA = 90  # 90 days for tokenized data
    SECURITY_EVENTS = 365  # 1 year for security events
    BACKUP_DATA = 180  # 6 months for backups


@dataclass
class RetentionRecord:
    """Record of data retention and disposal"""
    record_id: str
    data_type: str
    creation_date: datetime
    scheduled_deletion: datetime
    actual_deletion: Optional[datetime] = None
    deletion_method: Optional[str] = None
    verified_by: Optional[str] = None
    verification_hash: Optional[str] = None


class SecureDataWiper:
    """Secure data wiping utility"""
    
    @staticmethod
    def wipe_file(filepath: str, passes: int = 3) -> bool:
        """Securely wipe a file using DoD 5220.22-M standard"""
        try:
            if not os.path.exists(filepath):
                return False
            
            filesize = os.path.getsize(filepath)
            
            with open(filepath, "rb+") as f:
                for pass_num in range(passes):
                    f.seek(0)
                    
                    # Pass 1: Overwrite with zeros
                    if pass_num == 0:
                        f.write(b'\x00' * filesize)
                    
                    # Pass 2: Overwrite with ones
                    elif pass_num == 1:
                        f.write(b'\xFF' * filesize)
                    
                    # Pass 3: Overwrite with random data
                    else:
                        f.write(os.urandom(filesize))
                    
                    f.flush()
                    os.fsync(f.fileno())
            
            # Remove the file
            os.unlink(filepath)
            logger.info(f"Securely wiped file: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to wipe file {filepath}: {e}")
            return False
    
    @staticmethod
    def wipe_directory(dirpath: str) -> bool:
        """Securely wipe an entire directory"""
        try:
            for root, dirs, files in os.walk(dirpath, topdown=False):
                # Wipe all files
                for filename in files:
                    filepath = os.path.join(root, filename)
                    SecureDataWiper.wipe_file(filepath)
                
                # Remove empty directories
                for dirname in dirs:
                    dirpath = os.path.join(root, dirname)
                    os.rmdir(dirpath)
            
            # Remove the root directory
            os.rmdir(dirpath)
            logger.info(f"Securely wiped directory: {dirpath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to wipe directory {dirpath}: {e}")
            return False
    
    @staticmethod
    def wipe_database_records(db_path: str, table: str, condition: str) -> int:
        """Securely wipe database records"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get records to be deleted
            cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE {condition}")
            count = cursor.fetchone()[0]
            
            # Overwrite with random data first
            cursor.execute(
                f"UPDATE {table} SET data = randomblob(length(data)) WHERE {condition}"
            )
            
            # Then delete
            cursor.execute(f"DELETE FROM {table} WHERE {condition}")
            
            # VACUUM to ensure data is removed from free pages
            cursor.execute("VACUUM")
            
            conn.commit()
            conn.close()
            
            logger.info(f"Securely wiped {count} records from {table}")
            return count
            
        except Exception as e:
            logger.error(f"Failed to wipe database records: {e}")
            return 0


class DataRetentionManager:
    """Manages data retention and lifecycle per PCI DSS requirements"""
    
    def __init__(self, retention_db_path: str = "/secure/retention/retention.db"):
        self.db_path = retention_db_path
        self.wiper = SecureDataWiper()
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize retention tracking database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS retention_records (
                record_id TEXT PRIMARY KEY,
                data_type TEXT NOT NULL,
                data_location TEXT NOT NULL,
                creation_date TIMESTAMP NOT NULL,
                scheduled_deletion TIMESTAMP NOT NULL,
                actual_deletion TIMESTAMP,
                deletion_method TEXT,
                verified_by TEXT,
                verification_hash TEXT,
                metadata TEXT
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scheduled_deletion 
            ON retention_records(scheduled_deletion)
        """)
        
        conn.commit()
        conn.close()
    
    def register_data(self, data_type: str, data_location: str, 
                     retention_policy: RetentionPolicy,
                     metadata: Optional[Dict] = None) -> str:
        """Register data for retention tracking"""
        record_id = hashlib.sha256(
            f"{data_type}:{data_location}:{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]
        
        creation_date = datetime.utcnow()
        scheduled_deletion = creation_date + timedelta(days=retention_policy.value)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO retention_records 
            (record_id, data_type, data_location, creation_date, 
             scheduled_deletion, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            record_id,
            data_type,
            data_location,
            creation_date.isoformat(),
            scheduled_deletion.isoformat(),
            json.dumps(metadata or {})
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(
            f"Registered {data_type} for deletion on {scheduled_deletion.date()}"
        )
        
        return record_id
    
    def get_expired_data(self) -> List[Dict]:
        """Get list of data that has exceeded retention period"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT record_id, data_type, data_location, creation_date,
                   scheduled_deletion, metadata
            FROM retention_records
            WHERE scheduled_deletion <= datetime('now')
            AND actual_deletion IS NULL
            ORDER BY scheduled_deletion
        """)
        
        expired_data = []
        for row in cursor.fetchall():
            expired_data.append({
                'record_id': row[0],
                'data_type': row[1],
                'data_location': row[2],
                'creation_date': datetime.fromisoformat(row[3]),
                'scheduled_deletion': datetime.fromisoformat(row[4]),
                'metadata': json.loads(row[5])
            })
        
        conn.close()
        return expired_data
    
    def delete_expired_data(self, verified_by: str, 
                          dry_run: bool = False) -> Dict[str, int]:
        """Delete all expired data"""
        expired_data = self.get_expired_data()
        results = {
            'files_deleted': 0,
            'directories_deleted': 0,
            'database_records_deleted': 0,
            'errors': 0
        }
        
        for data in expired_data:
            try:
                if dry_run:
                    logger.info(
                        f"[DRY RUN] Would delete: {data['data_type']} "
                        f"at {data['data_location']}"
                    )
                    continue
                
                deletion_successful = False
                deletion_method = None
                
                # Determine deletion method based on data location
                if os.path.isfile(data['data_location']):
                    deletion_successful = self.wiper.wipe_file(data['data_location'])
                    deletion_method = "secure_file_wipe"
                    if deletion_successful:
                        results['files_deleted'] += 1
                        
                elif os.path.isdir(data['data_location']):
                    deletion_successful = self.wiper.wipe_directory(data['data_location'])
                    deletion_method = "secure_directory_wipe"
                    if deletion_successful:
                        results['directories_deleted'] += 1
                        
                elif data['data_location'].startswith("db:"):
                    # Database record format: "db:database_path:table:condition"
                    parts = data['data_location'].split(":")
                    if len(parts) >= 4:
                        db_path = parts[1]
                        table = parts[2]
                        condition = ":".join(parts[3:])
                        
                        count = self.wiper.wipe_database_records(
                            db_path, table, condition
                        )
                        deletion_successful = count > 0
                        deletion_method = "secure_database_wipe"
                        results['database_records_deleted'] += count
                
                # Update retention record
                if deletion_successful:
                    self._mark_as_deleted(
                        data['record_id'],
                        deletion_method,
                        verified_by
                    )
                else:
                    results['errors'] += 1
                    
            except Exception as e:
                logger.error(f"Error deleting {data['data_location']}: {e}")
                results['errors'] += 1
        
        return results
    
    def _mark_as_deleted(self, record_id: str, deletion_method: str, 
                        verified_by: str):
        """Mark a retention record as deleted"""
        # Generate verification hash
        verification_data = f"{record_id}:{deletion_method}:{verified_by}"
        verification_hash = hashlib.sha256(verification_data.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE retention_records
            SET actual_deletion = ?,
                deletion_method = ?,
                verified_by = ?,
                verification_hash = ?
            WHERE record_id = ?
        """, (
            datetime.utcnow().isoformat(),
            deletion_method,
            verified_by,
            verification_hash,
            record_id
        ))
        
        conn.commit()
        conn.close()
    
    def archive_audit_logs(self, source_dir: str, archive_dir: str,
                         older_than_days: int = 365) -> str:
        """Archive old audit logs to WORM media"""
        archive_date = datetime.utcnow() - timedelta(days=older_than_days)
        archive_name = f"audit_archive_{archive_date.strftime('%Y%m%d')}.tar.gz"
        archive_path = os.path.join(archive_dir, archive_name)
        
        # Create list of files to archive
        files_to_archive = []
        for filename in os.listdir(source_dir):
            filepath = os.path.join(source_dir, filename)
            if os.path.isfile(filepath):
                file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                if file_mtime < archive_date:
                    files_to_archive.append(filepath)
        
        if not files_to_archive:
            logger.info("No audit logs to archive")
            return ""
        
        # Create archive
        import tarfile
        with tarfile.open(archive_path, "w:gz") as tar:
            for filepath in files_to_archive:
                tar.add(filepath, arcname=os.path.basename(filepath))
        
        # Generate integrity hash
        with open(archive_path, "rb") as f:
            archive_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Write integrity file
        integrity_file = f"{archive_path}.integrity"
        with open(integrity_file, "w") as f:
            json.dump({
                "archive": archive_name,
                "created": datetime.utcnow().isoformat(),
                "file_count": len(files_to_archive),
                "hash": archive_hash,
                "files": [os.path.basename(f) for f in files_to_archive]
            }, f, indent=2)
        
        # Register archive for long-term retention
        self.register_data(
            "audit_archive",
            archive_path,
            RetentionPolicy.AUDIT_LOGS,
            {"integrity_file": integrity_file}
        )
        
        # Delete original files after successful archive
        for filepath in files_to_archive:
            self.wiper.wipe_file(filepath)
        
        logger.info(
            f"Archived {len(files_to_archive)} audit logs to {archive_path}"
        )
        
        return archive_path
    
    def generate_retention_report(self) -> Dict:
        """Generate data retention compliance report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get retention statistics
        cursor.execute("""
            SELECT data_type, 
                   COUNT(*) as total_records,
                   COUNT(CASE WHEN actual_deletion IS NOT NULL THEN 1 END) as deleted,
                   COUNT(CASE WHEN actual_deletion IS NULL 
                              AND scheduled_deletion <= datetime('now') THEN 1 END) as overdue
            FROM retention_records
            GROUP BY data_type
        """)
        
        stats = {}
        for row in cursor.fetchall():
            stats[row[0]] = {
                'total': row[1],
                'deleted': row[2],
                'overdue': row[3]
            }
        
        # Get recent deletions
        cursor.execute("""
            SELECT record_id, data_type, actual_deletion, verified_by
            FROM retention_records
            WHERE actual_deletion IS NOT NULL
            ORDER BY actual_deletion DESC
            LIMIT 10
        """)
        
        recent_deletions = []
        for row in cursor.fetchall():
            recent_deletions.append({
                'record_id': row[0],
                'data_type': row[1],
                'deleted': row[2],
                'verified_by': row[3]
            })
        
        conn.close()
        
        return {
            'generated': datetime.utcnow().isoformat(),
            'statistics': stats,
            'recent_deletions': recent_deletions,
            'compliance_status': 'COMPLIANT' if not any(
                s['overdue'] > 0 for s in stats.values()
            ) else 'NON_COMPLIANT'
        }


# Key rotation management
class KeyRotationManager:
    """Manages cryptographic key rotation"""
    
    def __init__(self, hsm_manager, retention_manager: DataRetentionManager):
        self.hsm = hsm_manager
        self.retention = retention_manager
        self.rotation_history = []
    
    def rotate_encryption_keys(self, key_type: str, operator: str) -> bool:
        """Rotate encryption keys and re-encrypt data"""
        logger.info(f"Starting key rotation for {key_type}")
        
        try:
            # Generate new key in HSM
            old_key, new_key = self.hsm.rotate_keys(key_type)
            
            # Re-encrypt affected data
            affected_count = self._reencrypt_data(old_key, new_key, key_type)
            
            # Record rotation
            rotation_record = {
                'timestamp': datetime.utcnow().isoformat(),
                'key_type': key_type,
                'old_key_ref': old_key,
                'new_key_ref': new_key,
                'operator': operator,
                'affected_records': affected_count
            }
            
            self.rotation_history.append(rotation_record)
            
            # Schedule old key for deletion after grace period
            self.retention.register_data(
                'encryption_key',
                f"hsm:key:{old_key}",
                RetentionPolicy.CARDHOLDER_DATA,
                rotation_record
            )
            
            logger.info(f"Key rotation completed. {affected_count} records re-encrypted")
            return True
            
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            return False
    
    def _reencrypt_data(self, old_key: str, new_key: str, 
                       key_type: str) -> int:
        """Re-encrypt data with new key"""
        # This would interface with the actual data storage
        # to re-encrypt all affected records
        count = 0
        
        # Simulated re-encryption process
        logger.info(f"Re-encrypting data from {old_key} to {new_key}")
        
        return count


# Example usage
if __name__ == "__main__":
    # Initialize retention manager
    retention_mgr = DataRetentionManager()
    
    # Register some test data
    retention_mgr.register_data(
        "transaction_log",
        "/secure/logs/transactions_20240101.log",
        RetentionPolicy.TRANSACTION_DATA
    )
    
    retention_mgr.register_data(
        "audit_log",
        "/secure/audit/audit_20240101.log",
        RetentionPolicy.AUDIT_LOGS
    )
    
    # Check expired data
    expired = retention_mgr.get_expired_data()
    print(f"Expired data items: {len(expired)}")
    
    # Delete expired data (dry run)
    results = retention_mgr.delete_expired_data("security_officer", dry_run=True)
    print(f"Deletion results (dry run): {results}")
    
    # Generate retention report
    report = retention_mgr.generate_retention_report()
    print(f"Retention report: {json.dumps(report, indent=2)}")
    
    # Archive old audit logs
    archive_path = retention_mgr.archive_audit_logs(
        "/secure/audit/logs",
        "/secure/audit/archives",
        older_than_days=365
    )
    if archive_path:
        print(f"Created archive: {archive_path}")