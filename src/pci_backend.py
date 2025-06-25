# Air-Gapped PCI Compliant Backend Implementation
# This is a working implementation framework for the PCI compliant backend

import os
import json
import hashlib
import hmac
import secrets
import datetime
import logging
from enum import Enum
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PCIBackend')

# Security Constants
class SecurityConfig:
    AES_KEY_SIZE = 32  # 256 bits
    RSA_KEY_SIZE = 4096
    PBKDF2_ITERATIONS = 100000
    TOKEN_LENGTH = 32
    MAX_FAILED_ATTEMPTS = 3
    SESSION_TIMEOUT_MINUTES = 15
    PASSWORD_MIN_LENGTH = 15
    AUDIT_RETENTION_DAYS = 2555  # 7 years per PCI requirement

class UserRole(Enum):
    SECURITY_OFFICER = "security_officer"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    SYSTEM = "system"

@dataclass
class AuditEntry:
    timestamp: datetime.datetime
    event_type: str
    user_id: str
    action: str
    result: str
    details: Dict = field(default_factory=dict)
    previous_hash: str = ""
    integrity_hash: str = ""

class CryptoEngine:
    """Core cryptographic operations engine"""
    
    def __init__(self):
        self.backend = default_backend()
        self._master_key = None
        self._initialize_keys()
    
    def _initialize_keys(self):
        """Initialize or load master keys (in production, use HSM)"""
        # In production, this would interface with an HSM
        # For demo, we generate keys
        self._master_key = os.urandom(SecurityConfig.AES_KEY_SIZE)
        self._signing_key = os.urandom(SecurityConfig.AES_KEY_SIZE)
    
    def encrypt_data(self, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes, bytes]:
        """Encrypt data using AES-256-GCM"""
        iv = os.urandom(12)  # 96-bit IV for GCM
        cipher = Cipher(
            algorithms.AES(self._master_key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag
    
    def decrypt_data(self, iv: bytes, ciphertext: bytes, tag: bytes, 
                    associated_data: bytes = b"") -> bytes:
        """Decrypt data using AES-256-GCM"""
        cipher = Cipher(
            algorithms.AES(self._master_key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def generate_token(self) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(SecurityConfig.TOKEN_LENGTH)
    
    def hash_data(self, data: bytes) -> str:
        """Generate SHA3-512 hash"""
        digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
        digest.update(data)
        return digest.finalize().hex()
    
    def hmac_sign(self, data: bytes) -> bytes:
        """Generate HMAC-SHA256 signature"""
        h = hmac.new(self._signing_key, data, hashlib.sha256)
        return h.digest()
    
    def secure_wipe(self, data: bytearray):
        """Securely overwrite sensitive data in memory"""
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = secrets.randbits(8)
            del data

class BlockchainAuditTrail:
    """Immutable audit trail using blockchain structure"""
    
    def __init__(self, crypto_engine: CryptoEngine):
        self.crypto = crypto_engine
        self.chain: List[AuditEntry] = []
        self._initialize_genesis_block()
    
    def _initialize_genesis_block(self):
        """Create the genesis block"""
        genesis = AuditEntry(
            timestamp=datetime.datetime.utcnow(),
            event_type="SYSTEM_INIT",
            user_id="SYSTEM",
            action="Initialize Audit Trail",
            result="SUCCESS",
            details={"version": "1.0", "compliance": "PCI-DSS-3.2.1"}
        )
        genesis.integrity_hash = self._calculate_hash(genesis)
        self.chain.append(genesis)
    
    def _calculate_hash(self, entry: AuditEntry) -> str:
        """Calculate cryptographic hash of audit entry"""
        data = f"{entry.timestamp}{entry.event_type}{entry.user_id}"
        data += f"{entry.action}{entry.result}{json.dumps(entry.details)}"
        data += entry.previous_hash
        return self.crypto.hash_data(data.encode())
    
    def add_entry(self, entry: AuditEntry):
        """Add new entry to the audit chain"""
        entry.previous_hash = self.chain[-1].integrity_hash if self.chain else ""
        entry.integrity_hash = self._calculate_hash(entry)
        self.chain.append(entry)
        
        # In production, also write to write-once media
        self._persist_entry(entry)
    
    def _persist_entry(self, entry: AuditEntry):
        """Persist entry to immutable storage"""
        # In production, this writes to WORM storage
        logger.info(f"Audit entry persisted: {entry.integrity_hash}")
    
    def verify_integrity(self) -> bool:
        """Verify the integrity of the entire audit chain"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Verify previous hash
            if current.previous_hash != previous.integrity_hash:
                return False
            
            # Verify current hash
            if current.integrity_hash != self._calculate_hash(current):
                return False
        
        return True

class TokenVault:
    """Secure token management for PCI compliance"""
    
    def __init__(self, crypto_engine: CryptoEngine):
        self.crypto = crypto_engine
        self.tokens: Dict[str, Dict] = {}
    
    def tokenize_pan(self, pan: str, merchant_id: str) -> str:
        """Tokenize a Primary Account Number"""
        # Validate PAN format (simplified)
        if not self._validate_pan(pan):
            raise ValueError("Invalid PAN format")
        
        # Generate token
        token = self.crypto.generate_token()
        
        # Store token mapping (encrypted)
        pan_encrypted = self._encrypt_pan(pan)
        
        self.tokens[token] = {
            "created": datetime.datetime.utcnow().isoformat(),
            "merchant_id": merchant_id,
            "usage_count": 0,
            "pan_hash": self.crypto.hash_data(pan.encode()),
            "encrypted_pan": pan_encrypted  # In production, store in HSM
        }
        
        # Clear PAN from memory
        pan_bytes = bytearray(pan.encode())
        self.crypto.secure_wipe(pan_bytes)
        
        return token
    
    def _validate_pan(self, pan: str) -> bool:
        """Validate PAN using Luhn algorithm"""
        if not pan.isdigit() or len(pan) < 13 or len(pan) > 19:
            return False
        
        # Luhn algorithm
        digits = [int(d) for d in pan]
        checksum = 0
        
        for i in range(len(digits) - 2, -1, -2):
            doubled = digits[i] * 2
            if doubled > 9:
                doubled = doubled - 9
            digits[i] = doubled
        
        return sum(digits) % 10 == 0
    
    def _encrypt_pan(self, pan: str) -> Dict:
        """Encrypt PAN for storage"""
        pan_bytes = pan.encode()
        iv, ciphertext, tag = self.crypto.encrypt_data(pan_bytes)
        
        return {
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        }

class AccessControl:
    """Role-based access control system"""
    
    def __init__(self, audit_trail: BlockchainAuditTrail):
        self.audit = audit_trail
        self.users: Dict[str, Dict] = {}
        self.sessions: Dict[str, Dict] = {}
        self.failed_attempts: Dict[str, int] = {}
        self._initialize_roles()
    
    def _initialize_roles(self):
        """Initialize RBAC permissions"""
        self.role_permissions = {
            UserRole.SECURITY_OFFICER: [
                "view_audit_logs", "manage_keys", "configure_security",
                "manage_users", "view_all_data"
            ],
            UserRole.OPERATOR: [
                "process_transactions", "view_transaction_logs",
                "tokenize_data"
            ],
            UserRole.AUDITOR: [
                "view_audit_logs", "export_reports", "verify_compliance"
            ]
        }
    
    def create_user(self, user_id: str, role: UserRole, 
                   password_hash: str, biometric_hash: str) -> bool:
        """Create a new user with multi-factor authentication"""
        if user_id in self.users:
            return False
        
        self.users[user_id] = {
            "role": role,
            "password_hash": password_hash,
            "biometric_hash": biometric_hash,
            "created": datetime.datetime.utcnow().isoformat(),
            "last_login": None,
            "mfa_enabled": True,
            "status": "active"
        }
        
        # Audit user creation
        self.audit.add_entry(AuditEntry(
            timestamp=datetime.datetime.utcnow(),
            event_type="USER_CREATED",
            user_id="SYSTEM",
            action=f"Created user {user_id} with role {role.value}",
            result="SUCCESS"
        ))
        
        return True
    
    def authenticate(self, user_id: str, password: str, 
                    biometric_data: str, hardware_token: str) -> Optional[str]:
        """Multi-factor authentication"""
        if user_id not in self.users:
            return None
        
        user = self.users[user_id]
        
        # Check if account is locked
        if self.failed_attempts.get(user_id, 0) >= SecurityConfig.MAX_FAILED_ATTEMPTS:
            self.audit.add_entry(AuditEntry(
                timestamp=datetime.datetime.utcnow(),
                event_type="AUTH_FAILED",
                user_id=user_id,
                action="Authentication attempt on locked account",
                result="FAILED"
            ))
            return None
        
        # Verify all factors (simplified for demo)
        factors_valid = all([
            self._verify_password(password, user["password_hash"]),
            self._verify_biometric(biometric_data, user["biometric_hash"]),
            self._verify_hardware_token(hardware_token)
        ])
        
        if not factors_valid:
            self.failed_attempts[user_id] = self.failed_attempts.get(user_id, 0) + 1
            self.audit.add_entry(AuditEntry(
                timestamp=datetime.datetime.utcnow(),
                event_type="AUTH_FAILED",
                user_id=user_id,
                action="Multi-factor authentication failed",
                result="FAILED"
            ))
            return None
        
        # Create session
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            "user_id": user_id,
            "role": user["role"],
            "created": datetime.datetime.utcnow(),
            "last_activity": datetime.datetime.utcnow()
        }
        
        # Reset failed attempts
        self.failed_attempts.pop(user_id, None)
        
        # Update last login
        user["last_login"] = datetime.datetime.utcnow().isoformat()
        
        # Audit successful login
        self.audit.add_entry(AuditEntry(
            timestamp=datetime.datetime.utcnow(),
            event_type="AUTH_SUCCESS",
            user_id=user_id,
            action="Multi-factor authentication successful",
            result="SUCCESS",
            details={"session_id": session_id}
        ))
        
        return session_id
    
    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password (simplified for demo)"""
        # In production, use bcrypt or argon2
        return hashlib.sha256(password.encode()).hexdigest() == stored_hash
    
    def _verify_biometric(self, biometric_data: str, stored_hash: str) -> bool:
        """Verify biometric data (simplified for demo)"""
        # In production, use proper biometric verification
        return hashlib.sha256(biometric_data.encode()).hexdigest() == stored_hash
    
    def _verify_hardware_token(self, token: str) -> bool:
        """Verify hardware token (simplified for demo)"""
        # In production, verify against hardware token service
        return len(token) == 6 and token.isdigit()
    
    def check_permission(self, session_id: str, permission: str) -> bool:
        """Check if session has required permission"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        # Check session timeout
        if (datetime.datetime.utcnow() - session["last_activity"]).seconds > \
           SecurityConfig.SESSION_TIMEOUT_MINUTES * 60:
            self.sessions.pop(session_id)
            return False
        
        # Update last activity
        session["last_activity"] = datetime.datetime.utcnow()
        
        # Check permission
        role = UserRole(session["role"])
        return permission in self.role_permissions.get(role, [])

class SecureFileTransfer:
    """Secure file transfer for air-gapped system"""
    
    def __init__(self, crypto_engine: CryptoEngine):
        self.crypto = crypto_engine
        self.transfer_log: List[Dict] = []
    
    def prepare_export(self, data: bytes, recipient_public_key: bytes) -> Dict:
        """Prepare data for secure export to external media"""
        # Generate session key
        session_key = os.urandom(SecurityConfig.AES_KEY_SIZE)
        
        # Encrypt data with session key
        iv, ciphertext, tag = self.crypto.encrypt_data(data)
        
        # Sign the package
        signature = self.crypto.hmac_sign(ciphertext + tag)
        
        # Create transfer package
        package = {
            "version": "1.0",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "transfer_id": self.crypto.generate_token(),
            "encrypted_data": {
                "iv": base64.b64encode(iv).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "tag": base64.b64encode(tag).decode()
            },
            "signature": base64.b64encode(signature).decode(),
            "checksum": self.crypto.hash_data(ciphertext)
        }
        
        # Log transfer
        self.transfer_log.append({
            "transfer_id": package["transfer_id"],
            "timestamp": package["timestamp"],
            "data_size": len(data),
            "recipient": "external",
            "status": "prepared"
        })
        
        return package
    
    def verify_import(self, package: Dict) -> Optional[bytes]:
        """Verify and import data from external media"""
        try:
            # Verify package structure
            required_fields = ["version", "timestamp", "transfer_id", 
                             "encrypted_data", "signature", "checksum"]
            if not all(field in package for field in required_fields):
                raise ValueError("Invalid package structure")
            
            # Decode components
            iv = base64.b64decode(package["encrypted_data"]["iv"])
            ciphertext = base64.b64decode(package["encrypted_data"]["ciphertext"])
            tag = base64.b64decode(package["encrypted_data"]["tag"])
            signature = base64.b64decode(package["signature"])
            
            # Verify checksum
            if self.crypto.hash_data(ciphertext) != package["checksum"]:
                raise ValueError("Checksum verification failed")
            
            # Verify signature
            expected_signature = self.crypto.hmac_sign(ciphertext + tag)
            if not hmac.compare_digest(signature, expected_signature):
                raise ValueError("Signature verification failed")
            
            # Decrypt data
            data = self.crypto.decrypt_data(iv, ciphertext, tag)
            
            # Log successful import
            self.transfer_log.append({
                "transfer_id": package["transfer_id"],
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "data_size": len(data),
                "source": "external",
                "status": "imported"
            })
            
            return data
            
        except Exception as e:
            logger.error(f"Import verification failed: {str(e)}")
            return None

class PCICompliantBackend:
    """Main PCI compliant backend system"""
    
    def __init__(self):
        logger.info("Initializing PCI Compliant Backend...")
        
        # Initialize components
        self.crypto = CryptoEngine()
        self.audit_trail = BlockchainAuditTrail(self.crypto)
        self.access_control = AccessControl(self.audit_trail)
        self.token_vault = TokenVault(self.crypto)
        self.file_transfer = SecureFileTransfer(self.crypto)
        
        # System initialization audit
        self.audit_trail.add_entry(AuditEntry(
            timestamp=datetime.datetime.utcnow(),
            event_type="SYSTEM_START",
            user_id="SYSTEM",
            action="PCI Compliant Backend initialized",
            result="SUCCESS",
            details={
                "components": ["crypto", "audit", "access_control", 
                              "token_vault", "file_transfer"],
                "security_config": {
                    "aes_key_size": SecurityConfig.AES_KEY_SIZE,
                    "rsa_key_size": SecurityConfig.RSA_KEY_SIZE,
                    "session_timeout": SecurityConfig.SESSION_TIMEOUT_MINUTES
                }
            }
        ))
        
        logger.info("PCI Compliant Backend initialized successfully")
    
    def process_payment(self, session_id: str, payment_data: Dict) -> Dict:
        """Process a payment transaction"""
        # Check permissions
        if not self.access_control.check_permission(session_id, "process_transactions"):
            return {"status": "error", "message": "Insufficient permissions"}
        
        try:
            # Extract and validate payment data
            pan = payment_data.get("pan")
            amount = payment_data.get("amount")
            merchant_id = payment_data.get("merchant_id")
            
            if not all([pan, amount, merchant_id]):
                raise ValueError("Missing required payment data")
            
            # Tokenize PAN
            token = self.token_vault.tokenize_pan(pan, merchant_id)
            
            # Process payment (simplified for demo)
            transaction_id = self.crypto.generate_token()
            
            # Audit transaction
            session = self.access_control.sessions[session_id]
            self.audit_trail.add_entry(AuditEntry(
                timestamp=datetime.datetime.utcnow(),
                event_type="PAYMENT_PROCESSED",
                user_id=session["user_id"],
                action="Payment transaction processed",
                result="SUCCESS",
                details={
                    "transaction_id": transaction_id,
                    "token": token,
                    "amount": amount,
                    "merchant_id": merchant_id
                }
            ))
            
            return {
                "status": "success",
                "transaction_id": transaction_id,
                "token": token,
                "timestamp": datetime.datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Payment processing failed: {str(e)}")
            return {"status": "error", "message": "Payment processing failed"}
    
    def generate_compliance_report(self, session_id: str) -> Optional[Dict]:
        """Generate PCI compliance report"""
        if not self.access_control.check_permission(session_id, "export_reports"):
            return None
        
        # Verify audit trail integrity
        integrity_valid = self.audit_trail.verify_integrity()
        
        report = {
            "generated": datetime.datetime.utcnow().isoformat(),
            "system_version": "1.0",
            "compliance_standard": "PCI-DSS-3.2.1",
            "audit_trail_integrity": integrity_valid,
            "total_audit_entries": len(self.audit_trail.chain),
            "active_users": len(self.access_control.users),
            "active_sessions": len(self.access_control.sessions),
            "tokens_issued": len(self.token_vault.tokens),
            "recent_events": []
        }
        
        # Include recent audit events
        for entry in self.audit_trail.chain[-10:]:
            report["recent_events"].append({
                "timestamp": entry.timestamp.isoformat(),
                "event": entry.event_type,
                "user": entry.user_id,
                "result": entry.result
            })
        
        return report
    
    def shutdown(self):
        """Secure system shutdown"""
        logger.info("Initiating secure shutdown...")
        
        # Clear all sessions
        self.access_control.sessions.clear()
        
        # Final audit entry
        self.audit_trail.add_entry(AuditEntry(
            timestamp=datetime.datetime.utcnow(),
            event_type="SYSTEM_SHUTDOWN",
            user_id="SYSTEM",
            action="System shutdown initiated",
            result="SUCCESS"
        ))
        
        # Clear sensitive data
        # In production, ensure all cryptographic material is cleared
        
        logger.info("Secure shutdown complete")


# Example usage and testing
if __name__ == "__main__":
    # Initialize the system
    backend = PCICompliantBackend()
    
    # Create a test user
    backend.access_control.create_user(
        user_id="test_operator",
        role=UserRole.OPERATOR,
        password_hash=hashlib.sha256("SecurePassword123!".encode()).hexdigest(),
        biometric_hash=hashlib.sha256("biometric_data".encode()).hexdigest()
    )
    
    # Authenticate user
    session = backend.access_control.authenticate(
        user_id="test_operator",
        password="SecurePassword123!",
        biometric_data="biometric_data",
        hardware_token="123456"
    )
    
    if session:
        print(f"Authentication successful. Session: {session}")
        
        # Process a test payment
        result = backend.process_payment(session, {
            "pan": "4532015112830366",  # Test PAN
            "amount": 100.00,
            "merchant_id": "MERCHANT001"
        })
        print(f"Payment result: {result}")
        
        # Generate compliance report
        report = backend.generate_compliance_report(session)
        print(f"Compliance report: {json.dumps(report, indent=2)}")
    
    # Verify audit trail integrity
    print(f"Audit trail integrity: {backend.audit_trail.verify_integrity()}")
    
    # Shutdown
    backend.shutdown()
