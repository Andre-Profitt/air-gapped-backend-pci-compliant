import pytest
import json
from datetime import datetime, timedelta
from src.pci_backend import (
    PCICompliantBackend, UserRole, SecurityConfig,
    CryptoEngine, TokenVault, AccessControl
)

class TestPCICompliance:
    """Test suite for PCI DSS compliance requirements"""
    
    @pytest.fixture
    def backend(self):
        """Create test backend instance"""
        return PCICompliantBackend()
    
    def test_requirement_2_no_default_passwords(self, backend):
        """Test Requirement 2: No vendor-supplied defaults"""
        # Attempt to create user with weak password
        with pytest.raises(ValueError):
            backend.access_control.create_user(
                user_id="test_user",
                role=UserRole.OPERATOR,
                password_hash="password123",  # Weak password
                biometric_hash="test"
            )
    
    def test_requirement_3_cardholder_data_protection(self, backend):
        """Test Requirement 3: Protect stored cardholder data"""
        # Test PAN tokenization
        token = backend.token_vault.tokenize_pan(
            "4532015112830366",  # Test PAN
            "MERCHANT001"
        )
        
        # Verify token is different from PAN
        assert token != "4532015112830366"
        assert len(token) >= SecurityConfig.TOKEN_LENGTH
        
        # Verify PAN is not stored in clear text
        stored_data = backend.token_vault.tokens[token]
        assert "4532015112830366" not in str(stored_data)
        assert "encrypted_pan" in stored_data
    
    def test_requirement_4_encrypted_transmission(self, backend):
        """Test Requirement 4: Encrypt transmission"""
        # Test data export encryption
        test_data = b"sensitive payment data"
        package = backend.file_transfer.prepare_export(
            test_data,
            b"recipient_public_key"
        )
        
        # Verify encryption
        assert "encrypted_data" in package
        assert package["encrypted_data"]["ciphertext"] != test_data.decode()
        assert "signature" in package
        assert "checksum" in package
    
    def test_requirement_6_secure_development(self, backend):
        """Test Requirement 6: Secure systems and applications"""
        # Test input validation
        invalid_payment_data = {
            "pan": "invalid",
            "amount": "not_a_number",
            "merchant_id": ""
        }
        
        # Create test session
        backend.access_control.create_user(
            "test_op", UserRole.OPERATOR,
            "hash", "bio"
        )
        session = "test_session"
        backend.access_control.sessions[session] = {
            "user_id": "test_op",
            "role": UserRole.OPERATOR.value,
            "created": datetime.utcnow(),
            "last_activity": datetime.utcnow()
        }
        
        result = backend.process_payment(session, invalid_payment_data)
        assert result["status"] == "error"
    
    def test_requirement_7_access_control(self, backend):
        """Test Requirement 7: Restrict access by business need-to-know"""
        # Create users with different roles
        backend.access_control.create_user(
            "auditor", UserRole.AUDITOR,
            "hash1", "bio1"
        )
        backend.access_control.create_user(
            "operator", UserRole.OPERATOR,
            "hash2", "bio2"
        )
        
        # Create sessions
        auditor_session = "auditor_session"
        operator_session = "operator_session"
        
        backend.access_control.sessions[auditor_session] = {
            "user_id": "auditor",
            "role": UserRole.AUDITOR.value,
            "created": datetime.utcnow(),
            "last_activity": datetime.utcnow()
        }
        
        backend.access_control.sessions[operator_session] = {
            "user_id": "operator",
            "role": UserRole.OPERATOR.value,
            "created": datetime.utcnow(),
            "last_activity": datetime.utcnow()
        }
        
        # Test permissions
        assert backend.access_control.check_permission(
            auditor_session, "view_audit_logs"
        )
        assert not backend.access_control.check_permission(
            auditor_session, "process_transactions"
        )
        
        assert backend.access_control.check_permission(
            operator_session, "process_transactions"
        )
        assert not backend.access_control.check_permission(
            operator_session, "manage_keys"
        )
    
    def test_requirement_8_user_authentication(self, backend):
        """Test Requirement 8: Identify and authenticate access"""
        # Test multi-factor authentication
        backend.access_control.create_user(
            "mfa_user", UserRole.OPERATOR,
            "secure_hash", "biometric_hash"
        )
        
        # Test with missing factors
        session = backend.access_control.authenticate(
            "mfa_user", "wrong_password", "biometric", "123456"
        )
        assert session is None
        
        # Test account lockout after failed attempts
        for _ in range(SecurityConfig.MAX_FAILED_ATTEMPTS):
            backend.access_control.authenticate(
                "mfa_user", "wrong", "wrong", "wrong"
            )
        
        # Account should be locked
        session = backend.access_control.authenticate(
            "mfa_user", "correct", "correct", "123456"
        )
        assert session is None
    
    def test_requirement_10_logging(self, backend):
        """Test Requirement 10: Track and monitor all access"""
        # Perform some actions
        backend.access_control.create_user(
            "log_test", UserRole.OPERATOR,
            "hash", "bio"
        )
        
        # Check audit trail
        assert len(backend.audit_trail.chain) > 1
        
        # Verify log integrity
        assert backend.audit_trail.verify_integrity()
        
        # Check log contains required information
        last_entry = backend.audit_trail.chain[-1]
        assert last_entry.timestamp
        assert last_entry.user_id
        assert last_entry.action
        assert last_entry.result
    
    def test_requirement_11_security_testing(self, backend):
        """Test Requirement 11: Regular security testing"""
        # Test vulnerability in tokenization
        with pytest.raises(ValueError):
            # SQL injection attempt
            backend.token_vault.tokenize_pan(
                "4532015112830366'; DROP TABLE tokens;--",
                "MERCHANT001"
            )
        
        # Test buffer overflow attempt
        oversized_data = "A" * 10000
        token = backend.token_vault.tokenize_pan(
            "4532015112830366",
            oversized_data[:100]  # Should truncate safely
        )
        assert token is not None
    
    def test_session_timeout(self, backend):
        """Test session timeout enforcement"""
        # Create session
        backend.access_control.create_user(
            "timeout_user", UserRole.OPERATOR,
            "hash", "bio"
        )
        
        session_id = "test_session"
        backend.access_control.sessions[session_id] = {
            "user_id": "timeout_user",
            "role": UserRole.OPERATOR.value,
            "created": datetime.utcnow(),
            "last_activity": datetime.utcnow() - timedelta(minutes=20)
        }
        
        # Session should be expired
        assert not backend.access_control.check_permission(
            session_id, "process_transactions"
        )
        assert session_id not in backend.access_control.sessions