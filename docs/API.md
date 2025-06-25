# API Reference

## Overview

The PCI Compliant Backend provides a secure API for payment processing operations. All API interactions occur through the air-gapped system via secure media exchange.

## Authentication

### Multi-Factor Authentication

```python
def authenticate(user_id: str, password: str, 
                biometric_data: str, hardware_token: str) -> Optional[str]:
    """
    Authenticate user with multi-factor authentication
    
    Args:
        user_id: Unique user identifier
        password: User password (will be hashed)
        biometric_data: Biometric scan data
        hardware_token: 6-digit hardware token
    
    Returns:
        Session ID if successful, None otherwise
    """
```

## Core Operations

### Tokenization

```python
def tokenize_pan(session_id: str, pan: str, merchant_id: str) -> str:
    """
    Tokenize a Primary Account Number (PAN)
    
    Args:
        session_id: Valid session ID
        pan: Primary Account Number (13-19 digits)
        merchant_id: Merchant identifier
    
    Returns:
        Secure token for the PAN
    
    Raises:
        ValueError: Invalid PAN format
        PermissionError: Insufficient permissions
    """
```

### Payment Processing

```python
def process_payment(session_id: str, payment_data: Dict) -> Dict:
    """
    Process a payment transaction
    
    Args:
        session_id: Valid session ID
        payment_data: {
            "pan": str,           # or "token": str
            "amount": float,
            "currency": str,
            "merchant_id": str,
            "reference": str
        }
    
    Returns:
        {
            "status": "success" | "error",
            "transaction_id": str,
            "timestamp": str,
            "token": str  # if PAN was provided
        }
    """
```

## Administrative Functions

### User Management

```python
def create_user(session_id: str, user_data: Dict) -> bool:
    """
    Create a new user account
    
    Args:
        session_id: Admin session ID
        user_data: {
            "user_id": str,
            "role": "operator" | "auditor" | "security_officer",
            "biometric_data": str,
            "contact_info": Dict
        }
    
    Returns:
        True if successful
    
    Requires:
        security_officer role
    """
```

### Audit Operations

```python
def get_audit_report(session_id: str, filters: Dict = None) -> Dict:
    """
    Generate audit report
    
    Args:
        session_id: Valid session ID
        filters: {
            "start_date": str,
            "end_date": str,
            "event_types": List[str],
            "users": List[str]
        }
    
    Returns:
        Comprehensive audit report
    
    Requires:
        auditor or security_officer role
    """
```

## Data Transfer

### Export Data

```python
def prepare_export(session_id: str, data: bytes, 
                  recipient_public_key: bytes) -> Dict:
    """
    Prepare data for secure export
    
    Args:
        session_id: Valid session ID
        data: Data to export
        recipient_public_key: Recipient's public key
    
    Returns:
        Encrypted package for transfer
    """
```

### Import Data

```python
def verify_import(session_id: str, package: Dict) -> Optional[bytes]:
    """
    Verify and import data from external media
    
    Args:
        session_id: Valid session ID
        package: Encrypted package from external source
    
    Returns:
        Decrypted data if valid, None otherwise
    """
```

## Error Handling

### Error Codes

| Code | Description |
|------|-------------|
| 401 | Authentication required |
| 403 | Insufficient permissions |
| 404 | Resource not found |
| 422 | Invalid input data |
| 500 | Internal error |

### Error Response Format

```json
{
    "error": {
        "code": 422,
        "message": "Invalid PAN format",
        "details": {
            "field": "pan",
            "reason": "Failed Luhn check"
        }
    }
}
```

## Security Considerations

1. All API calls are logged in the audit trail
2. Session timeout is enforced (15 minutes)
3. Rate limiting prevents brute force attacks
4. Input validation on all parameters
5. No sensitive data in responses

## Integration Examples

### Python Client

```python
from pci_backend import PCICompliantBackend

# Initialize client
backend = PCICompliantBackend()

# Authenticate
session = backend.authenticate(
    user_id="operator1",
    password="SecurePass123!",
    biometric_data=biometric_scan(),
    hardware_token=get_token()
)

# Process payment
if session:
    result = backend.process_payment(session, {
        "pan": "4532015112830366",
        "amount": 100.00,
        "currency": "USD",
        "merchant_id": "MERCH001",
        "reference": "ORDER-12345"
    })
    
    print(f"Transaction: {result['transaction_id']}")
    print(f"Token: {result['token']}")
```