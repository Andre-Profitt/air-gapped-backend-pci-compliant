# Air-Gapped PCI Compliant Backend

A production-ready, air-gapped payment processing backend that meets PCI DSS 3.2.1 compliance requirements.

## 🚀 Overview

This system implements a completely isolated payment processing environment with:
- ✅ Zero network connectivity (true air-gap)
- ✅ Hardware Security Module (HSM) integration
- ✅ Multi-factor authentication
- ✅ Blockchain-based audit trail
- ✅ Secure media transfer station
- ✅ Full PCI DSS compliance

## 🆕 Enhanced Components

We've added enterprise-grade enhancements in the `src/enhancements/` directory:

- **HSM Integration** - Production-ready Hardware Security Module support
- **Data Retention Manager** - Automated lifecycle management with secure wiping
- **Incident Response Plan** - Complete procedures for security incidents
- **Air-Gap Validator** - Automated network isolation verification
- **Compliance Automation** - Automated PCI DSS compliance checking

See [Enhancement Documentation](src/enhancements/README.md) for details.

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│         Air-Gapped Environment          │
│                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────┐ │
│  │   Core   │  │  Audit   │  │ HSM  │ │
│  │ Backend  │  │ Processor│  │      │ │
│  └──────────┘  └──────────┘  └──────┘ │
│                                         │
│  ┌────────────────────────────────────┐│
│  │     Secure Transfer Station        ││
│  └────────────────────────────────────┘│
└─────────────────────────────────────────┘
```

## 🎯 Quick Demo

Want to see it in action? Run the demo:

```bash
# Run the automated demo setup
cd demo/
chmod +x setup_demo.sh
./setup_demo.sh

# Start the demo
cd pci-backend-demo/
./run_demo.sh
```

## 🔐 Security Features

### Cryptography
- AES-256-GCM for data encryption
- RSA-4096 for key wrapping
- PBKDF2-SHA256 for key derivation
- Hardware Security Module (HSM) for key management

### Authentication
- Multi-factor authentication (MFA)
- Biometric verification
- Hardware token support
- Role-based access control (RBAC)

### Audit Trail
- Blockchain-based immutable logging
- Cryptographic integrity verification
- 7-year retention policy
- Write-once media archival

## 📋 Compliance

This system addresses all 12 PCI DSS requirements:

1. ✓ Firewall configuration (physical isolation)
2. ✓ No default passwords
3. ✓ Cardholder data protection
4. ✓ Encrypted transmission
5. ✓ Antivirus (read-only system)
6. ✓ Secure development
7. ✓ Access control
8. ✓ User authentication
9. ✓ Physical access controls
10. ✓ Logging and monitoring
11. ✓ Security testing
12. ✓ Security policy

## 🛠️ Production Deployment

### Prerequisites
- RHEL 8+ or Ubuntu 20.04+
- HSM device (e.g., Thales Luna, Utimaco)
- Biometric readers
- Secure facility
- Write-once optical media drives

### Installation

1. **Prepare the air-gapped system**
   ```bash
   sudo ./scripts/setup.sh
   ```

2. **Validate air-gap integrity**
   ```bash
   sudo ./src/enhancements/airgap_validator.sh
   ```

3. **Build containers**
   ```bash
   make build
   ```

4. **Run security validation**
   ```bash
   make security-scan
   ```

5. **Deploy**
   ```bash
   make deploy-prod
   ```

## 📁 Project Structure

```
.
├── src/                    # Core application source
│   ├── pci_backend.py     # Main backend implementation
│   └── enhancements/      # Enterprise enhancements
│       ├── hsm_integration.py
│       ├── data_retention_manager.py
│       ├── incident_response_plan.md
│       ├── airgap_validator.sh
│       └── compliance_automation.py
├── demo/                   # Demo environment
│   └── setup_demo.sh      # Automated demo setup
├── docker/                 # Container configurations
│   ├── Dockerfile.secure  # Hardened container
│   └── docker-compose.yml # Orchestration
├── config/                 # Configuration files
│   └── pci-config.yaml    # Application config
├── scripts/                # Deployment scripts
│   ├── setup.sh           # System setup
│   └── security_validator.py # Security validation
├── tests/                  # Test suites
│   └── compliance_tests.py # PCI compliance tests
├── terraform/              # Infrastructure as Code
├── ansible/                # Configuration management
└── docs/                   # Documentation
```

## 📚 Documentation

- [Architecture Documentation](docs/ARCHITECTURE.md)
- [Security Guide](docs/SECURITY.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [API Reference](docs/API.md)
- [Compliance Documentation](docs/COMPLIANCE.md)
- [Enhancement Guide](src/enhancements/README.md)

## 🧪 Testing

Run the complete test suite:
```bash
make test
```

Run compliance tests only:
```bash
python -m pytest tests/compliance_tests.py -v
```

Run automated compliance check:
```bash
python src/enhancements/compliance_automation.py --executive-summary
```

## ⚠️ Security Considerations

- **Never connect to any network**
- **All data transfers via encrypted media only**
- **Minimum two-person integrity for all operations**
- **Regular security audits required**
- **Physical security is paramount**

## 📄 License

This software is provided for demonstration and educational purposes.

## 🤝 Support

For PCI compliance questions, consult your QSA (Qualified Security Assessor).

---

**Remember: The security of this system depends on maintaining complete physical and logical isolation.**
