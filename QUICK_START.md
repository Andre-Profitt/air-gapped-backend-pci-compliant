# 🚀 Quick Start Guide

## Demo in Under 5 Minutes

Want to see the PCI compliant backend in action? Follow these steps:

### 1. Clone the Repository

```bash
git clone https://github.com/Andre-Profitt/air-gapped-backend-pci-compliant.git
cd air-gapped-backend-pci-compliant
```

### 2. Run the Demo Setup

```bash
cd demo/
chmod +x setup_demo.sh
./setup_demo.sh
```

This will:
- ✅ Check system requirements
- ✅ Create a virtual environment
- ✅ Install dependencies
- ✅ Set up the demo application

### 3. Start the Demo

```bash
cd pci-backend-demo/
./run_interactive.sh
```

### 4. Try It Out!

#### Login as Operator
```bash
python src/demo_cli.py login
# Username: operator
# Password: Operator123!
```

#### Tokenize a Credit Card
```bash
python src/demo_cli.py tokenize 4532015112830366
```

You'll see:
```
💳 Tokenizing PAN
PAN: ************0366
✅ Tokenization successful!
Token: TOK_xxxxxxxxxxxxxxxx
```

#### Try to Access Audit (Will Fail - Wrong Role!)
```bash
python src/demo_cli.py audit
# ❌ Access denied - insufficient permissions
```

#### Switch to Auditor
```bash
python src/demo_cli.py logout
python src/demo_cli.py login
# Username: auditor
# Password: Auditor123!
```

#### Now View Audit Report
```bash
python src/demo_cli.py audit
```

## What You Just Saw

- 🔐 **Multi-user authentication** with role-based access
- 💳 **PAN tokenization** converting credit cards to secure tokens
- 📊 **Audit trail** tracking all system activities
- 🚫 **Access control** preventing unauthorized operations

## Next Steps

1. **Explore the Code**: Check out `src/pci_backend.py`
2. **Run Tests**: `pytest tests/ -v`
3. **Read the Docs**: Start with [Architecture](docs/ARCHITECTURE.md)
4. **Deploy**: See [Deployment Guide](docs/DEPLOYMENT.md)

## Demo Users Reference

| Username | Password | Role | Can Do |
|----------|----------|------|--------|
| admin | Admin123! | Security Officer | Everything |
| operator | Operator123! | Operator | Process payments |
| auditor | Auditor123! | Auditor | View reports |

## Need Help?

- 📚 [Full Documentation](docs/)
- 🐛 [Report Issues](https://github.com/Andre-Profitt/air-gapped-backend-pci-compliant/issues)
- 💬 [Discussions](https://github.com/Andre-Profitt/air-gapped-backend-pci-compliant/discussions)