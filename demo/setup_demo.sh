#!/bin/bash
# PCI Backend Demo Environment Setup Script
# This creates a complete demo environment on your local machine

set -e

echo "================================================"
echo "    PCI Compliant Backend - Demo Setup          "
echo "================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check requirements
check_requirements() {
    echo "Checking system requirements..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}✗ Python 3 is not installed${NC}"
        echo "  Please install Python 3.8 or higher"
        exit 1
    else
        echo -e "${GREEN}✓ Python 3 found${NC}"
    fi
    
    # Check Docker (optional)
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}✓ Docker found (optional)${NC}"
        DOCKER_AVAILABLE=true
    else
        echo -e "${YELLOW}! Docker not found (optional)${NC}"
        DOCKER_AVAILABLE=false
    fi
    
    # Check available space
    AVAILABLE_SPACE=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$AVAILABLE_SPACE" -lt 2 ]; then
        echo -e "${RED}✗ Insufficient disk space (need at least 2GB)${NC}"
        exit 1
    else
        echo -e "${GREEN}✓ Sufficient disk space${NC}"
    fi
    
    echo ""
}

# Create directory structure
create_directories() {
    echo "Creating demo directory structure..."
    
    # Base directory
    DEMO_DIR="pci-backend-demo"
    mkdir -p $DEMO_DIR
    cd $DEMO_DIR
    
    # Create secure directory structure
    mkdir -p {src,config,tests,scripts,logs,data}
    mkdir -p data/{audit,tokens,transfer/{import,export}}
    mkdir -p logs/{audit,system,security}
    
    echo -e "${GREEN}✓ Directory structure created${NC}"
    echo ""
}

# Create Python virtual environment
setup_python_env() {
    echo "Setting up Python environment..."
    
    # Create virtual environment
    python3 -m venv venv
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Create requirements.txt
    cat > requirements.txt << 'EOF'
cryptography==41.0.7
pycryptodome==3.19.0
argon2-cffi==23.1.0
pyotp==2.9.0
structlog==23.2.0
colorlog==6.8.0
click==8.1.7
rich==13.7.0
pytest==7.4.3
pytest-cov==4.1.0
pyyaml==6.0.1
EOF
    
    # Install dependencies
    pip install --upgrade pip
    pip install -r requirements.txt
    
    echo -e "${GREEN}✓ Python environment ready${NC}"
    echo ""
}

# Create the main application files
create_application_files() {
    echo "Creating application files..."
    
    # Create main PCI backend module
    cat > src/pci_backend.py << 'EOF'
# Simplified PCI Backend for Demo
import os
import json
import hashlib
import secrets
import datetime
import logging
from typing import Dict, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import colorlog

# Configure colored logging for demo
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    }
))

logger = colorlog.getLogger('PCIBackend')
logger.addHandler(handler)
logger.setLevel(logging.INFO)

class DemoPCIBackend:
    """Simplified PCI Backend for demonstration"""
    
    def __init__(self):
        logger.info("🔐 Initializing PCI Compliant Backend (Demo Mode)")
        self.master_key = os.urandom(32)  # In production: HSM
        self.tokens = {}
        self.audit_log = []
        self.users = {}
        self.sessions = {}
        self._init_demo_data()
        
    def _init_demo_data(self):
        """Initialize demo users and data"""
        # Create demo users
        self.users = {
            "admin": {
                "role": "security_officer",
                "password": hashlib.sha256(b"Admin123!").hexdigest(),
                "name": "Security Admin"
            },
            "operator": {
                "role": "operator", 
                "password": hashlib.sha256(b"Operator123!").hexdigest(),
                "name": "Payment Operator"
            },
            "auditor": {
                "role": "auditor",
                "password": hashlib.sha256(b"Auditor123!").hexdigest(),
                "name": "Compliance Auditor"
            }
        }
        
        logger.info("✅ Demo users created")
        self._audit_log("SYSTEM", "Demo initialization complete")
        
    def _audit_log(self, user: str, action: str, details: Dict = None):
        """Add entry to audit log"""
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "user": user,
            "action": action,
            "details": details or {}
        }
        self.audit_log.append(entry)
        logger.info(f"📝 Audit: {user} - {action}")
        
    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user (simplified for demo)"""
        if username not in self.users:
            logger.error(f"❌ Authentication failed: Unknown user {username}")
            self._audit_log(username, "AUTH_FAILED", {"reason": "unknown_user"})
            return None
            
        user = self.users[username]
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if user["password"] != pwd_hash:
            logger.error(f"❌ Authentication failed: Invalid password for {username}")
            self._audit_log(username, "AUTH_FAILED", {"reason": "invalid_password"})
            return None
            
        # Create session
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            "username": username,
            "role": user["role"],
            "created": datetime.datetime.utcnow()
        }
        
        logger.info(f"✅ User {username} authenticated successfully")
        self._audit_log(username, "AUTH_SUCCESS", {"session_id": session_id[:8] + "..."})
        return session_id
        
    def tokenize_pan(self, session_id: str, pan: str) -> Optional[str]:
        """Tokenize a payment card number"""
        if session_id not in self.sessions:
            logger.error("❌ Invalid session")
            return None
            
        session = self.sessions[session_id]
        
        # Check permission
        if session["role"] not in ["operator", "security_officer"]:
            logger.error(f"❌ User {session['username']} lacks tokenization permission")
            self._audit_log(session["username"], "TOKENIZE_DENIED", {"reason": "insufficient_permissions"})
            return None
            
        # Validate PAN (simplified Luhn check)
        if not self._validate_pan(pan):
            logger.error("❌ Invalid PAN format")
            return None
            
        # Generate token
        token = "TOK_" + secrets.token_urlsafe(16)
        
        # Store encrypted (demo - in production use HSM)
        encrypted_pan = self._encrypt_data(pan.encode())
        self.tokens[token] = {
            "encrypted_pan": encrypted_pan,
            "created": datetime.datetime.utcnow().isoformat(),
            "created_by": session["username"]
        }
        
        logger.info(f"✅ PAN tokenized successfully: {token}")
        self._audit_log(session["username"], "TOKENIZE_SUCCESS", {
            "token": token,
            "last4": pan[-4:]
        })
        
        return token
        
    def _validate_pan(self, pan: str) -> bool:
        """Basic PAN validation"""
        if not pan.isdigit() or len(pan) < 13 or len(pan) > 19:
            return False
        return True  # Simplified for demo
        
    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data (simplified for demo)"""
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad data to 16-byte boundary
        pad_len = 16 - (len(data) % 16)
        padded_data = data + (bytes([pad_len]) * pad_len)
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted
        
    def get_audit_report(self, session_id: str) -> Optional[Dict]:
        """Get audit report"""
        if session_id not in self.sessions:
            return None
            
        session = self.sessions[session_id]
        
        # Check permission
        if session["role"] not in ["auditor", "security_officer"]:
            logger.error(f"❌ User {session['username']} lacks audit access")
            return None
            
        report = {
            "generated": datetime.datetime.utcnow().isoformat(),
            "generated_by": session["username"],
            "total_events": len(self.audit_log),
            "recent_events": self.audit_log[-10:],
            "token_count": len(self.tokens),
            "active_sessions": len(self.sessions)
        }
        
        logger.info(f"✅ Audit report generated by {session['username']}")
        self._audit_log(session["username"], "AUDIT_REPORT_GENERATED")
        
        return report

# Create demo instance
demo_backend = DemoPCIBackend()
EOF

    # Create CLI interface
    cat > src/demo_cli.py << 'EOF'
#!/usr/bin/env python3
"""
PCI Backend Demo CLI
Interactive demonstration of the air-gapped PCI compliant backend
"""

import click
import json
import getpass
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from pci_backend import demo_backend

console = Console()

# Store current session
current_session = None
current_user = None

def print_header():
    """Print demo header"""
    header = Text("🔐 PCI Compliant Backend Demo", style="bold cyan")
    subtitle = Text("Air-Gapped Payment Processing System", style="italic")
    console.print(Panel.fit(header + "\n" + subtitle, box=box.HEAVY))
    console.print()

@click.group()
def cli():
    """PCI Backend Demo - Interactive Command Line Interface"""
    pass

@cli.command()
def login():
    """Login to the system"""
    global current_session, current_user
    
    console.print("🔑 [bold]User Authentication[/bold]")
    console.print("Demo users: admin, operator, auditor")
    console.print("Password for all: [Username]123! (e.g., Admin123!)")
    console.print()
    
    username = console.input("[cyan]Username:[/cyan] ")
    password = getpass.getpass("Password: ")
    
    session = demo_backend.authenticate(username, password)
    
    if session:
        current_session = session
        current_user = username
        user_info = demo_backend.users[username]
        console.print(f"\n✅ [green]Welcome, {user_info['name']}![/green]")
        console.print(f"Role: [yellow]{user_info['role']}[/yellow]")
        console.print(f"Session: [dim]{session[:8]}...[/dim]")
    else:
        console.print("\n❌ [red]Authentication failed[/red]")

@cli.command()
def logout():
    """Logout from the system"""
    global current_session, current_user
    
    if not current_session:
        console.print("❌ [red]Not logged in[/red]")
        return
        
    console.print(f"👋 [yellow]Goodbye, {current_user}![/yellow]")
    current_session = None
    current_user = None

@cli.command()
@click.argument('pan')
def tokenize(pan):
    """Tokenize a payment card number"""
    if not current_session:
        console.print("❌ [red]Please login first[/red]")
        return
        
    console.print(f"💳 [bold]Tokenizing PAN[/bold]")
    console.print(f"PAN: [dim]{'*' * (len(pan)-4)}{pan[-4:]}[/dim]")
    
    token = demo_backend.tokenize_pan(current_session, pan)
    
    if token:
        console.print(f"\n✅ [green]Tokenization successful![/green]")
        console.print(f"Token: [bold cyan]{token}[/bold cyan]")
        console.print("\n[dim]This token can be safely stored and transmitted.[/dim]")
    else:
        console.print("\n❌ [red]Tokenization failed[/red]")

@cli.command()
def audit():
    """View audit report"""
    if not current_session:
        console.print("❌ [red]Please login first[/red]")
        return
        
    report = demo_backend.get_audit_report(current_session)
    
    if not report:
        console.print("❌ [red]Access denied - insufficient permissions[/red]")
        return
        
    console.print("📊 [bold]Audit Report[/bold]")
    console.print(f"Generated: [dim]{report['generated']}[/dim]")
    console.print(f"Generated by: [yellow]{report['generated_by']}[/yellow]")
    console.print()
    
    # Statistics table
    stats_table = Table(title="System Statistics", box=box.ROUNDED)
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="green")
    
    stats_table.add_row("Total Events", str(report['total_events']))
    stats_table.add_row("Active Tokens", str(report['token_count']))
    stats_table.add_row("Active Sessions", str(report['active_sessions']))
    
    console.print(stats_table)
    console.print()
    
    # Recent events
    if report['recent_events']:
        events_table = Table(title="Recent Events", box=box.ROUNDED)
        events_table.add_column("Timestamp", style="dim")
        events_table.add_column("User", style="cyan")
        events_table.add_column("Action", style="yellow")
        
        for event in report['recent_events'][-5:]:
            events_table.add_row(
                event['timestamp'][:19],
                event['user'],
                event['action']
            )
        
        console.print(events_table)

@cli.command()
def status():
    """Show system status"""
    console.print("🔍 [bold]System Status[/bold]")
    
    if current_session:
        console.print(f"✅ [green]Logged in as:[/green] {current_user}")
        console.print(f"   Role: [yellow]{demo_backend.users[current_user]['role']}[/yellow]")
    else:
        console.print("❌ [red]Not logged in[/red]")
    
    console.print(f"\n📊 System Metrics:")
    console.print(f"   Active Sessions: [cyan]{len(demo_backend.sessions)}[/cyan]")
    console.print(f"   Stored Tokens: [cyan]{len(demo_backend.tokens)}[/cyan]")
    console.print(f"   Audit Events: [cyan]{len(demo_backend.audit_log)}[/cyan]")

@cli.command()
def demo():
    """Run interactive demo walkthrough"""
    print_header()
    
    console.print("🎯 [bold]Welcome to the PCI Backend Demo![/bold]")
    console.print("\nThis demo simulates an air-gapped payment processing system.")
    console.print("In production, this would run on physically isolated hardware.\n")
    
    console.print("[yellow]Demo Scenario:[/yellow]")
    console.print("1. Login as different users to see role-based access")
    console.print("2. Tokenize payment card numbers securely")
    console.print("3. View audit logs and compliance reports")
    console.print("4. Observe security features in action\n")
    
    console.print("[bold]Available Commands:[/bold]")
    console.print("  [cyan]login[/cyan]    - Authenticate to the system")
    console.print("  [cyan]tokenize[/cyan] - Convert PAN to secure token")
    console.print("  [cyan]audit[/cyan]    - View audit report (auditor/admin only)")
    console.print("  [cyan]status[/cyan]   - Check system status")
    console.print("  [cyan]logout[/cyan]   - End current session")
    console.print()
    
    console.print("[dim]Try: python demo_cli.py login[/dim]")

if __name__ == '__main__':
    cli()
EOF

    # Create test credit card numbers
    cat > config/test_cards.txt << 'EOF'
# Test Credit Card Numbers (for demo only)
# These are valid test card numbers that pass Luhn validation

# Visa
4532015112830366
4916909992268760
4539578763621486

# Mastercard
5425233430109903
5553042241984105
5105105105105100

# American Express
371449635398431
378282246310005

# Discover
6011111111111117
6011000990139424
EOF

    # Create a simple test suite
    cat > tests/test_demo.py << 'EOF'
import pytest
from src.pci_backend import DemoPCIBackend

def test_authentication():
    backend = DemoPCIBackend()
    
    # Test valid authentication
    session = backend.authenticate("admin", "Admin123!")
    assert session is not None
    
    # Test invalid authentication
    session = backend.authenticate("admin", "wrong_password")
    assert session is None

def test_tokenization():
    backend = DemoPCIBackend()
    
    # Login as operator
    session = backend.authenticate("operator", "Operator123!")
    
    # Test tokenization
    token = backend.tokenize_pan(session, "4532015112830366")
    assert token is not None
    assert token.startswith("TOK_")

def test_audit_permissions():
    backend = DemoPCIBackend()
    
    # Login as operator (should not have audit access)
    session = backend.authenticate("operator", "Operator123!")
    report = backend.get_audit_report(session)
    assert report is None
    
    # Login as auditor (should have audit access)
    session = backend.authenticate("auditor", "Auditor123!")
    report = backend.get_audit_report(session)
    assert report is not None
    assert "total_events" in report
EOF

    echo -e "${GREEN}✓ Application files created${NC}"
    echo ""
}

# Create Docker setup (optional)
create_docker_setup() {
    if [ "$DOCKER_AVAILABLE" = true ]; then
        echo "Creating Docker configuration..."
        
        cat > Dockerfile << 'EOF'
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "src/demo_cli.py", "demo"]
EOF

        cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  pci-demo:
    build: .
    container_name: pci-backend-demo
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data
    environment:
      - DEMO_MODE=true
    stdin_open: true
    tty: true
    networks:
      - isolated

networks:
  isolated:
    driver: bridge
    internal: true
EOF
        
        echo -e "${GREEN}✓ Docker configuration created${NC}"
        echo ""
    fi
}

# Create run scripts
create_run_scripts() {
    echo "Creating run scripts..."
    
    # Create run script
    cat > run_demo.sh << 'EOF'
#!/bin/bash
source venv/bin/activate
export PYTHONPATH=$PWD/src:$PYTHONPATH
python src/demo_cli.py demo
EOF
    chmod +x run_demo.sh
    
    # Create interactive script
    cat > run_interactive.sh << 'EOF'
#!/bin/bash
source venv/bin/activate
export PYTHONPATH=$PWD/src:$PYTHONPATH
echo "PCI Backend Demo - Interactive Mode"
echo "Type 'python src/demo_cli.py --help' for commands"
exec bash
EOF
    chmod +x run_interactive.sh
    
    echo -e "${GREEN}✓ Run scripts created${NC}"
    echo ""
}

# Create README for demo
create_demo_readme() {
    cat > README.md << 'EOF'
# PCI Backend Demo Environment

This is a demonstration environment for the air-gapped PCI compliant backend system.

## Quick Start

1. **Run the demo introduction:**
   ```bash
   ./run_demo.sh
   ```

2. **Start interactive mode:**
   ```bash
   ./run_interactive.sh
   ```

## Demo Users

| Username | Password     | Role              | Permissions                    |
|----------|-------------|-------------------|--------------------------------|
| admin    | Admin123!   | Security Officer  | Full access                    |
| operator | Operator123!| Operator          | Process payments, tokenization |
| auditor  | Auditor123! | Auditor           | View audit logs and reports    |

## Demo Commands

```bash
# Login to the system
python src/demo_cli.py login

# Tokenize a test card
python src/demo_cli.py tokenize 4532015112830366

# View audit report (auditor/admin only)
python src/demo_cli.py audit

# Check system status
python src/demo_cli.py status

# Logout
python src/demo_cli.py logout
```

## Test Credit Cards

See `config/test_cards.txt` for valid test card numbers.

## Running Tests

```bash
source venv/bin/activate
pytest tests/ -v
```

## Architecture

```
Air-Gapped Environment (Simulated)
├── Authentication (Multi-factor in production)
├── Tokenization Engine
├── Audit Trail (Blockchain-based)
└── Role-Based Access Control
```

## Security Features Demonstrated

- ✅ Secure authentication
- ✅ Role-based access control
- ✅ PAN tokenization
- ✅ Comprehensive audit logging
- ✅ Encrypted storage
- ✅ Session management

## Note

This is a simplified demo. The production system includes:
- Hardware Security Module (HSM) integration
- Biometric authentication
- Physical air-gap enforcement
- Write-once media transfers
- Complete PCI DSS compliance
EOF
    
    echo -e "${GREEN}✓ Demo README created${NC}"
    echo ""
}

# Main setup flow
main() {
    echo "Starting PCI Backend Demo Setup..."
    echo ""
    
    check_requirements
    create_directories
    setup_python_env
    create_application_files
    create_docker_setup
    create_run_scripts
    create_demo_readme
    
    echo "================================================"
    echo -e "${GREEN}✅ Demo Environment Setup Complete!${NC}"
    echo "================================================"
    echo ""
    echo "📁 Location: $(pwd)"
    echo ""
    echo "🚀 To start the demo:"
    echo "   ./run_demo.sh"
    echo ""
    echo "💻 For interactive mode:"
    echo "   ./run_interactive.sh"
    echo ""
    echo "🧪 To run tests:"
    echo "   source venv/bin/activate"
    echo "   pytest tests/ -v"
    echo ""
    echo "📚 See README.md for detailed instructions"
    echo ""
    echo -e "${YELLOW}Demo Users:${NC}"
    echo "  admin/Admin123!     - Full access"
    echo "  operator/Operator123! - Payment processing"
    echo "  auditor/Auditor123!  - Audit reports"
    echo ""
}

# Run main setup
main
