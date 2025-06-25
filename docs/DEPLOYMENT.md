# Deployment Guide

## Prerequisites

### Hardware Requirements
- Dedicated air-gapped server
- Hardware Security Module (HSM)
- Biometric readers
- Optical media drives
- Secure facility

### Software Requirements
- RHEL 8+ or Ubuntu 20.04+
- Docker Engine 20.10+
- Python 3.8+
- HSM drivers and SDK

## Installation Steps

### 1. Prepare Air-Gapped System

```bash
# Run as root
sudo ./scripts/setup.sh
```

This script will:
- Create secure directory structure
- Configure system users and groups
- Set up audit logging
- Apply security hardening
- Initialize AIDE integrity monitoring

### 2. Install HSM

```bash
# Install HSM drivers
sudo dpkg -i luna-hsm-client.deb

# Configure HSM connection
sudo lunacm -c "clientconfig deploy"

# Initialize HSM partition
sudo lunacm -c "partition create -name PCI_PARTITION"
```

### 3. Build Containers

```bash
# Build secure containers
make build

# Verify container security
make security-scan
```

### 4. Deploy Application

```bash
# Deploy to production
make deploy-prod

# Verify deployment
docker ps --filter "label=pci-compliant"
```

## Configuration

### Environment Variables

```bash
# /etc/pci-backend/env
PCI_ENV=production
HSM_SLOT=0
HSM_PIN_FILE=/secure/keys/hsm.pin
AUDIT_LEVEL=maximum
FIPS_MODE=enabled
```

### Application Configuration

Edit `/etc/pci-backend/config.yaml`:

```yaml
security:
  session_timeout_minutes: 15
  max_failed_attempts: 3
  
hsm:
  type: luna
  slot: 0
  high_availability: true
```

## Operational Procedures

### Starting the System

1. Verify physical security
2. Check HSM status
3. Start core services:
   ```bash
   systemctl start pci-backend
   systemctl start pci-audit
   systemctl start pci-transfer
   ```
4. Verify system health

### Stopping the System

1. Notify users
2. Complete pending transactions
3. Stop services:
   ```bash
   systemctl stop pci-backend
   systemctl stop pci-audit
   systemctl stop pci-transfer
   ```
4. Secure facility

### Data Import Process

1. Receive encrypted media
2. Verify chain of custody
3. Load into scanner station
4. Run verification:
   ```bash
   /usr/local/bin/pci-import-verify.sh /media/cdrom
   ```
5. Import data:
   ```bash
   /usr/local/bin/pci-import-data.sh /media/cdrom
   ```
6. Destroy media

### Backup Procedures

```bash
# Daily backup
/usr/local/bin/pci-backup.sh daily

# Weekly backup to off-site
/usr/local/bin/pci-backup.sh weekly --offsite

# Verify backup
/usr/local/bin/pci-backup-verify.sh /secure/backups/latest
```

## Monitoring

### Health Checks

```bash
# System health
curl -k https://localhost:9090/health

# HSM status
lunacm -c "slot list"

# Audit trail integrity
/usr/local/bin/pci-audit-verify.sh
```

### Metrics

- Transaction processing rate
- Token generation rate
- Failed authentication attempts
- System resource usage
- HSM performance

## Troubleshooting

### Common Issues

1. **HSM Connection Failed**
   ```bash
   # Check HSM service
   systemctl status luna-hsm
   
   # Verify network (for network HSM)
   lunacm -c "clientconfig listservers"
   ```

2. **Audit Trail Error**
   ```bash
   # Check permissions
   ls -la /secure/audit/logs
   
   # Verify integrity
   /usr/local/bin/pci-audit-repair.sh
   ```

3. **Container Not Starting**
   ```bash
   # Check logs
   docker logs pci-backend-core
   
   # Verify volumes
   docker volume ls
   ```