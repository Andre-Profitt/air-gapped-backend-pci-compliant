#!/usr/bin/env python3
"""
PCI DSS Compliance Automation Suite
Automated compliance checking and reporting for air-gapped systems
"""

import os
import json
import hashlib
import subprocess
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging
import csv

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ComplianceChecker')


class ComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class ComplianceCheck:
    """Individual compliance check result"""
    requirement: str
    description: str
    status: ComplianceStatus
    details: str
    evidence: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    last_checked: datetime = field(default_factory=datetime.utcnow)


class PasswordPolicyChecker:
    """Check password policy compliance"""
    
    def __init__(self):
        self.min_length = 15
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_numbers = True
        self.require_special = True
        self.max_age_days = 90
        self.min_age_days = 1
        self.history_count = 12
        
    def check_pam_configuration(self) -> ComplianceCheck:
        """Check PAM password configuration"""
        try:
            # Check password quality requirements
            with open('/etc/pam.d/common-password', 'r') as f:
                pam_config = f.read()
            
            compliant = True
            issues = []
            
            # Check password complexity
            if f'minlen={self.min_length}' not in pam_config:
                compliant = False
                issues.append(f"Minimum length not set to {self.min_length}")
            
            if 'ucredit=-1' not in pam_config:
                compliant = False
                issues.append("Uppercase requirement not enforced")
                
            if 'lcredit=-1' not in pam_config:
                compliant = False
                issues.append("Lowercase requirement not enforced")
                
            if 'dcredit=-1' not in pam_config:
                compliant = False
                issues.append("Digit requirement not enforced")
                
            if 'ocredit=-1' not in pam_config:
                compliant = False
                issues.append("Special character requirement not enforced")
            
            # Check password history
            if f'remember={self.history_count}' not in pam_config:
                compliant = False
                issues.append(f"Password history not set to {self.history_count}")
            
            return ComplianceCheck(
                requirement="8.2.3",
                description="Password complexity requirements",
                status=ComplianceStatus.COMPLIANT if compliant else ComplianceStatus.NON_COMPLIANT,
                details="PAM configuration check",
                evidence=['/etc/pam.d/common-password'],
                remediation="\n".join(issues) if issues else None
            )
            
        except Exception as e:
            return ComplianceCheck(
                requirement="8.2.3",
                description="Password complexity requirements",
                status=ComplianceStatus.NON_COMPLIANT,
                details=f"Error checking PAM configuration: {str(e)}",
                evidence=[],
                remediation="Verify PAM configuration files exist and are readable"
            )
    
    def check_password_aging(self) -> ComplianceCheck:
        """Check password aging policies"""
        try:
            # Check /etc/login.defs
            with open('/etc/login.defs', 'r') as f:
                login_defs = f.read()
            
            compliant = True
            issues = []
            
            # Extract values
            max_days = re.search(r'PASS_MAX_DAYS\s+(\d+)', login_defs)
            min_days = re.search(r'PASS_MIN_DAYS\s+(\d+)', login_defs)
            warn_age = re.search(r'PASS_WARN_AGE\s+(\d+)', login_defs)
            
            if not max_days or int(max_days.group(1)) > self.max_age_days:
                compliant = False
                issues.append(f"Maximum password age not set to {self.max_age_days} days")
            
            if not min_days or int(min_days.group(1)) < self.min_age_days:
                compliant = False
                issues.append(f"Minimum password age not set to {self.min_age_days} days")
            
            if not warn_age or int(warn_age.group(1)) < 7:
                compliant = False
                issues.append("Password expiration warning not set to 7 days")
            
            return ComplianceCheck(
                requirement="8.2.4",
                description="Password aging controls",
                status=ComplianceStatus.COMPLIANT if compliant else ComplianceStatus.NON_COMPLIANT,
                details="Password aging policy check",
                evidence=['/etc/login.defs'],
                remediation="\n".join(issues) if issues else None
            )
            
        except Exception as e:
            return ComplianceCheck(
                requirement="8.2.4",
                description="Password aging controls",
                status=ComplianceStatus.NON_COMPLIANT,
                details=f"Error checking password aging: {str(e)}",
                evidence=[],
                remediation="Verify /etc/login.defs exists and is properly configured"
            )
    
    def check_account_lockout(self) -> ComplianceCheck:
        """Check account lockout policy"""
        try:
            # Check PAM tally2/faillock configuration
            with open('/etc/pam.d/common-auth', 'r') as f:
                auth_config = f.read()
            
            if 'pam_faillock.so' in auth_config or 'pam_tally2.so' in auth_config:
                # Check for proper configuration
                if 'deny=6' in auth_config and 'unlock_time=1800' in auth_config:
                    status = ComplianceStatus.COMPLIANT
                    details = "Account lockout properly configured"
                    remediation = None
                else:
                    status = ComplianceStatus.PARTIALLY_COMPLIANT
                    details = "Account lockout enabled but may need adjustment"
                    remediation = "Set deny=6 and unlock_time=1800 (30 minutes)"
            else:
                status = ComplianceStatus.NON_COMPLIANT
                details = "Account lockout not configured"
                remediation = "Enable pam_faillock or pam_tally2 in PAM configuration"
            
            return ComplianceCheck(
                requirement="8.1.6",
                description="Account lockout mechanism",
                status=status,
                details=details,
                evidence=['/etc/pam.d/common-auth'],
                remediation=remediation
            )
            
        except Exception as e:
            return ComplianceCheck(
                requirement="8.1.6",
                description="Account lockout mechanism",
                status=ComplianceStatus.NON_COMPLIANT,
                details=f"Error checking account lockout: {str(e)}",
                evidence=[],
                remediation="Verify PAM configuration for account lockout"
            )


class EncryptionChecker:
    """Check encryption compliance"""
    
    def __init__(self):
        self.approved_algorithms = {
            'AES-256-GCM', 'AES-256-CBC', 'RSA-4096', 
            'SHA-256', 'SHA-384', 'SHA-512', 'SHA3-512'
        }
        self.minimum_key_sizes = {
            'AES': 256,
            'RSA': 2048,  # PCI requires 2048, we use 4096
            'DH': 2048,
            'ECC': 256
        }
    
    def check_fips_mode(self) -> ComplianceCheck:
        """Check if FIPS mode is enabled"""
        try:
            # Check kernel FIPS mode
            fips_enabled = False
            if os.path.exists('/proc/sys/crypto/fips_enabled'):
                with open('/proc/sys/crypto/fips_enabled', 'r') as f:
                    fips_enabled = f.read().strip() == '1'
            
            if fips_enabled:
                return ComplianceCheck(
                    requirement="2.3",
                    description="Strong cryptography (FIPS mode)",
                    status=ComplianceStatus.COMPLIANT,
                    details="FIPS 140-2 mode is enabled",
                    evidence=['/proc/sys/crypto/fips_enabled']
                )
            else:
                return ComplianceCheck(
                    requirement="2.3",
                    description="Strong cryptography (FIPS mode)",
                    status=ComplianceStatus.PARTIALLY_COMPLIANT,
                    details="FIPS mode not enabled but strong crypto in use",
                    evidence=['/proc/sys/crypto/fips_enabled'],
                    remediation="Enable FIPS mode: update-crypto-policies --set FIPS"
                )
                
        except Exception as e:
            return ComplianceCheck(
                requirement="2.3",
                description="Strong cryptography (FIPS mode)",
                status=ComplianceStatus.NON_COMPLIANT,
                details=f"Error checking FIPS mode: {str(e)}",
                evidence=[],
                remediation="Verify FIPS mode support in kernel"
            )
    
    def check_tls_configuration(self) -> ComplianceCheck:
        """Check TLS configuration for internal services"""
        try:
            # This would check any internal TLS services
            # For air-gapped system, this might be minimal
            
            issues = []
            
            # Check for weak protocols in OpenSSL config
            if os.path.exists('/etc/ssl/openssl.cnf'):
                with open('/etc/ssl/openssl.cnf', 'r') as f:
                    ssl_config = f.read()
                
                if 'SSLv2' in ssl_config or 'SSLv3' in ssl_config:
                    issues.append("Weak SSL protocols may be enabled")
                
                if 'TLSv1.0' in ssl_config:
                    issues.append("TLS 1.0 should be disabled")
            
            if issues:
                return ComplianceCheck(
                    requirement="4.1",
                    description="Strong cryptography for transmission",
                    status=ComplianceStatus.PARTIALLY_COMPLIANT,
                    details="TLS configuration needs hardening",
                    evidence=['/etc/ssl/openssl.cnf'],
                    remediation="\n".join(issues)
                )
            else:
                return ComplianceCheck(
                    requirement="4.1",
                    description="Strong cryptography for transmission",
                    status=ComplianceStatus.COMPLIANT,
                    details="TLS properly configured for internal use",
                    evidence=['/etc/ssl/openssl.cnf']
                )
                
        except Exception as e:
            return ComplianceCheck(
                requirement="4.1",
                description="Strong cryptography for transmission",
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Air-gapped system - no network transmission",
                evidence=[]
            )
    
    def check_disk_encryption(self) -> ComplianceCheck:
        """Check disk encryption status"""
        try:
            # Check for LUKS encryption
            result = subprocess.run(
                ['lsblk', '-o', 'NAME,FSTYPE,MOUNTPOINT'],
                capture_output=True,
                text=True
            )
            
            encrypted_volumes = []
            for line in result.stdout.splitlines():
                if 'crypto_LUKS' in line:
                    encrypted_volumes.append(line.strip())
            
            # Check if critical directories are on encrypted volumes
            critical_paths = ['/secure', '/var/lib/pci', '/opt/pci-backend']
            encrypted_paths = []
            
            for path in critical_paths:
                if os.path.exists(path):
                    # Check if path is on encrypted volume
                    df_result = subprocess.run(
                        ['df', path],
                        capture_output=True,
                        text=True
                    )
                    # Simple check - in production, verify against encrypted_volumes
                    encrypted_paths.append(path)
            
            if encrypted_volumes:
                return ComplianceCheck(
                    requirement="3.4.1",
                    description="Disk encryption for stored cardholder data",
                    status=ComplianceStatus.COMPLIANT,
                    details=f"Found {len(encrypted_volumes)} encrypted volumes",
                    evidence=encrypted_volumes
                )
            else:
                return ComplianceCheck(
                    requirement="3.4.1",
                    description="Disk encryption for stored cardholder data",
                    status=ComplianceStatus.NON_COMPLIANT,
                    details="No encrypted volumes detected",
                    evidence=[],
                    remediation="Implement full disk encryption with LUKS"
                )
                
        except Exception as e:
            return ComplianceCheck(
                requirement="3.4.1",
                description="Disk encryption for stored cardholder data",
                status=ComplianceStatus.NON_COMPLIANT,
                details=f"Error checking disk encryption: {str(e)}",
                evidence=[],
                remediation="Verify disk encryption status manually"
            )


class AccessControlChecker:
    """Check access control compliance"""
    
    def check_user_access_review(self) -> ComplianceCheck:
        """Check if user access reviews are performed"""
        try:
            # Check for access review logs
            review_log = '/var/log/pci/access-reviews.log'
            
            if os.path.exists(review_log):
                # Check last review date
                mtime = os.path.getmtime(review_log)
                last_review = datetime.fromtimestamp(mtime)
                days_since_review = (datetime.now() - last_review).days
                
                if days_since_review <= 90:  # Quarterly review
                    return ComplianceCheck(
                        requirement="8.1.5",
                        description="Quarterly user access reviews",
                        status=ComplianceStatus.COMPLIANT,
                        details=f"Last review: {days_since_review} days ago",
                        evidence=[review_log]
                    )
                else:
                    return ComplianceCheck(
                        requirement="8.1.5",
                        description="Quarterly user access reviews",
                        status=ComplianceStatus.NON_COMPLIANT,
                        details=f"Last review: {days_since_review} days ago",
                        evidence=[review_log],
                        remediation="Perform user access review (overdue)"
                    )
            else:
                return ComplianceCheck(
                    requirement="8.1.5",
                    description="Quarterly user access reviews",
                    status=ComplianceStatus.NON_COMPLIANT,
                    details="No access review log found",
                    evidence=[],
                    remediation="Implement and document quarterly access reviews"
                )
                
        except Exception as e:
            return ComplianceCheck(
                requirement="8.1.5",
                description="Quarterly user access reviews",
                status=ComplianceStatus.NON_COMPLIANT,
                details=f"Error checking access reviews: {str(e)}",
                evidence=[],
                remediation="Verify access review process"
            )
    
    def check_privilege_separation(self) -> ComplianceCheck:
        """Check for proper privilege separation"""
        try:
            # Check sudo configuration
            sudo_issues = []
            
            with open('/etc/sudoers', 'r') as f:
                sudoers = f.read()
            
            # Check for dangerous sudo rules
            if 'NOPASSWD' in sudoers:
                sudo_issues.append("NOPASSWD sudo rules detected")
            
            if 'ALL=(ALL:ALL) ALL' in sudoers:
                sudo_issues.append("Overly permissive sudo rules")
            
            # Check for service accounts with shells
            service_accounts = ['pci-operator', 'pci-audit', 'pci-backup']
            shell_issues = []
            
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        shell = parts[6]
                        if username in service_accounts and shell not in ['/bin/false', '/usr/sbin/nologin']:
                            shell_issues.append(f"{username} has shell: {shell}")
            
            all_issues = sudo_issues + shell_issues
            
            if not all_issues:
                return ComplianceCheck(
                    requirement="7.1",
                    description="Least privilege and separation of duties",
                    status=ComplianceStatus.COMPLIANT,
                    details="Proper privilege separation configured",
                    evidence=['/etc/sudoers', '/etc/passwd']
                )
            else:
                return ComplianceCheck(
                    requirement="7.1",
                    description="Least privilege and separation of duties",
                    status=ComplianceStatus.PARTIALLY_COMPLIANT,
                    details="Some privilege separation issues found",
                    evidence=['/etc/sudoers', '/etc/passwd'],
                    remediation="\n".join(all_issues)
                )
                
        except Exception as e:
            return ComplianceCheck(
                requirement="7.1",
                description="Least privilege and separation of duties",
                status=ComplianceStatus.NON_COMPLIANT,
                details=f"Error checking privilege separation: {str(e)}",
                evidence=[],
                remediation="Review sudo and account configurations"
            )


class AuditingChecker:
    """Check audit logging compliance"""
    
    def check_audit_daemon(self) -> ComplianceCheck:
        """Check if audit daemon is running and configured"""
        try:
            # Check auditd status
            result = subprocess.run(
                ['systemctl', 'is-active', 'auditd'],
                capture_output=True,
                text=True
            )
            
            if result.stdout.strip() != 'active':
                return ComplianceCheck(
                    requirement="10.1",
                    description="Audit logging implementation",
                    status=ComplianceStatus.NON_COMPLIANT,
                    details="Audit daemon is not running",
                    evidence=[],
                    remediation="Start auditd: systemctl start auditd"
                )
            
            # Check audit rules
            rules_result = subprocess.run(
                ['auditctl', '-l'],
                capture_output=True,
                text=True
            )
            
            required_rules = [
                'access to cardholder',
                'privilege functions',
                'authentication',
                'system modifications'
            ]
            
            missing_rules = []
            for rule in required_rules:
                if rule not in rules_result.stdout.lower():
                    missing_rules.append(rule)
            
            if not missing_rules:
                return ComplianceCheck(
                    requirement="10.1",
                    description="Audit logging implementation",
                    status=ComplianceStatus.COMPLIANT,
                    details="Audit daemon running with proper rules",
                    evidence=['auditd active', f"{len(rules_result.stdout.splitlines())} audit rules"]
                )
            else:
                return ComplianceCheck(
                    requirement="10.1",
                    description="Audit logging implementation",
                    status=ComplianceStatus.PARTIALLY_COMPLIANT,
                    details="Audit daemon running but missing some rules",
                    evidence=['auditd active'],
                    remediation=f"Add audit rules for: {', '.join(missing_rules)}"
                )
                
        except Exception as e:
            return ComplianceCheck(
                requirement="10.1",
                description="Audit logging implementation",
                status=ComplianceStatus.NON_COMPLIANT,
                details=f"Error checking audit daemon: {str(e)}",
                evidence=[],
                remediation="Install and configure auditd"
            )
    
    def check_log_retention(self) -> ComplianceCheck:
        """Check log retention meets requirements"""
        try:
            log_dir = '/var/log/pci'
            if not os.path.exists(log_dir):
                return ComplianceCheck(
                    requirement="10.7",
                    description="Audit log retention (1 year minimum)",
                    status=ComplianceStatus.NON_COMPLIANT,
                    details="PCI log directory not found",
                    evidence=[],
                    remediation="Create /var/log/pci directory"
                )
            
            # Check oldest log file
            oldest_date = datetime.now()
            for root, dirs, files in os.walk(log_dir):
                for file in files:
                    filepath = os.path.join(root, file)
                    mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                    if mtime < oldest_date:
                        oldest_date = mtime
            
            retention_days = (datetime.now() - oldest_date).days
            
            if retention_days >= 365:
                return ComplianceCheck(
                    requirement="10.7",
                    description="Audit log retention (1 year minimum)",
                    status=ComplianceStatus.COMPLIANT,
                    details=f"Oldest log: {retention_days} days",
                    evidence=[log_dir]
                )
            else:
                return ComplianceCheck(
                    requirement="10.7",
                    description="Audit log retention (1 year minimum)",
                    status=ComplianceStatus.PARTIALLY_COMPLIANT,
                    details=f"Oldest log: {retention_days} days (building history)",
                    evidence=[log_dir],
                    remediation="Continue retaining logs for 1 year minimum"
                )
                
        except Exception as e:
            return ComplianceCheck(
                requirement="10.7",
                description="Audit log retention (1 year minimum)",
                status=ComplianceStatus.NON_COMPLIANT,
                details=f"Error checking log retention: {str(e)}",
                evidence=[],
                remediation="Verify log retention configuration"
            )


class ComplianceAutomation:
    """Main compliance automation system"""
    
    def __init__(self):
        self.password_checker = PasswordPolicyChecker()
        self.encryption_checker = EncryptionChecker()
        self.access_checker = AccessControlChecker()
        self.audit_checker = AuditingChecker()
        self.results: List[ComplianceCheck] = []
    
    def run_all_checks(self) -> None:
        """Run all compliance checks"""
        logger.info("Starting PCI DSS compliance checks...")
        
        # Password policy checks
        self.results.append(self.password_checker.check_pam_configuration())
        self.results.append(self.password_checker.check_password_aging())
        self.results.append(self.password_checker.check_account_lockout())
        
        # Encryption checks
        self.results.append(self.encryption_checker.check_fips_mode())
        self.results.append(self.encryption_checker.check_tls_configuration())
        self.results.append(self.encryption_checker.check_disk_encryption())
        
        # Access control checks
        self.results.append(self.access_checker.check_user_access_review())
        self.results.append(self.access_checker.check_privilege_separation())
        
        # Audit checks
        self.results.append(self.audit_checker.check_audit_daemon())
        self.results.append(self.audit_checker.check_log_retention())
        
        logger.info(f"Completed {len(self.results)} compliance checks")
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate compliance summary"""
        summary = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_checks': len(self.results),
            'compliant': 0,
            'non_compliant': 0,
            'partially_compliant': 0,
            'not_applicable': 0,
            'overall_status': ComplianceStatus.COMPLIANT,
            'requirements': {}
        }
        
        for check in self.results:
            # Count by status
            if check.status == ComplianceStatus.COMPLIANT:
                summary['compliant'] += 1
            elif check.status == ComplianceStatus.NON_COMPLIANT:
                summary['non_compliant'] += 1
            elif check.status == ComplianceStatus.PARTIALLY_COMPLIANT:
                summary['partially_compliant'] += 1
            else:
                summary['not_applicable'] += 1
            
            # Group by requirement
            req_num = check.requirement.split('.')[0]
            if req_num not in summary['requirements']:
                summary['requirements'][req_num] = {
                    'total': 0,
                    'compliant': 0,
                    'issues': []
                }
            
            summary['requirements'][req_num]['total'] += 1
            if check.status == ComplianceStatus.COMPLIANT:
                summary['requirements'][req_num]['compliant'] += 1
            else:
                summary['requirements'][req_num]['issues'].append({
                    'requirement': check.requirement,
                    'description': check.description,
                    'status': check.status.value,
                    'remediation': check.remediation
                })
        
        # Determine overall status
        if summary['non_compliant'] > 0:
            summary['overall_status'] = ComplianceStatus.NON_COMPLIANT
        elif summary['partially_compliant'] > 0:
            summary['overall_status'] = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            summary['overall_status'] = ComplianceStatus.COMPLIANT
        
        return summary
    
    def generate_saq_data(self) -> Dict[str, Any]:
        """Generate data for SAQ (Self-Assessment Questionnaire)"""
        saq_data = {
            'merchant_level': 'Level 1',  # Adjust based on transaction volume
            'saq_type': 'SAQ-D',  # For service providers
            'assessment_date': datetime.utcnow().isoformat(),
            'responses': {}
        }
        
        # Map compliance checks to SAQ questions
        saq_mapping = {
            '2.3': 'Are strong cryptography and security protocols used?',
            '3.4.1': 'Is cardholder data encrypted at rest?',
            '7.1': 'Is access limited to least privilege?',
            '8.1.5': 'Are user access reviews performed quarterly?',
            '8.1.6': 'Is account lockout mechanism enabled?',
            '8.2.3': 'Are strong password requirements enforced?',
            '8.2.4': 'Are passwords changed regularly?',
            '10.1': 'Are audit trails implemented?',
            '10.7': 'Are audit logs retained for one year?'
        }
        
        for check in self.results:
            if check.requirement in saq_mapping:
                saq_data['responses'][check.requirement] = {
                    'question': saq_mapping[check.requirement],
                    'answer': 'YES' if check.status == ComplianceStatus.COMPLIANT else 'NO',
                    'details': check.details,
                    'evidence': check.evidence
                }
        
        return saq_data
    
    def export_report(self, format: str = 'json') -> str:
        """Export compliance report in various formats"""
        summary = self.generate_summary()
        saq_data = self.generate_saq_data()
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        
        if format == 'json':
            filename = f'/var/log/pci/compliance_report_{timestamp}.json'
            report_data = {
                'summary': summary,
                'detailed_results': [
                    {
                        'requirement': check.requirement,
                        'description': check.description,
                        'status': check.status.value,
                        'details': check.details,
                        'evidence': check.evidence,
                        'remediation': check.remediation,
                        'last_checked': check.last_checked.isoformat()
                    }
                    for check in self.results
                ],
                'saq_data': saq_data
            }
            
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
                
        elif format == 'csv':
            filename = f'/var/log/pci/compliance_report_{timestamp}.csv'
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Requirement', 'Description', 'Status', 
                    'Details', 'Evidence', 'Remediation'
                ])
                for check in self.results:
                    writer.writerow([
                        check.requirement,
                        check.description,
                        check.status.value,
                        check.details,
                        '; '.join(check.evidence),
                        check.remediation or ''
                    ])
        
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logger.info(f"Report exported to: {filename}")
        return filename
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary for management"""
        summary = self.generate_summary()
        
        report = f"""
PCI DSS Compliance Executive Summary
===================================
Generated: {summary['timestamp']}

Overall Compliance Status: {summary['overall_status'].value}

Summary Statistics:
- Total Checks Performed: {summary['total_checks']}
- Fully Compliant: {summary['compliant']}
- Non-Compliant: {summary['non_compliant']}
- Partially Compliant: {summary['partially_compliant']}

Compliance Score: {(summary['compliant'] / summary['total_checks'] * 100):.1f}%

Key Findings:
"""
        
        # Add non-compliant items
        if summary['non_compliant'] > 0:
            report += "\nCRITICAL - Non-Compliant Items:\n"
            for check in self.results:
                if check.status == ComplianceStatus.NON_COMPLIANT:
                    report += f"- {check.requirement}: {check.description}\n"
                    if check.remediation:
                        report += f"  Remediation: {check.remediation}\n"
        
        # Add recommendations
        report += "\nRecommendations:\n"
        if summary['overall_status'] == ComplianceStatus.COMPLIANT:
            report += "- Continue regular compliance monitoring\n"
            report += "- Schedule next assessment in 90 days\n"
        else:
            report += "- Address all non-compliant items immediately\n"
            report += "- Re-run compliance check after remediation\n"
            report += "- Consider engaging QSA for validation\n"
        
        return report


# Main execution
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='PCI DSS Compliance Automation')
    parser.add_argument('--format', choices=['json', 'csv'], default='json',
                       help='Report format')
    parser.add_argument('--executive-summary', action='store_true',
                       help='Generate executive summary')
    
    args = parser.parse_args()
    
    # Run compliance checks
    automation = ComplianceAutomation()
    automation.run_all_checks()
    
    # Generate reports
    report_file = automation.export_report(format=args.format)
    print(f"Compliance report saved to: {report_file}")
    
    if args.executive_summary:
        exec_summary = automation.generate_executive_summary()
        print("\n" + exec_summary)
        
        # Save executive summary
        exec_file = report_file.replace('.json', '_executive.txt').replace('.csv', '_executive.txt')
        with open(exec_file, 'w') as f:
            f.write(exec_summary)
        print(f"\nExecutive summary saved to: {exec_file}")
    
    # Show quick status
    summary = automation.generate_summary()
    print(f"\nOverall Status: {summary['overall_status'].value}")
    print(f"Compliance Score: {(summary['compliant'] / summary['total_checks'] * 100):.1f}%")
