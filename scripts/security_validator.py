#!/usr/bin/env python3
"""
PCI DSS Security Validator
Validates security configurations and compliance
"""

import os
import sys
import json
import subprocess
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple

class SecurityValidator:
    """Validates security configurations for PCI compliance"""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "passed": [],
            "failed": [],
            "warnings": []
        }
    
    def check_file_permissions(self) -> bool:
        """Check critical file permissions"""
        critical_paths = [
            ("/etc/passwd", "0644"),
            ("/etc/shadow", "0000"),
            ("/etc/gshadow", "0000"),
            ("/secure/audit", "0750"),
            ("/secure/tokens", "0700"),
        ]
        
        all_passed = True
        for path, expected_mode in critical_paths:
            if os.path.exists(path):
                stat = os.stat(path)
                actual_mode = oct(stat.st_mode)[-4:]
                
                if actual_mode != expected_mode:
                    self.results["failed"].append(
                        f"File {path} has mode {actual_mode}, expected {expected_mode}"
                    )
                    all_passed = False
                else:
                    self.results["passed"].append(
                        f"File {path} has correct permissions"
                    )
        
        return all_passed
    
    def check_kernel_parameters(self) -> bool:
        """Check kernel security parameters"""
        required_params = {
            "kernel.randomize_va_space": "2",
            "kernel.kptr_restrict": "2",
            "kernel.yama.ptrace_scope": "3",
            "net.ipv4.ip_forward": "0",
            "net.ipv6.conf.all.disable_ipv6": "1"
        }
        
        all_passed = True
        for param, expected in required_params.items():
            try:
                result = subprocess.check_output(
                    ["sysctl", param], 
                    text=True
                ).strip()
                
                actual = result.split("=")[1].strip()
                if actual != expected:
                    self.results["failed"].append(
                        f"Kernel parameter {param} = {actual}, expected {expected}"
                    )
                    all_passed = False
                else:
                    self.results["passed"].append(
                        f"Kernel parameter {param} correctly set"
                    )
            except Exception as e:
                self.results["failed"].append(
                    f"Failed to check {param}: {str(e)}"
                )
                all_passed = False
        
        return all_passed
    
    def check_services(self) -> bool:
        """Check for prohibited services"""
        prohibited_services = [
            "telnet", "rsh", "rlogin", "ftp", 
            "NetworkManager", "bluetooth", "avahi-daemon"
        ]
        
        all_passed = True
        for service in prohibited_services:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:  # Service is active
                    self.results["failed"].append(
                        f"Prohibited service {service} is running"
                    )
                    all_passed = False
                else:
                    self.results["passed"].append(
                        f"Service {service} is not running"
                    )
            except Exception:
                # Service doesn't exist - that's good
                self.results["passed"].append(
                    f"Service {service} not found"
                )
        
        return all_passed
    
    def check_audit_logs(self) -> bool:
        """Check audit log configuration"""
        audit_checks = [
            ("/var/log/pci", os.path.exists),
            ("/etc/audit/rules.d/pci.rules", os.path.exists),
        ]
        
        all_passed = True
        for path, check_func in audit_checks:
            if check_func(path):
                self.results["passed"].append(
                    f"Audit configuration {path} exists"
                )
            else:
                self.results["failed"].append(
                    f"Audit configuration {path} missing"
                )
                all_passed = False
        
        # Check if auditd is running
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "auditd"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.results["passed"].append("Auditd service is running")
            else:
                self.results["failed"].append("Auditd service is not running")
                all_passed = False
        except Exception as e:
            self.results["failed"].append(f"Cannot check auditd: {str(e)}")
            all_passed = False
        
        return all_passed
    
    def check_encryption(self) -> bool:
        """Check encryption configurations"""
        # Check for FIPS mode
        fips_enabled = False
        if os.path.exists("/proc/sys/crypto/fips_enabled"):
            with open("/proc/sys/crypto/fips_enabled", "r") as f:
                fips_enabled = f.read().strip() == "1"
        
        if fips_enabled:
            self.results["passed"].append("FIPS mode is enabled")
        else:
            self.results["warnings"].append("FIPS mode is not enabled")
        
        return True
    
    def generate_report(self) -> Dict:
        """Generate security validation report"""
        self.check_file_permissions()
        self.check_kernel_parameters()
        self.check_services()
        self.check_audit_logs()
        self.check_encryption()
        
        self.results["summary"] = {
            "total_checks": len(self.results["passed"]) + len(self.results["failed"]),
            "passed": len(self.results["passed"]),
            "failed": len(self.results["failed"]),
            "warnings": len(self.results["warnings"]),
            "compliance_score": len(self.results["passed"]) / 
                              (len(self.results["passed"]) + len(self.results["failed"])) * 100
        }
        
        return self.results

def main():
    """Main validation function"""
    validator = SecurityValidator()
    report = validator.generate_report()
    
    # Write report
    with open("/var/log/pci/security-validation.json", "w") as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print(f"Security Validation Report - {report['timestamp']}")
    print(f"Compliance Score: {report['summary']['compliance_score']:.1f}%")
    print(f"Passed: {report['summary']['passed']}")
    print(f"Failed: {report['summary']['failed']}")
    print(f"Warnings: {report['summary']['warnings']}")
    
    # Exit with error if any checks failed
    sys.exit(0 if report['summary']['failed'] == 0 else 1)

if __name__ == "__main__":
    main()