#!/bin/bash
#
# Air-Gap Integrity Validator
# Verifies complete network isolation for PCI compliance
# Run this script regularly to ensure air-gap integrity
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LOG_FILE="/var/log/pci/airgap-validation.log"
ALERT_EMAIL="security@company.com"
VALIDATION_TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Alert function
alert() {
    local severity=$1
    local message=$2
    
    echo -e "${RED}[ALERT] ${severity}: ${message}${NC}"
    log "ALERT - ${severity}: ${message}"
    
    # In production, send secure alert (via serial console, light signal, etc.)
    # echo "${message}" > /dev/ttyS0  # Serial console alert
}

# Success message
success() {
    echo -e "${GREEN}[PASS] $1${NC}"
    log "PASS - $1"
}

# Warning message
warning() {
    echo -e "${YELLOW}[WARN] $1${NC}"
    log "WARN - $1"
}

# Info message
info() {
    echo -e "${BLUE}[INFO] $1${NC}"
    log "INFO - $1"
}

# Initialize validation
echo "========================================"
echo "   Air-Gap Integrity Validator v1.0     "
echo "========================================"
echo ""
info "Starting validation at ${VALIDATION_TIMESTAMP}"
echo ""

VALIDATION_PASSED=true
CRITICAL_FAILURES=0
WARNINGS=0

# Function to check network interfaces
check_network_interfaces() {
    echo -e "\n${BLUE}=== Checking Network Interfaces ===${NC}"
    
    # Get all network interfaces
    interfaces=$(ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' ')
    
    for interface in $interfaces; do
        if [[ "$interface" == "lo" ]]; then
            success "Loopback interface ${interface} is acceptable"
            continue
        fi
        
        # Check if interface is up
        if ip link show "$interface" | grep -q "state UP"; then
            alert "CRITICAL" "Network interface ${interface} is UP! Air-gap violated!"
            CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
            VALIDATION_PASSED=false
        else
            success "Network interface ${interface} is DOWN"
        fi
        
        # Check for IP addresses
        if ip addr show "$interface" | grep -q "inet "; then
            alert "CRITICAL" "Network interface ${interface} has IP address assigned!"
            CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
            VALIDATION_PASSED=false
        fi
    done
}

# Function to check network kernel modules
check_network_modules() {
    echo -e "\n${BLUE}=== Checking Network Kernel Modules ===${NC}"
    
    # List of network modules that should not be loaded
    network_modules=(
        "e1000" "e1000e" "igb" "ixgbe" "r8169" "tg3"
        "bnx2" "bnx2x" "mlx4_en" "mlx5_core"
        "iwlwifi" "ath9k" "ath10k" "rtl8192"
        "bluetooth" "btusb" "rfcomm"
    )
    
    for module in "${network_modules[@]}"; do
        if lsmod | grep -q "^${module} "; then
            warning "Network module ${module} is loaded"
            WARNINGS=$((WARNINGS + 1))
            
            # Try to remove the module
            if rmmod "$module" 2>/dev/null; then
                success "Removed network module ${module}"
            else
                warning "Could not remove module ${module} - may be in use"
            fi
        else
            success "Network module ${module} is not loaded"
        fi
    done
}

# Function to check network services
check_network_services() {
    echo -e "\n${BLUE}=== Checking Network Services ===${NC}"
    
    # Services that should not be running
    network_services=(
        "NetworkManager" "networking" "systemd-networkd"
        "wpa_supplicant" "dhcpcd" "dhclient"
        "sshd" "ssh" "telnet" "ftp" "vsftpd"
        "apache2" "nginx" "httpd"
        "bluetooth" "avahi-daemon"
    )
    
    for service in "${network_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            alert "CRITICAL" "Network service ${service} is running!"
            CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
            VALIDATION_PASSED=false
            
            # Attempt to stop the service
            if systemctl stop "$service" 2>/dev/null; then
                success "Stopped service ${service}"
            fi
        else
            success "Network service ${service} is not running"
        fi
    done
}

# Function to check firewall rules
check_firewall_rules() {
    echo -e "\n${BLUE}=== Checking Firewall Rules ===${NC}"
    
    # Check iptables rules
    if command -v iptables &> /dev/null; then
        # Count total rules
        total_rules=$(iptables -L -n | grep -c "^Chain\|^ACCEPT\|^DROP\|^REJECT" || true)
        
        if [[ $total_rules -eq 0 ]]; then
            success "No iptables rules configured (good for air-gap)"
        else
            # Check for any ACCEPT rules that aren't loopback
            if iptables -L -n | grep -v "127.0.0.1" | grep -q "ACCEPT"; then
                warning "Found non-loopback ACCEPT rules in iptables"
                WARNINGS=$((WARNINGS + 1))
            fi
        fi
        
        # Ensure default policies are DROP
        for chain in INPUT OUTPUT FORWARD; do
            policy=$(iptables -L $chain -n | head -1 | awk '{print $4}' | tr -d ')')
            if [[ "$policy" != "DROP" ]]; then
                warning "iptables ${chain} policy is ${policy}, should be DROP"
                iptables -P $chain DROP
                success "Set iptables ${chain} policy to DROP"
            else
                success "iptables ${chain} policy is correctly set to DROP"
            fi
        done
    else
        info "iptables not installed"
    fi
}

# Function to check network configuration files
check_network_configs() {
    echo -e "\n${BLUE}=== Checking Network Configuration Files ===${NC}"
    
    # Check /etc/network/interfaces
    if [[ -f /etc/network/interfaces ]]; then
        if grep -q "^[[:space:]]*auto\|^[[:space:]]*iface" /etc/network/interfaces | grep -v "lo"; then
            warning "Found network interface configuration in /etc/network/interfaces"
            WARNINGS=$((WARNINGS + 1))
        else
            success "/etc/network/interfaces contains only loopback configuration"
        fi
    fi
    
    # Check NetworkManager connections
    if [[ -d /etc/NetworkManager/system-connections ]]; then
        conn_count=$(find /etc/NetworkManager/system-connections -type f | wc -l)
        if [[ $conn_count -gt 0 ]]; then
            warning "Found ${conn_count} NetworkManager connection profiles"
            WARNINGS=$((WARNINGS + 1))
        else
            success "No NetworkManager connection profiles found"
        fi
    fi
    
    # Check for WiFi configurations
    if [[ -f /etc/wpa_supplicant/wpa_supplicant.conf ]]; then
        if grep -q "^[[:space:]]*network=" /etc/wpa_supplicant/wpa_supplicant.conf; then
            alert "CRITICAL" "Found WiFi network configuration!"
            CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
            VALIDATION_PASSED=false
        fi
    else
        success "No WiFi configuration found"
    fi
}

# Function to check for network hardware
check_network_hardware() {
    echo -e "\n${BLUE}=== Checking Network Hardware ===${NC}"
    
    # Check PCI devices for network cards
    if command -v lspci &> /dev/null; then
        network_devices=$(lspci | grep -i "ethernet\|network\|wireless" || true)
        if [[ -n "$network_devices" ]]; then
            warning "Found network hardware devices:"
            echo "$network_devices" | while read -r line; do
                warning "  - $line"
            done
            WARNINGS=$((WARNINGS + 1))
            
            # Check if devices are disabled in BIOS (would require physical verification)
            info "Network hardware should be disabled in BIOS/UEFI"
        else
            success "No network hardware detected via lspci"
        fi
    fi
    
    # Check USB devices for network adapters
    if command -v lsusb &> /dev/null; then
        usb_network=$(lsusb | grep -i "ethernet\|wireless\|network" || true)
        if [[ -n "$usb_network" ]]; then
            alert "CRITICAL" "Found USB network device(s):"
            echo "$usb_network" | while read -r line; do
                echo "  - $line"
            done
            CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
            VALIDATION_PASSED=false
        else
            success "No USB network devices detected"
        fi
    fi
}

# Function to check system logs for network activity
check_system_logs() {
    echo -e "\n${BLUE}=== Checking System Logs ===${NC}"
    
    # Check for recent network-related log entries
    if [[ -f /var/log/syslog ]] || [[ -f /var/log/messages ]]; then
        log_file="/var/log/syslog"
        [[ -f /var/log/messages ]] && log_file="/var/log/messages"
        
        # Look for network-related messages in the last hour
        recent_network=$(grep -i "eth0\|wlan\|dhcp\|network" "$log_file" | \
                        grep "$(date '+%b %_d %H')" || true)
        
        if [[ -n "$recent_network" ]]; then
            warning "Found recent network-related log entries"
            WARNINGS=$((WARNINGS + 1))
        else
            success "No recent network activity in system logs"
        fi
    fi
}

# Function to verify kernel parameters
check_kernel_parameters() {
    echo -e "\n${BLUE}=== Checking Kernel Parameters ===${NC}"
    
    # Network-related kernel parameters that should be set
    declare -A kernel_params=(
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv6.conf.all.disable_ipv6"]="1"
        ["net.ipv6.conf.default.disable_ipv6"]="1"
        ["net.ipv6.conf.lo.disable_ipv6"]="1"
    )
    
    for param in "${!kernel_params[@]}"; do
        expected="${kernel_params[$param]}"
        actual=$(sysctl -n "$param" 2>/dev/null || echo "not_set")
        
        if [[ "$actual" == "$expected" ]]; then
            success "Kernel parameter $param = $expected"
        else
            warning "Kernel parameter $param = $actual (expected $expected)"
            # Set the correct value
            sysctl -w "$param=$expected" &>/dev/null
            success "Corrected kernel parameter $param"
        fi
    done
}

# Function to check for network-related processes
check_network_processes() {
    echo -e "\n${BLUE}=== Checking Network Processes ===${NC}"
    
    # Look for processes that might indicate network activity
    suspicious_processes=(
        "ping" "telnet" "ssh" "scp" "sftp" "ftp"
        "wget" "curl" "nc" "netcat" "socat"
        "tcpdump" "wireshark" "nmap"
    )
    
    for proc in "${suspicious_processes[@]}"; do
        if pgrep -x "$proc" > /dev/null; then
            alert "CRITICAL" "Found running network process: $proc"
            CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
            VALIDATION_PASSED=false
            
            # Kill the process
            pkill -9 "$proc" 2>/dev/null && success "Terminated process $proc"
        fi
    done
    
    # Check for listening ports
    if command -v ss &> /dev/null; then
        listening_ports=$(ss -tuln | grep -v "127.0.0.1\|::1" | grep "LISTEN" || true)
        if [[ -n "$listening_ports" ]]; then
            alert "CRITICAL" "Found non-localhost listening ports:"
            echo "$listening_ports"
            CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
            VALIDATION_PASSED=false
        else
            success "No non-localhost listening ports detected"
        fi
    fi
}

# Function to generate validation report
generate_report() {
    echo -e "\n${BLUE}=== Validation Summary ===${NC}"
    
    report_file="/var/log/pci/airgap-report-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "Air-Gap Integrity Validation Report"
        echo "==================================="
        echo "Timestamp: ${VALIDATION_TIMESTAMP}"
        echo "Host: $(hostname)"
        echo "Validator Version: 1.0"
        echo ""
        echo "Overall Status: $(if $VALIDATION_PASSED; then echo "PASSED"; else echo "FAILED"; fi)"
        echo "Critical Failures: ${CRITICAL_FAILURES}"
        echo "Warnings: ${WARNINGS}"
        echo ""
        echo "Detailed Results:"
        echo "-----------------"
        grep "^\\[" "$LOG_FILE" | tail -n 50
    } > "$report_file"
    
    if $VALIDATION_PASSED; then
        success "Air-gap integrity validation PASSED"
        echo -e "${GREEN}No critical network vulnerabilities detected${NC}"
    else
        alert "CRITICAL" "Air-gap integrity validation FAILED"
        echo -e "${RED}${CRITICAL_FAILURES} critical failure(s) detected!${NC}"
        echo -e "${RED}IMMEDIATE ACTION REQUIRED${NC}"
    fi
    
    echo ""
    info "Full report saved to: $report_file"
    
    # Return appropriate exit code
    if $VALIDATION_PASSED; then
        exit 0
    else
        exit 1
    fi
}

# Function to perform physical checks reminder
physical_checks_reminder() {
    echo -e "\n${BLUE}=== Physical Security Reminders ===${NC}"
    
    echo -e "${YELLOW}Please perform the following physical checks:${NC}"
    echo "  [ ] Verify no network cables connected to the system"
    echo "  [ ] Check for unauthorized wireless devices"
    echo "  [ ] Inspect USB ports for network adapters"
    echo "  [ ] Verify Faraday cage integrity (if applicable)"
    echo "  [ ] Check server room access logs"
    echo "  [ ] Verify security seals on equipment"
    echo ""
    warning "Physical verification required for complete validation"
}

# Main validation execution
main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        alert "ERROR" "This script must be run as root"
        exit 1
    fi
    
    # Create lockfile to prevent concurrent runs
    LOCKFILE="/var/run/airgap-validator.lock"
    if [[ -f "$LOCKFILE" ]]; then
        alert "ERROR" "Validation already running (lockfile exists)"
        exit 1
    fi
    
    # Set trap to remove lockfile
    trap 'rm -f "$LOCKFILE"' EXIT
    touch "$LOCKFILE"
    
    # Run all checks
    check_network_interfaces
    check_network_modules
    check_network_services
    check_firewall_rules
    check_network_configs
    check_network_hardware
    check_system_logs
    check_kernel_parameters
    check_network_processes
    
    # Physical security reminder
    physical_checks_reminder
    
    # Generate final report
    generate_report
}

# Execute main function
main "$@"
