#!/bin/bash

# CIS PostgreSQL 16 Benchmark Audit Script with HTML Output, Banner, and Dynamic Output Path
# Author: ChatGPT
# Version: Extended with Banner & Output Directory Fix

PG_VER="16"
PG_SERVICE="postgresql-${PG_VER}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
HTML_REPORT="${SCRIPT_DIR}/cis_pg_audit_report.html"
PGDATA="/var/lib/pgsql/${PG_VER}/data"
PG_BIN="/usr/pgsql-${PG_VER}/bin"
TIMESTAMP=$(date)

# Banner
clear
echo -e "\033[1;34m"
echo "###############################################################"
echo "#                                                             #"
echo "#         CIS PostgreSQL 16 Benchmark Audit Utility           #"
echo "#            Security Configuration Check Script              #"
echo "#                                                             #"
echo "###############################################################"
echo -e "\033[0m"

# Start HTML Report
echo "<html><head><title>CIS PostgreSQL 16 Audit Report</title></head><body>" > "$HTML_REPORT"
echo "<h1 style='color:#003366;'>CIS PostgreSQL 16 Benchmark Audit Report</h1>" >> "$HTML_REPORT"
echo "<p><strong>Date:</strong> $TIMESTAMP</p>" >> "$HTML_REPORT"

# Consent
read -p "Do you agree to run this CIS Benchmark audit script on this system? (yes/no): " consent
if [[ "$consent" != "yes" ]]; then
    echo "Consent not given. Exiting."
    echo "<p><strong>Status:</strong> Audit not performed. Consent not provided.</p></body></html>" >> "$HTML_REPORT"
    exit 1
fi

# OS Detection
read -p "Enter your OS type (centos/debian): " os_type
case "$os_type" in
  centos)
    pkg_mgr="dnf"
    repo_check="pgdg${PG_VER}"
    ;;
  debian)
    pkg_mgr="apt"
    repo_check="apt.postgresql.org"
    ;;
  *)
    echo "Unsupported OS. Use 'centos' or 'debian'."
    echo "<p><strong>Status:</strong> Unsupported OS entered.</p></body></html>" >> "$HTML_REPORT"
    exit 1
    ;;
esac

# Output helper
write_finding() {
    local id="$1"
    local name="$2"
    local result="$3"
    local severity="$4"
    local type="$5"
    local remediation="$6"

    echo "<div style='border:1px solid #ccc;padding:10px;margin:10px;'>" >> "$HTML_REPORT"
    echo "<h3>$id - $name</h3>" >> "$HTML_REPORT"
    echo "<p><strong>Risk Rating:</strong> $severity</p>" >> "$HTML_REPORT"
    echo "<p><strong>Finding Type:</strong> $type</p>" >> "$HTML_REPORT"
    echo "<p><strong>Status:</strong> <strong style='color:$( [[ "$result" == "PASS" ]] && echo green || echo red );'>$result</strong></p>" >> "$HTML_REPORT"
    echo "<p><strong>Remediation:</strong> $remediation</p>" >> "$HTML_REPORT"
    echo "</div>" >> "$HTML_REPORT"
}

# Run PostgreSQL query
psql_query() {
    sudo -u postgres psql -tAc "$1" 2>/dev/null
}

### BENCHMARK CHECKS

# 1.1 Authorized repositories
if [[ "$os_type" == "centos" ]]; then
    out=$(dnf info $(rpm -qa | grep postgresql${PG_VER}) 2>/dev/null | grep "From repo" | grep -q "$repo_check" && echo "PASS" || echo "FAIL")
else
    out=$(apt-cache policy | grep postgresql | grep -q "$repo_check" && echo "PASS" || echo "FAIL")
fi
write_finding "1.1" "Ensure packages are from authorized repositories" "$out" "High" "Quick" "Use only PostgreSQL official or internal signed package sources."

# 1.2 Systemd service
systemctl is-enabled ${PG_SERVICE} &>/dev/null
out=$([[ $? -eq 0 ]] && echo "PASS" || echo "FAIL")
write_finding "1.2" "Ensure systemd PostgreSQL service is enabled" "$out" "Medium" "Quick" "Run: systemctl enable ${PG_SERVICE}"

# 2.1 Umask
umask_val=$(sudo -u postgres bash -c 'umask')
out=$([[ "$umask_val" == "0077" ]] && echo "PASS" || echo "FAIL")
write_finding "2.1" "Ensure postgres user has umask set to 0077" "$out" "Medium" "Planned" "Set umask 077 in .bash_profile for postgres user."

# 3.x Logging
declare -A checks=(
    ["3.1.2"]="SHOW log_destination;"
    ["3.1.3"]="SHOW logging_collector;"
    ["3.1.4"]="SHOW log_directory;"
    ["3.1.5"]="SHOW log_filename;"
    ["3.1.6"]="SHOW log_file_mode;"
    ["3.1.7"]="SHOW log_truncate_on_rotation;"
    ["3.1.8"]="SHOW log_rotation_age;"
    ["3.1.9"]="SHOW log_rotation_size;"
    ["3.1.14"]="SHOW log_min_messages;"
    ["3.1.15"]="SHOW log_min_error_statement;"
    ["3.1.16"]="SHOW debug_print_parse;"
    ["3.1.17"]="SHOW debug_print_rewritten;"
    ["3.1.18"]="SHOW debug_print_plan;"
    ["3.1.19"]="SHOW debug_pretty_print;"
)

declare -A expected=(
    ["3.1.2"]="csvlog"
    ["3.1.3"]="on"
    ["3.1.4"]="/"
    ["3.1.5"]="postgresql-"
    ["3.1.6"]="0600"
    ["3.1.7"]="on"
    ["3.1.8"]="0"
    ["3.1.9"]="0"
    ["3.1.14"]="warning"
    ["3.1.15"]="error"
    ["3.1.16"]="off"
    ["3.1.17"]="off"
    ["3.1.18"]="off"
    ["3.1.19"]="on"
)

for id in "${!checks[@]}"; do
    value=$(psql_query "${checks[$id]}")
    vclean=$(echo "$value" | xargs)
    exp="${expected[$id]}"
    if [[ "$id" == "3.1.4" ]]; then
        [[ "$vclean" != "/" ]] && status="PASS" || status="FAIL"
    elif [[ "$id" == "3.1.8" || "$id" == "3.1.9" ]]; then
        [[ "$vclean" != "0" ]] && status="PASS" || status="FAIL"
    elif [[ "$id" == "3.1.2" || "$id" == "3.1.5" ]]; then
        [[ "$vclean" == *"$exp"* ]] && status="PASS" || status="FAIL"
    else
        [[ "$vclean" == "$exp" ]] && status="PASS" || status="FAIL"
    fi
    write_finding "$id" "${checks[$id]}" "$status" "Medium" "Quick" "Adjust this value in postgresql.conf."
done

# Close HTML
echo "</body></html>" >> "$HTML_REPORT"
echo -e "\n\033[1;32mAudit complete. View the HTML report at:\033[0m $HTML_REPORT"
