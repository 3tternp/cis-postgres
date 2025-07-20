#!/bin/bash

# CIS PostgreSQL 16 Audit with Tabular Report, Banner, Summary
PG_VER="16"
PG_SERVICE="postgresql-${PG_VER}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
HTML_REPORT="${SCRIPT_DIR}/cis_pg_audit_report.html"
TIMESTAMP=$(date)
TOTAL=0
PASS=0
FAIL=0

clear
echo -e "\033[1;34m"
echo "#############################################################"
echo "#           CIS PostgreSQL 16 Security Audit Tool           #"
echo "#                HTML Tabular Report Format                 #"
echo "#############################################################"
echo -e "\033[0m"

read -p "Do you agree to run this audit? (yes/no): " consent
[[ "$consent" != "yes" ]] && echo "Exiting." && exit 1

read -p "Enter OS type (centos/debian): " os_type
case "$os_type" in
  centos) repo_check="pgdg${PG_VER}" ;;
  debian) repo_check="apt.postgresql.org" ;;
  *) echo "Unsupported OS."; exit 1 ;;
esac

psql_query() {
  sudo -u postgres psql -tAc "$1" 2>/dev/null
}

# Start HTML
cat <<EOF > "$HTML_REPORT"
<html><head><title>CIS PostgreSQL 16 Report</title>
<style>
body { font-family: Arial; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
th { background: #003366; color: white; }
.pass { background: #c6f6d5; }
.fail { background: #feb2b2; }
</style>
</head><body>
<h2>CIS PostgreSQL Benchmark Audit Report</h2>
<p><strong>Date:</strong> $TIMESTAMP</p>
<table>
<tr><th>ID</th><th>Check</th><th>Status</th><th>Risk</th><th>Type</th><th>Remediation</th></tr>
EOF

write_row() {
  local id="$1" desc="$2" status="$3" risk="$4" type="$5" fix="$6"
  TOTAL=$((TOTAL+1))
  [[ "$status" == "PASS" ]] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
  echo "<tr class='$(echo $status | tr 'A-Z' 'a-z')'><td>$id</td><td>$desc</td><td>$status</td><td>$risk</td><td>$type</td><td>$fix</td></tr>" >> "$HTML_REPORT"
}

# Check 1.1
if [[ "$os_type" == "centos" ]]; then
  dnf info $(rpm -qa | grep postgresql${PG_VER}) | grep -q "$repo_check"
else
  apt-cache policy | grep postgresql | grep -q "$repo_check"
fi
[[ $? -eq 0 ]] && res="PASS" || res="FAIL"
write_row "1.1" "Packages from authorized sources" "$res" "High" "Quick" "Use official PG repos"

# Check 1.2
systemctl is-enabled ${PG_SERVICE} &>/dev/null
[[ $? -eq 0 ]] && res="PASS" || res="FAIL"
write_row "1.2" "PostgreSQL service enabled" "$res" "Medium" "Quick" "Run: systemctl enable ${PG_SERVICE}"

# Check 2.1
umask_val=$(sudo -u postgres bash -c 'umask')
[[ "$umask_val" == "0077" ]] && res="PASS" || res="FAIL"
write_row "2.1" "Postgres umask is 0077" "$res" "Medium" "Planned" "Set umask in .bash_profile"

# PostgreSQL Settings
declare -A pg_checks=(
["3.1.2"]="SHOW log_destination;|csvlog"
["3.1.3"]="SHOW logging_collector;|on"
["3.1.6"]="SHOW log_file_mode;|0600"
["3.1.14"]="SHOW log_min_messages;|warning"
["3.1.15"]="SHOW log_min_error_statement;|error"
["3.1.16"]="SHOW debug_print_parse;|off"
["3.1.17"]="SHOW debug_print_rewritten;|off"
["3.1.18"]="SHOW debug_print_plan;|off"
["3.1.19"]="SHOW debug_pretty_print;|on"
["6.7"]="SHOW ssl_library;|OpenSSL"
["6.8"]="SHOW ssl;|on"
)

for id in "${!pg_checks[@]}"; do
  query="${pg_checks[$id]%%|*}"
  expected="${pg_checks[$id]##*|}"
  value=$(psql_query "$query" | xargs)
  [[ "$value" == *"$expected"* ]] && status="PASS" || status="FAIL"
  write_row "$id" "$query" "$status" "Medium" "Quick" "Set in postgresql.conf"
done

# Summary
echo "</table><br>" >> "$HTML_REPORT"
echo "<h3>Summary</h3>" >> "$HTML_REPORT"
echo "<p><strong>Total Checks:</strong> $TOTAL</p>" >> "$HTML_REPORT"
echo "<p><strong>Passed:</strong> $PASS</p>" >> "$HTML_REPORT"
echo "<p><strong>Failed:</strong> $FAIL</p>" >> "$HTML_REPORT"
echo "</body></html>" >> "$HTML_REPORT"

echo -e "\n\033[1;32mAudit complete. Report saved at:\033[0m $HTML_REPORT"
