#!/bin/bash

# Apache Tomcat 8 CIS Benchmark - FULL Compliance Validation
# This script performs all CIS checks, evaluates pass/fail, captures evidence,
# rates exploitability, and provides full remediation guidance.
# Output is written to both screen and a compliance report, which is uploaded
# to a GitHub repository if GH_TOKEN is present.

check_controls_v8() {
  local dir="$1"
  local hostname=$(hostname)
  
  local output_dir="/opt/tomcat_hardening"
  mkdir -p "$output_dir"

  local report_name="${hostname}_tomcat8_cis_compliance.txt"
  local report_path="$output_dir/$report_name"

  # Clear or create report file
  : > "$report_path" || { echo "❌ Failed to create $report_path" >&2; return 1; }
  
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Apache Tomcat 8 Hardening Assessment"
  echo "Host: $hostname"
  echo "Version: $("$dir/bin/version.sh" 2>/dev/null | grep 'Server number' | cut -d':' -f2 | xargs)"
  echo "Date: $(date)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  echo "Apache Tomcat 8 Compliance Report - $(date)" > "$report_path"
  echo "Host: $hostname" >> "$report_path"
  echo "Tomcat Version: $("$dir/bin/version.sh" 2>/dev/null | grep 'Server number' | cut -d':' -f2 | xargs)" >> "$report_path"

 # =============================
# [CIS 1.1] Ensure the Latest Security Patches are Applied
# =============================
echo -e "\n[CIS 1.1] Ensure the Latest Security Patches are Applied" | tee -a "$report_path"
tomcat_version_detected=$(grep 'Server version' "$dir/RELEASE-NOTES" 2>/dev/null | head -n1 | awk '{print $NF}')
echo "Evidence: Tomcat version from RELEASE-NOTES is $tomcat_version_detected" | tee -a "$report_path"
if [[ -z "$tomcat_version_detected" ]]; then
  echo "❌ FAIL: Unable to determine Tomcat version from RELEASE-NOTES" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Validate Tomcat installation and check https://tomcat.apache.org/download-80.cgi for the latest version" | tee -a "$report_path"
else
  echo "NOTE: This script does not dynamically compare with latest version online." | tee -a "$report_path"
  echo "✅ INFO: Detected version is $tomcat_version_detected – please verify manually." | tee -a "$report_path"
  echo "Exploitability: Medium – depends on known vulnerabilities in current version." | tee -a "$report_path"
  echo "Remediation: Keep Tomcat updated with the latest security patches from Apache." | tee -a "$report_path"
fi

# =============================
# [CIS 1.2] Remove Unnecessary Default Content
# =============================
echo -e "\n[CIS 1.2] Remove Unnecessary Default Content" | tee -a "$report_path"
default_dirs=("docs" "examples" "host-manager" "manager")
found_defaults=()
for dir_name in "${default_dirs[@]}"; do
  if [[ -d "$dir/webapps/$dir_name" ]]; then
    found_defaults+=("$dir_name")
  fi
done

if [[ ${#found_defaults[@]} -eq 0 ]]; then
  echo "✅ PASS: No default applications or documentation present" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Default applications or documentation found: ${found_defaults[*]}" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Remove the following directories from webapps/: ${found_defaults[*]}" | tee -a "$report_path"
fi

# =============================
# [CIS 2.1] Ensure ownership of Tomcat installation directory is set to tomcat user
# =============================
echo -e "\n[CIS 2.1] Ensure ownership of Tomcat installation directory is set to tomcat user" | tee -a "$report_path"
install_owner=$(stat -c "%U" "$dir")
echo "Evidence: Owner of $dir is $install_owner" | tee -a "$report_path"
if [[ "$install_owner" == "tomcat" ]]; then
  echo "✅ PASS: Tomcat directory is owned by 'tomcat' user" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Tomcat directory is owned by '$install_owner'" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: chown -R tomcat:tomcat $dir" | tee -a "$report_path"
fi

# =============================
# [CIS 2.2] Ensure permissions on Tomcat installation directory are set to 750
# =============================
echo -e "\n[CIS 2.2] Ensure permissions on Tomcat installation directory are set to 750" | tee -a "$report_path"
install_perms=$(stat -c "%a" "$dir")
echo "Evidence: Permissions on $dir are $install_perms" | tee -a "$report_path"
if [[ "$install_perms" -le 750 ]]; then
  echo "✅ PASS: Permissions are set securely (<= 750)" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Permissions are too permissive: $install_perms" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: chmod -R 750 $dir" | tee -a "$report_path"
fi

# =============================
# [CIS 2.3] Ensure Tomcat configuration directory is owned by tomcat user
# =============================
echo -e "\n[CIS 2.3] Ensure Tomcat configuration directory is owned by tomcat user" | tee -a "$report_path"
config_dir="$dir/conf"
config_owner=$(stat -c "%U" "$config_dir")
echo "Evidence: Owner of $config_dir is $config_owner" | tee -a "$report_path"
if [[ "$config_owner" == "tomcat" ]]; then
  echo "✅ PASS: Configuration directory is owned by 'tomcat'" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Configuration directory owned by '$config_owner'" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: chown -R tomcat:tomcat $config_dir" | tee -a "$report_path"
fi

# =============================
# [CIS 2.4] Ensure permissions on Tomcat configuration directory are set to 750
# =============================
echo -e "\n[CIS 2.4] Ensure permissions on Tomcat configuration directory are set to 750" | tee -a "$report_path"
config_perms=$(stat -c "%a" "$config_dir")
echo "Evidence: Permissions on $config_dir are $config_perms" | tee -a "$report_path"
if [[ "$config_perms" -le 750 ]]; then
  echo "✅ PASS: Configuration directory permissions are set securely (<= 750)" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Permissions on configuration directory are too permissive: $config_perms" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: chmod -R 750 $config_dir" | tee -a "$report_path"
fi

# =============================
# [CIS 3.1] Run Tomcat as an unprivileged user
# =============================
echo -e "\n[CIS 3.1] Run Tomcat as an unprivileged user" | tee -a "$report_path"
tomcat_pid=$(pgrep -f 'org.apache.catalina.startup.Bootstrap')
if [[ -n "$tomcat_pid" ]]; then
  tomcat_user=$(ps -o user= -p "$tomcat_pid")
  echo "Evidence: Tomcat process running as $tomcat_user" | tee -a "$report_path"
  if [[ "$tomcat_user" != "root" ]]; then
    echo "✅ PASS: Tomcat is running as unprivileged user: $tomcat_user" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: Tomcat is running as root" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Configure Tomcat service to run as a non-root user such as 'tomcat'" | tee -a "$report_path"
  fi
else
  echo "❌ FAIL: Tomcat process not found or not running" | tee -a "$report_path"
  echo "Remediation: Ensure Tomcat is installed and running to evaluate this control" | tee -a "$report_path"
fi

# =============================
# [CIS 3.2] Prevent Tomcat from starting automatically on boot (if not required)
# =============================
echo -e "\n[CIS 3.2] Prevent Tomcat from starting automatically on boot (if not required)" | tee -a "$report_path"
if command -v systemctl >/dev/null 2>&1; then
  enabled=$(systemctl is-enabled tomcat 2>/dev/null)
else
  enabled=$(chkconfig --list tomcat 2>/dev/null | grep -E '3:on|5:on')
fi
echo "Evidence: Tomcat service boot status: $enabled" | tee -a "$report_path"
if [[ "$enabled" == "disabled" || -z "$enabled" ]]; then
  echo "✅ PASS: Tomcat is not enabled to start on boot" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "⚠️ INFO: Tomcat is set to start on boot – ensure this is necessary" | tee -a "$report_path"
  echo "Exploitability: Context-dependent" | tee -a "$report_path"
  echo "Remediation: Disable automatic startup with 'systemctl disable tomcat' or equivalent" | tee -a "$report_path"
fi

# =============================
# [CIS 4.1] Disable the shutdown port
# =============================
echo -e "\n[CIS 4.1] Disable the shutdown port" | tee -a "$report_path"
shutdown_port=$(grep 'shutdown=' "$server_xml" | grep -v '^<!--' | awk -F'shutdown=' '{print $2}' | tr -d '"' | awk '{print $1}')
echo "Evidence: Shutdown port setting in server.xml: $shutdown_port" | tee -a "$report_path"
if [[ "$shutdown_port" == "-1" ]]; then
  echo "✅ PASS: Shutdown port is disabled (-1)" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Shutdown port is enabled: $shutdown_port" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: In server.xml, set shutdown=\"-1\" to disable remote shutdown port" | tee -a "$report_path"
fi

# =============================
# [CIS 4.2] Bind the connector to specific IP addresses
# =============================
echo -e "\n[CIS 4.2] Bind the connector to specific IP addresses" | tee -a "$report_path"
ip_binding=$(grep -E "<Connector .*address=" "$server_xml")
echo "Evidence: Connector IP binding configuration: $ip_binding" | tee -a "$report_path"
if echo "$ip_binding" | grep -q 'address='; then
  echo "✅ PASS: Connectors are bound to specific IP addresses" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: No address binding found in Connector definitions" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Add 'address=\"<ip-address>\"' attribute to each <Connector> element in server.xml" | tee -a "$report_path"
fi

# =============================
# [CIS 5.1] Ensure Access Logging is Enabled
# =============================
echo -e "\n[CIS 5.1] Ensure Access Logging is Enabled" | tee -a "$report_path"
access_logging=$(grep -i "<Valve className=\"org.apache.catalina.valves.AccessLogValve\"" "$server_xml")
echo "Evidence: $access_logging" | tee -a "$report_path"
if [[ -n "$access_logging" ]]; then
  echo "✅ PASS: Access logging valve is configured" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Access logging is not configured" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Add an AccessLogValve element to server.xml under the <Host> element" | tee -a "$report_path"
fi

# =============================
# [CIS 5.2] Restrict Access to Log Files
# =============================
echo -e "\n[CIS 5.2] Restrict Access to Log Files" | tee -a "$report_path"
log_dir="$dir/logs"
if [[ -d "$log_dir" ]]; then
  log_perms=$(stat -c "%a" "$log_dir")
  log_owner=$(stat -c "%U" "$log_dir")
  echo "Evidence: Permissions: $log_perms, Owner: $log_owner" | tee -a "$report_path"
  if [[ "$log_perms" -le 750 && "$log_owner" == "tomcat" ]]; then
    echo "✅ PASS: Log directory permissions and ownership are secure" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: Log directory permissions/ownership are insecure" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set ownership to tomcat and permissions to 750 with 'chown tomcat:tomcat $log_dir && chmod 750 $log_dir'" | tee -a "$report_path"
  fi
else
  echo "❌ FAIL: Log directory not found at $log_dir" | tee -a "$report_path"
  echo "Remediation: Verify the correct Tomcat log directory and apply secure access controls" | tee -a "$report_path"
fi

# =============================
# [CIS 6.1] Remove Default Applications
# =============================
echo -e "\n[CIS 6.1] Remove Default Applications" | tee -a "$report_path"
default_apps=("examples" "docs" "host-manager" "manager")
found_apps=()
for app in "${default_apps[@]}"; do
  if [[ -d "$dir/webapps/$app" ]]; then
    found_apps+=("$app")
  fi
done

if [[ ${#found_apps[@]} -eq 0 ]]; then
  echo "✅ PASS: No default applications found" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Default applications still present: ${found_apps[*]}" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Remove default applications using 'rm -rf $dir/webapps/{examples,docs,host-manager,manager}'" | tee -a "$report_path"
fi

# =============================
# [CIS 6.2] Remove Unnecessary Web Applications
# =============================
echo -e "\n[CIS 6.2] Remove Unnecessary Web Applications" | tee -a "$report_path"
deployed_apps=$(ls -1 "$dir/webapps" | grep -vE '^ROOT$')
echo "Evidence: Deployed applications other than ROOT: $deployed_apps" | tee -a "$report_path"
if [[ -z "$deployed_apps" ]]; then
  echo "✅ PASS: No unnecessary applications deployed" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "⚠️ INFO: Additional applications found in webapps: $deployed_apps" | tee -a "$report_path"
  echo "Exploitability: Medium (depends on application contents)" | tee -a "$report_path"
  echo "Remediation: Remove any unnecessary or unapproved web applications" | tee -a "$report_path"
fi

# =============================
# [CIS 7.1] Enable the Security Manager
# =============================
echo -e "\n[CIS 7.1] Enable the Security Manager" | tee -a "$report_path"
security_manager_enabled=0

if grep -q "\-Djava.security.manager" "$dir/bin/catalina.sh"; then
  security_manager_enabled=1
  echo "Evidence: Security Manager flag '-Djava.security.manager' found in catalina.sh" | tee -a "$report_path"
elif grep -q "\-security" "$dir/bin/startup.sh"; then
  security_manager_enabled=1
  echo "Evidence: '-security' flag found in startup.sh" | tee -a "$report_path"
else
  echo "Evidence: No Security Manager flags found in catalina.sh or startup.sh" | tee -a "$report_path"
fi

if [[ $security_manager_enabled -eq 1 ]]; then
  echo "✅ PASS: Security Manager is enabled" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Security Manager is not enabled" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Add '-security' to Tomcat startup command or use '-Djava.security.manager' in catalina.sh" | tee -a "$report_path"
fi

# =============================
# [CIS 8.1] Disable or Remove Unused Realms
# =============================
echo -e "\n[CIS 8.1] Disable or Remove Unused Realms" | tee -a "$report_path"
realm_count=$(grep -c '<Realm' "$server_xml")
echo "Evidence: Number of <Realm> entries in server.xml: $realm_count" | tee -a "$report_path"
if [[ "$realm_count" -le 1 ]]; then
  echo "✅ PASS: No unnecessary Realm configurations found" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Multiple Realm configurations found" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Remove or comment out unused Realm entries in server.xml" | tee -a "$report_path"
fi

# =============================
# [CIS 8.2] Use Strong Password Hashes for Realms
# =============================
echo -e "\n[CIS 8.2] Use Strong Password Hashes for Realms" | tee -a "$report_path"
realm_config=$(grep -i 'digest' "$server_xml")
echo "Evidence: Realm digest configuration: $realm_config" | tee -a "$report_path"
if echo "$realm_config" | grep -iq 'digest="sha-256"\|digest="sha-512"'; then
  echo "✅ PASS: Strong hash algorithm configured for Realms" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Weak or no password hashing configured for Realm" | tee -a "$report_path"
  echo "Exploitability: Medium to High" | tee -a "$report_path"
  echo "Remediation: Configure Realm with digest=\"SHA-256\" or stronger in server.xml" | tee -a "$report_path"
fi

# =============================
# [CIS 9.1] Use Secure Connector Configuration (SSL/TLS)
# =============================
echo -e "\n[CIS 9.1] Use Secure Connector Configuration (SSL/TLS)" | tee -a "$report_path"
ssl_connector=$(grep -i "<Connector" "$server_xml" | grep -i 'SSLEnabled="true"')
echo "Evidence: SSL Connector line: $ssl_connector" | tee -a "$report_path"
if [[ -n "$ssl_connector" ]]; then
  echo "✅ PASS: SSL/TLS connector is configured" | tee -a "$report_path"
  echo "Exploitability: Low (Assuming strong ciphers used)" | tee -a "$report_path"
else
  echo "❌ FAIL: No SSL/TLS connector found in server.xml" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Configure a <Connector> with SSLEnabled=\"true\" and appropriate keystore/cipher settings" | tee -a "$report_path"
fi

# =============================
# [CIS 9.2] Disable Insecure HTTP Methods
# =============================
echo -e "\n[CIS 9.2] Disable Insecure HTTP Methods" | tee -a "$report_path"
web_xml="$dir/conf/web.xml"
trace_setting=$(grep -A 10 "<security-constraint>" "$web_xml" | grep -i "TRACE")
echo "Evidence: TRACE method configuration in web.xml: $trace_setting" | tee -a "$report_path"
if echo "$trace_setting" | grep -iq "TRACE"; then
  echo "❌ FAIL: HTTP TRACE method appears to be allowed" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Disable TRACE method by configuring a security-constraint block in web.xml or use RemoteIpFilter" | tee -a "$report_path"
else
  echo "✅ PASS: TRACE method appears to be disabled" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
fi

# =============================
# [CIS 10.1] Set umask to 027 or more restrictive
# =============================
echo -e "\n[CIS 10.1] Set umask to 027 or more restrictive" | tee -a "$report_path"
umask_value=$(grep -E 'umask' "$dir/bin/setenv.sh" 2>/dev/null | grep -v '^#' | awk '{print $2}')
echo "Evidence: umask setting in setenv.sh: $umask_value" | tee -a "$report_path"
if [[ "$umask_value" =~ 027|077 ]]; then
  echo "✅ PASS: Secure umask value ($umask_value) is set" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: No secure umask value found or umask not configured" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Set umask 027 or 077 in $dir/bin/setenv.sh" | tee -a "$report_path"
fi

# =============================
# [CIS 10.2] Restrict access to Tomcat binaries
# =============================
echo -e "\n[CIS 10.2] Restrict access to Tomcat binaries" | tee -a "$report_path"
bin_dir="$dir/bin"
bin_perms=$(stat -c "%a" "$bin_dir")
echo "Evidence: Permissions on $bin_dir: $bin_perms" | tee -a "$report_path"
if [[ "$bin_perms" -le 750 ]]; then
  echo "✅ PASS: Tomcat binaries are restricted" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ FAIL: Permissions on $bin_dir are too permissive: $bin_perms" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: chmod -R 750 $bin_dir and chown -R tomcat:tomcat $bin_dir" | tee -a "$report_path"
fi

  # === Exit with result summary ===
  if grep -q "❌" "$report_path"; then
    echo "" | tee -a "$report_path"
    echo "Tomcat hardening check: FAILED" | tee -a "$report_path"
  else
    echo "" | tee -a "$report_path"
    echo "Tomcat hardening check: PASSED" | tee -a "$report_path"
  fi

  # ✅ Echo the report path for parent script to capture
  echo "$report_path"
}
