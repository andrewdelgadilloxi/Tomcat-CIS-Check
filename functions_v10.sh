#!/bin/bash

# Apache Tomcat 10 CIS Benchmark v1.1.0 - FULL Compliance Validation
# This script performs all CIS checks, evaluates pass/fail, captures evidence,
# rates exploitability, and provides full remediation guidance.
# Output is written to both screen and a compliance report, which is uploaded
# to a GitHub repository if GH_TOKEN is present.

check_controls_v10() {
  local dir="$1"
  local hostname=$(hostname)
  
  local output_dir="/opt/tomcat_hardening"
  mkdir -p "$output_dir"

  local report_name="${hostname}_tomcat10_cis_compliance.txt"
  local report_path="$output_dir/$report_name"

  # Clear or create report file
  : > "$report_path" || { echo "❌ Failed to create $report_path" >&2; return 1; }
  
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Apache Tomcat 10 Hardening Assessment"
  echo "Host: $hostname"
  echo "Version: $("$dir/bin/version.sh" 2>/dev/null | grep 'Server number' | cut -d':' -f2 | xargs)"
  echo "Date: $(date)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  echo "Apache Tomcat 10 Compliance Report - $(date)" > "$report_path"
  echo "Host: $hostname" >> "$report_path"
  echo "Tomcat Version: $("$dir/bin/version.sh" 2>/dev/null | grep 'Server number' | cut -d':' -f2 | xargs)" >> "$report_path"

# [CIS 1.1] Remove sample applications and documentation
echo -e "\n[CIS 1.1] Remove sample applications and documentation" | tee -a "$report_path"
samples=(examples docs ROOT host-manager manager)
found=0
for app in "${samples[@]}"; do
  if [[ -e "$dir/webapps/$app" || -e "$dir/server/webapps/$app" ]]; then
    echo "❌ Found: $app in webapps directory" | tee -a "$report_path"
    echo "Evidence: $dir/webapps/$app exists" | tee -a "$report_path"
    found=1
  else
    echo "✅ $app not found in webapps directory" | tee -a "$report_path"
    echo "Evidence: $dir/webapps/$app does not exist" | tee -a "$report_path"
  fi
done
[[ $found -eq 0 ]] && echo "Exploitability: Low" || echo "Exploitability: Medium" | tee -a "$report_path"
[[ $found -eq 0 ]] || echo "Remediation: Remove unused sample applications from $dir/webapps/" | tee -a "$report_path"

# [CIS 1.2] Remove or secure the shutdown port
echo -e "\n[CIS 1.2] Remove or secure the shutdown port" | tee -a "$report_path"
shutdown_port=$(grep -oP '<Server port="\K[^"]+' "$dir/conf/server.xml")
echo "Evidence: Shutdown port is configured as '$shutdown_port'" | tee -a "$report_path"
if [[ "$shutdown_port" == "-1" ]]; then
  echo "✅ Shutdown port is disabled (port=-1)" | tee -a "$report_path"
else
  echo "❌ Shutdown port is set to $shutdown_port" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Change the shutdown port to -1 in server.xml to disable remote shutdown access" | tee -a "$report_path"
fi

# [CIS 1.3] Disable or secure unused connectors
echo -e "\n[CIS 1.3] Disable or secure unused connectors" | tee -a "$report_path"
connector_count=$(grep -c '<Connector ' "$dir/conf/server.xml")
echo "Evidence: Found $connector_count <Connector> entries in server.xml" | tee -a "$report_path"
if [[ $connector_count -le 1 ]]; then
  echo "✅ Only necessary connector(s) are configured" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ Multiple connectors detected; verify necessity and disable unused ones" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Comment out or remove unused <Connector> entries in server.xml" | tee -a "$report_path"
fi

# [CIS 1.4] Change the shutdown command to a non-default value
echo -e "\n[CIS 1.4] Change the shutdown command" | tee -a "$report_path"
shutdown_cmd=$(grep -oP 'shutdown="\K[^"]+' "$dir/conf/server.xml")
echo "Evidence: Shutdown command is '$shutdown_cmd'" | tee -a "$report_path"
if [[ "$shutdown_cmd" != "SHUTDOWN" ]]; then
  echo "✅ Custom shutdown command is configured" | tee -a "$report_path"
else
  echo "❌ Default shutdown command 'SHUTDOWN' is in use" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Change shutdown=\"SHUTDOWN\" to a strong random string in server.xml" | tee -a "$report_path"
fi

# [CIS 1.5] Remove or obfuscate the server header
echo -e "\n[CIS 1.5] Remove or obfuscate the server header" | tee -a "$report_path"
server_header=$(grep -oP 'server="\K[^"]+' "$dir/conf/server.xml")
echo "Evidence: server header is set to '$server_header'" | tee -a "$report_path"
if [[ -n "$server_header" && "$server_header" != "Apache Tomcat" ]]; then
  echo "✅ server header is obfuscated or customized" | tee -a "$report_path"
else
  echo "❌ server header is default or not set" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Set a custom 'server' attribute in <Connector> elements to obscure Tomcat identity" | tee -a "$report_path"
fi

# [CIS 1.6] Disable TRACE method
echo -e "\n[CIS 1.6] Disable TRACE method" | tee -a "$report_path"
trace_check=$(grep -o 'allowTrace="true"' "$dir/conf/server.xml")
echo "Evidence: $(if [[ -n "$trace_check" ]]; then echo "allowTrace=\"true\" found"; else echo "allowTrace not set or set to false"; fi)" | tee -a "$report_path"
if grep -q 'allowTrace="true"' "$dir/conf/server.xml"; then
  echo "❌ TRACE method is enabled" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Set allowTrace=\"false\" or remove the attribute from all <Connector> elements" | tee -a "$report_path"
else
  echo "✅ TRACE method is disabled or not explicitly enabled" | tee -a "$report_path"
fi

# [CIS 1.7] Disable auto deployment of applications
echo -e "\n[CIS 1.7] Disable auto deployment of applications" | tee -a "$report_path"
auto_deploy=$(grep -oP 'autoDeploy="\K[^"]+' "$dir/conf/server.xml" | head -n1)
deploy_on_startup=$(grep -oP 'deployOnStartup="\K[^"]+' "$dir/conf/server.xml" | head -n1)
echo "Evidence: autoDeploy=\"$auto_deploy\", deployOnStartup=\"$deploy_on_startup\"" | tee -a "$report_path"
if [[ "$auto_deploy" == "false" && "$deploy_on_startup" == "false" ]]; then
  echo "✅ Auto deployment and deploy-on-startup are disabled" | tee -a "$report_path"
else
  echo "❌ autoDeploy or deployOnStartup still enabled" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Set autoDeploy=\"false\" and deployOnStartup=\"false\" in <Host> section of server.xml" | tee -a "$report_path"
fi

# [CIS 1.8] Restrict access to the manager application
echo -e "\n[CIS 1.8] Restrict access to the manager application" | tee -a "$report_path"
if [[ -e "$dir/webapps/manager" ]]; then
  manager_realm=$(grep -A5 '<Context' "$dir/webapps/manager/META-INF/context.xml" 2>/dev/null | grep -i 'Valve\|RemoteAddr')
  echo "Evidence: $([[ -n "$manager_realm" ]] && echo "$manager_realm" || echo "No IP restriction found")" | tee -a "$report_path"
  if echo "$manager_realm" | grep -q 'RemoteAddrValve'; then
    echo "✅ Remote address restriction is configured for manager app" | tee -a "$report_path"
  else
    echo "❌ No IP-based access restriction for manager app" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Define a RemoteAddrValve in context.xml to restrict manager app by IP" | tee -a "$report_path"
  fi
else
  echo "✅ Manager application not installed" | tee -a "$report_path"
fi

# [CIS 1.9] Restrict access to the host-manager application
echo -e "\n[CIS 1.9] Restrict access to the host-manager application" | tee -a "$report_path"
if [[ -e "$dir/webapps/host-manager" ]]; then
  host_mgr_realm=$(grep -A5 '<Context' "$dir/webapps/host-manager/META-INF/context.xml" 2>/dev/null | grep -i 'Valve\|RemoteAddr')
  echo "Evidence: $([[ -n "$host_mgr_realm" ]] && echo "$host_mgr_realm" || echo "No IP restriction found")" | tee -a "$report_path"
  if echo "$host_mgr_realm" | grep -q 'RemoteAddrValve'; then
    echo "✅ Remote address restriction is configured for host-manager app" | tee -a "$report_path"
  else
    echo "❌ No IP-based access restriction for host-manager app" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Define a RemoteAddrValve in context.xml to restrict host-manager app by IP" | tee -a "$report_path"
  fi
else
  echo "✅ Host-manager application not installed" | tee -a "$report_path"
fi

# [CIS 1.10] Remove the default ROOT application
echo -e "\n[CIS 1.10] Remove the default ROOT application" | tee -a "$report_path"
if [[ -d "$dir/webapps/ROOT" ]]; then
  echo "❌ Default ROOT application is installed" | tee -a "$report_path"
  echo "Evidence: $dir/webapps/ROOT exists" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Remove the ROOT directory from $dir/webapps/" | tee -a "$report_path"
else
  echo "✅ ROOT application not present" | tee -a "$report_path"
fi

# [CIS 2.1] Hide server version information
echo -e "\n[CIS 2.1] Hide server version information" | tee -a "$report_path"
server_info=$(unzip -p "$dir/lib/catalina.jar" org/apache/catalina/util/ServerInfo.properties 2>/dev/null | grep server.info)
echo "Evidence: $server_info" | tee -a "$report_path"
if [[ "$server_info" =~ Apache ]]; then
  echo "❌ Default server.info value found" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Modify server.info in ServerInfo.properties within catalina.jar to obfuscate identity" | tee -a "$report_path"
else
  echo "✅ server.info is customized" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
fi

# [CIS 2.2] Hide server build number
echo -e "\n[CIS 2.2] Hide server build number" | tee -a "$report_path"
server_built=$(unzip -p "$dir/lib/catalina.jar" org/apache/catalina/util/ServerInfo.properties 2>/dev/null | grep server.built)
echo "Evidence: $server_built" | tee -a "$report_path"
if [[ "$server_built" =~ [0-9]{4}-[0-9]{2}-[0-9]{2} ]]; then
  echo "❌ Build date detected" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
  echo "Remediation: Modify server.built to mask build date in ServerInfo.properties" | tee -a "$report_path"
else
  echo "✅ server.built appears customized or hidden" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
fi

# [CIS 2.3] Hide server version number
echo -e "\n[CIS 2.3] Hide server version number" | tee -a "$report_path"
server_number=$(unzip -p "$dir/lib/catalina.jar" org/apache/catalina/util/ServerInfo.properties 2>/dev/null | grep server.number)
echo "Evidence: $server_number" | tee -a "$report_path"
if [[ "$server_number" =~ ^11\\. ]]; then
  echo "❌ Default version string detected" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Modify server.number in ServerInfo.properties inside catalina.jar" | tee -a "$report_path"
else
  echo "✅ server.number is customized" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
fi

# [CIS 2.4] Disable X-Powered-By header
echo -e "\n[CIS 2.4] Disable X-Powered-By header" | tee -a "$report_path"
xpb_status=$(grep -oP 'xpoweredBy="\K[^"]+' "$dir/conf/server.xml")
echo "Evidence: xpoweredBy=\"$xpb_status\"" | tee -a "$report_path"
if [[ "$xpb_status" == "false" ]]; then
  echo "✅ xpoweredBy is explicitly disabled" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ xpoweredBy is not set to false" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Set xpoweredBy=\"false\" in Connector elements in server.xml" | tee -a "$report_path"
fi

# [CIS 3.1] Restrict access to conf directory
echo -e "\n[CIS 3.1] Restrict access to conf directory" | tee -a "$report_path"
conf_perms=$(stat -c "%a" "$dir/conf")
conf_owner=$(stat -c "%U:%G" "$dir/conf")
echo "Evidence: Permissions = $conf_perms, Ownership = $conf_owner" | tee -a "$report_path"
if [[ "$conf_owner" == "tomcat:tomcat" && "$conf_perms" -le 750 ]]; then
  echo "✅ conf directory is properly secured" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ conf directory is too permissive or improperly owned" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Run 'chown tomcat:tomcat $dir/conf && chmod 750 $dir/conf'" | tee -a "$report_path"
fi

# [CIS 3.2] Restrict access to bin directory
echo -e "\n[CIS 3.2] Restrict access to bin directory" | tee -a "$report_path"
bin_perms=$(stat -c "%a" "$dir/bin")
bin_owner=$(stat -c "%U:%G" "$dir/bin")
echo "Evidence: Permissions = $bin_perms, Ownership = $bin_owner" | tee -a "$report_path"
if [[ "$bin_owner" == "tomcat:tomcat" && "$bin_perms" -le 750 ]]; then
  echo "✅ bin directory is properly secured" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ bin directory is too permissive or improperly owned" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Run 'chown tomcat:tomcat $dir/bin && chmod 750 $dir/bin'" | tee -a "$report_path"
fi

# [CIS 3.3] Restrict access to logs directory
echo -e "\n[CIS 3.3] Restrict access to logs directory" | tee -a "$report_path"
logs_perms=$(stat -c "%a" "$dir/logs")
logs_owner=$(stat -c "%U:%G" "$dir/logs")
echo "Evidence: Permissions = $logs_perms, Ownership = $logs_owner" | tee -a "$report_path"
if [[ "$logs_owner" == "tomcat:tomcat" && "$logs_perms" -le 750 ]]; then
  echo "✅ logs directory is properly secured" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ logs directory is too permissive or improperly owned" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Run 'chown tomcat:tomcat $dir/logs && chmod 750 $dir/logs'" | tee -a "$report_path"
fi

# [CIS 3.4] Restrict access to webapps directory
echo -e "\n[CIS 3.4] Restrict access to webapps directory" | tee -a "$report_path"
webapps_perms=$(stat -c "%a" "$dir/webapps")
webapps_owner=$(stat -c "%U:%G" "$dir/webapps")
echo "Evidence: Permissions = $webapps_perms, Ownership = $webapps_owner" | tee -a "$report_path"
if [[ "$webapps_owner" == "tomcat:tomcat" && "$webapps_perms" -le 750 ]]; then
  echo "✅ webapps directory is properly secured" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ webapps directory is too permissive or improperly owned" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Run 'chown tomcat:tomcat $dir/webapps && chmod 750 $dir/webapps'" | tee -a "$report_path"
fi

# [CIS 4.1] Configure centralized logging
echo -e "\n[CIS 4.1] Configure centralized logging" | tee -a "$report_path"
if [[ -f "$dir/conf/logging.properties" ]]; then
  log_dir=$(grep 'org.apache.juli.FileHandler.directory' "$dir/conf/logging.properties" | cut -d'=' -f2 | xargs)
  echo "Evidence: org.apache.juli.FileHandler.directory = $log_dir" | tee -a "$report_path"
  if [[ -n "$log_dir" && "$log_dir" != "." ]]; then
    echo "✅ Logging is directed to a centralized directory" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ Logging may be using default or relative path" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set a full path for org.apache.juli.FileHandler.directory in logging.properties" | tee -a "$report_path"
  fi
else
  echo "❌ logging.properties file not found" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Recreate logging.properties or restore from a known-good configuration" | tee -a "$report_path"
fi

# [CIS 4.2] Secure access to log files
echo -e "\n[CIS 4.2] Secure access to log files" | tee -a "$report_path"
if [[ -d "$dir/logs" ]]; then
  perms=$(stat -c "%a" "$dir/logs")
  owner=$(stat -c "%U:%G" "$dir/logs")
  echo "Evidence: logs/ permissions = $perms, owner = $owner" | tee -a "$report_path"
  if [[ "$owner" == "tomcat:tomcat" && "$perms" -le 750 ]]; then
    echo "✅ Log directory is properly secured" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ Log directory is too permissive or improperly owned" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: chown tomcat:tomcat $dir/logs && chmod 750 $dir/logs" | tee -a "$report_path"
  fi
else
  echo "❌ logs directory does not exist" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Ensure logging directory exists at $dir/logs with restricted access" | tee -a "$report_path"
fi

# [CIS 4.3] Ensure log rotation is configured
echo -e "\n[CIS 4.3] Ensure log rotation is configured" | tee -a "$report_path"
rotation_check=$(grep -i 'rotatable=' "$dir/conf/logging.properties" | grep -i 'false')
echo "Evidence: $(if [[ -z "$rotation_check" ]]; then echo "rotation enabled (default or explicit)"; else echo "$rotation_check"; fi)" | tee -a "$report_path"
if [[ -z "$rotation_check" ]]; then
  echo "✅ Log rotation appears to be enabled" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ Log rotation is disabled for some handlers" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Remove rotatable=false or explicitly set rotatable=true in logging.properties" | tee -a "$report_path"
fi

# [CIS 4.4] Enable access log valve for web access logging
echo -e "\n[CIS 4.4] Enable access log valve" | tee -a "$report_path"
access_log_check=$(grep -i '<Valve className="org.apache.catalina.valves.AccessLogValve"' "$dir/conf/server.xml")
echo "Evidence: $(if [[ -n "$access_log_check" ]]; then echo "AccessLogValve present"; else echo "No AccessLogValve found"; fi)" | tee -a "$report_path"
if [[ -n "$access_log_check" ]]; then
  echo "✅ Access logging is enabled via AccessLogValve" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ AccessLogValve not present in server.xml" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Add AccessLogValve to <Host> section of server.xml for access auditing" | tee -a "$report_path"
fi

# [CIS 5.1] Use LockOutRealm for brute-force protection
echo -e "\n[CIS 5.1] Use LockOutRealm for brute-force protection" | tee -a "$report_path"
lockout_realm=$(grep -i 'LockOutRealm' "$dir/conf/server.xml")
echo "Evidence: $(if [[ -n "$lockout_realm" ]]; then echo "$lockout_realm"; else echo "No LockOutRealm found"; fi)" | tee -a "$report_path"
if [[ -n "$lockout_realm" ]]; then
  echo "✅ LockOutRealm is configured" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ LockOutRealm is not configured" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Add <Realm className=\"org.apache.catalina.realm.LockOutRealm\"> around user realm definition in server.xml" | tee -a "$report_path"
fi

# [CIS 5.2] Restrict access to tomcat-users.xml
echo -e "\n[CIS 5.2] Restrict access to tomcat-users.xml" | tee -a "$report_path"
if [[ -f "$dir/conf/tomcat-users.xml" ]]; then
  perms=$(stat -c "%a" "$dir/conf/tomcat-users.xml")
  owner=$(stat -c "%U:%G" "$dir/conf/tomcat-users.xml")
  echo "Evidence: Permissions = $perms, Owner = $owner" | tee -a "$report_path"
  if [[ "$owner" == "tomcat:tomcat" && $perms -le 640 ]]; then
    echo "✅ tomcat-users.xml is securely configured" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ tomcat-users.xml permissions are too permissive or improperly owned" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: chown tomcat:tomcat $dir/conf/tomcat-users.xml && chmod 640 $dir/conf/tomcat-users.xml" | tee -a "$report_path"
  fi
else
  echo "❌ tomcat-users.xml not found" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Ensure tomcat-users.xml exists and is securely owned with restrictive permissions" | tee -a "$report_path"
fi

# [CIS 5.3] Avoid use of clear-text passwords
echo -e "\n[CIS 5.3] Avoid use of clear-text passwords" | tee -a "$report_path"
if grep -q 'password="[^"]\+"' "$dir/conf/tomcat-users.xml"; then
  echo "❌ Passwords appear to be stored in clear text in tomcat-users.xml" | tee -a "$report_path"
  echo "Evidence: Cleartext password attributes found" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Integrate digest password storage or externalize credentials via JNDI or secure vault" | tee -a "$report_path"
else
  echo "✅ No clear-text password values found in tomcat-users.xml" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
fi

# [CIS 6.1] Ensure HTTPS is used for all connections
echo -e "\n[CIS 6.1] Ensure HTTPS is used for all connections" | tee -a "$report_path"
https_connectors=$(grep '<Connector' "$dir/conf/server.xml" | grep -i 'sslProtocol\|SSLEnabled')
echo "Evidence: $(if [[ -n \"$https_connectors\" ]]; then echo \"$https_connectors\"; else echo \"No SSL-enabled connectors found\"; fi)" | tee -a "$report_path"
if echo "$https_connectors" | grep -q 'SSLEnabled="true"'; then
  echo "✅ HTTPS connectors are configured" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ HTTPS connectors not found or not enabled" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Define <Connector ... SSLEnabled=\"true\" ... /> in server.xml with appropriate certs" | tee -a "$report_path"
fi

# [CIS 6.2] Use strong SSL/TLS protocols
echo -e "\n[CIS 6.2] Use strong SSL/TLS protocols" | tee -a "$report_path"
tls_protocols=$(grep -i 'sslProtocol\|protocol' "$dir/conf/server.xml" | grep -i 'TLS')
echo "Evidence: $(if [[ -n \"$tls_protocols\" ]]; then echo \"$tls_protocols\"; else echo \"No TLS protocol explicitly defined\"; fi)" | tee -a "$report_path"
if echo "$tls_protocols" | grep -q 'TLSv1\.2\|TLSv1\.3'; then
  echo "✅ Strong TLS protocol (1.2 or 1.3) is configured" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ Weak or unspecified SSL/TLS protocol used" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Set protocol=\"TLSv1.2\" or \"TLSv1.3\" in all <Connector> blocks in server.xml" | tee -a "$report_path"
fi

# [CIS 6.3] Configure secure ciphers
echo -e "\n[CIS 6.3] Configure secure ciphers" | tee -a "$report_path"
ciphers=$(grep -i 'ciphers' "$dir/conf/server.xml")
echo "Evidence: $(if [[ -n \"$ciphers\" ]]; then echo \"$ciphers\"; else echo \"No cipher suite configuration found\"; fi)" | tee -a "$report_path"
if [[ "$ciphers" =~ ECDHE ]]; then
  echo "✅ Secure ciphers including ECDHE are configured" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ Secure cipher suites are not configured" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Define strong cipher suite list (e.g., ECDHE+AESGCM) in the <Connector> configuration" | tee -a "$report_path"
fi

# [CIS 6.4] Disable insecure SSL/TLS protocols
echo -e "\n[CIS 6.4] Disable insecure SSL/TLS protocols" | tee -a "$report_path"
disabled_protocols=$(grep -i 'sslEnabledProtocols' "$dir/conf/server.xml")
echo "Evidence: $(if [[ -n \"$disabled_protocols\" ]]; then echo \"$disabled_protocols\"; else echo \"sslEnabledProtocols not configured\"; fi)" | tee -a "$report_path"
if echo "$disabled_protocols" | grep -q 'TLSv1\|TLSv1\.1'; then
  echo "❌ Insecure protocols (TLSv1 or TLSv1.1) still allowed" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Remove TLSv1 and TLSv1.1 from sslEnabledProtocols or restrict to TLSv1.2 and TLSv1.3 only" | tee -a "$report_path"
else
  echo "✅ Insecure SSL/TLS protocols are not enabled" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
fi

# [CIS 7.1] Ensure Tomcat is up to date
echo -e "\n[CIS 7.1] Ensure Tomcat is up to date" | tee -a "$report_path"
installed_version=$("$dir/bin/version.sh" 2>/dev/null | grep 'Server number' | cut -d':' -f2 | xargs)
echo "Evidence: Installed Tomcat version = $installed_version" | tee -a "$report_path"

latest_version=$(curl -s https://downloads.apache.org/tomcat/tomcat-11/ | grep -Eo 'v11\.[0-9]+\.[0-9]+' | sort -V | tail -n1)

if [[ -n "$latest_version" && "$installed_version" == *"${latest_version/v/}"* ]]; then
  echo "✅ Installed version $installed_version is current (latest = ${latest_version/v/})" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ Installed version $installed_version is outdated (latest = ${latest_version/v/})" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Download and install the latest Tomcat 11 release from https://tomcat.apache.org" | tee -a "$report_path"
fi

# [CIS 8.1] Restrict access to sensitive Tomcat files
echo -e "\n[CIS 8.1] Restrict access to sensitive Tomcat files" | tee -a "$report_path"
sensitive_files=("$dir/conf/server.xml" "$dir/conf/web.xml" "$dir/bin/catalina.sh")
for file in "${sensitive_files[@]}"; do
  if [[ -f "$file" ]]; then
    perms=$(stat -c "%a" "$file")
    owner=$(stat -c "%U:%G" "$file")
    echo "File: $file | Permissions: $perms | Owner: $owner" | tee -a "$report_path"
    if [[ "$owner" == "tomcat:tomcat" && "$perms" -le 640 ]]; then
      echo "✅ $file is properly secured" | tee -a "$report_path"
    else
      echo "❌ $file is too permissive or improperly owned" | tee -a "$report_path"
      echo "Remediation: chown tomcat:tomcat $file && chmod 640 $file" | tee -a "$report_path"
    fi
  else
    echo "⚠️ $file not found; validate manually" | tee -a "$report_path"
  fi
done

# [CIS 8.2] Ensure setuid and setgid bits are not set on Tomcat scripts
echo -e "\n[CIS 8.2] Ensure setuid/setgid bits are not set on Tomcat scripts" | tee -a "$report_path"
setuid_files=$(find "$dir/bin" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
if [[ -z "$setuid_files" ]]; then
  echo "✅ No setuid/setgid bits set on Tomcat scripts" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ The following scripts have setuid/setgid bits set:" | tee -a "$report_path"
  echo "$setuid_files" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: chmod a-s on the above files" | tee -a "$report_path"
fi

# [CIS 8.3] Ensure symbolic links do not bypass restrictions
echo -e "\n[CIS 8.3] Ensure symbolic links do not bypass restrictions" | tee -a "$report_path"
symlinks=$(find "$dir" -type l)
if [[ -z "$symlinks" ]]; then
  echo "✅ No symbolic links present under Tomcat directory" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ Symbolic links detected that could bypass restrictions" | tee -a "$report_path"
  echo "$symlinks" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Review all symlinks and ensure they do not point to unrestricted locations" | tee -a "$report_path"
fi

# [CIS 9.1] Restrict access to the Tomcat administrative interfaces
echo -e "\n[CIS 9.1] Restrict access to administrative interfaces" | tee -a "$report_path"
admin_apps=("manager" "host-manager")
restricted=0
for app in "${admin_apps[@]}"; do
  context_file="$dir/webapps/$app/META-INF/context.xml"
  if [[ -f "$context_file" ]]; then
    restriction=$(grep -i 'RemoteAddrValve' "$context_file")
    echo "Evidence ($app): $(if [[ -n \"$restriction\" ]]; then echo \"$restriction\"; else echo \"No RemoteAddrValve present\"; fi)" | tee -a "$report_path"
    if [[ -n "$restriction" ]]; then
      echo "✅ $app interface is IP-restricted via RemoteAddrValve" | tee -a "$report_path"
      restricted=$((restricted + 1))
    else
      echo "❌ $app interface is not IP-restricted" | tee -a "$report_path"
      echo "Exploitability: High" | tee -a "$report_path"
      echo "Remediation: Add <Valve className=\"org.apache.catalina.valves.RemoteAddrValve\" ...> in $context_file" | tee -a "$report_path"
    fi
  else
    echo "⚠️ $app context.xml not found – likely not installed" | tee -a "$report_path"
  fi
done
[[ $restricted -eq 2 ]] && echo "Exploitability: Low" | tee -a "$report_path" || echo "Exploitability: High" | tee -a "$report_path"

# [CIS 9.2] Disable the Manager and Host-Manager applications if not used
echo -e "\n[CIS 9.2] Disable Manager and Host-Manager apps if not in use" | tee -a "$report_path"
apps_disabled=0
for app in "${admin_apps[@]}"; do
  if [[ ! -d "$dir/webapps/$app" ]]; then
    echo "✅ $app application is not deployed" | tee -a "$report_path"
    apps_disabled=$((apps_disabled + 1))
  else
    echo "❌ $app is deployed" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Remove $dir/webapps/$app if the application is not required" | tee -a "$report_path"
  fi
done
[[ $apps_disabled -eq 2 ]] && echo "Exploitability: Low" | tee -a "$report_path" || echo "Exploitability: Medium" | tee -a "$report_path"

# [CIS 10.1] Deploy applications as unprivileged user
echo -e "\n[CIS 10.1] Deploy applications as unprivileged user" | tee -a "$report_path"
tomcat_user=$(ps -eo user,comm | grep -E "catalina|tomcat" | awk '{print $1}' | sort -u)
echo "Evidence: Tomcat is running as user: $tomcat_user" | tee -a "$report_path"
if [[ "$tomcat_user" != "root" && -n "$tomcat_user" ]]; then
  echo "✅ Tomcat is running as non-root user" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ Tomcat is running as root" | tee -a "$report_path"
  echo "Exploitability: High" | tee -a "$report_path"
  echo "Remediation: Configure the service to run as a dedicated non-root user such as 'tomcat'" | tee -a "$report_path"
fi

# [CIS 10.2] Use secure session cookies
echo -e "\n[CIS 10.2] Use secure session cookies" | tee -a "$report_path"
context_secure_cookie=$(grep -i 'useHttpOnly' "$dir/conf/context.xml")
echo "Evidence: $context_secure_cookie" | tee -a "$report_path"
if echo "$context_secure_cookie" | grep -iq 'useHttpOnly="true"'; then
  echo "✅ Secure cookie flags are enabled" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ Secure cookie flag not set to true" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Add useHttpOnly=\"true\" and secure=\"true\" to <Context> in context.xml" | tee -a "$report_path"
fi

# [CIS 10.3] Ensure web application directory is not browsable
echo -e "\n[CIS 10.3] Ensure web application directory is not browsable" | tee -a "$report_path"
if grep -q 'listings="false"' "$dir/conf/web.xml"; then
  echo "✅ Directory listings disabled in web.xml" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
else
  echo "❌ Directory listings may be enabled (listings=\"false\" not found)" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Set listings=\"false\" in the default servlet of web.xml" | tee -a "$report_path"
fi

# [CIS 10.4] Remove default web.xml
echo -e "\n[CIS 10.4] Remove default web.xml" | tee -a "$report_path"
if [[ -f "$dir/conf/web.xml" ]]; then
  echo "❌ web.xml exists at $dir/conf/web.xml" | tee -a "$report_path"
  echo "Exploitability: Medium" | tee -a "$report_path"
  echo "Remediation: Remove or replace web.xml with a hardened version as needed" | tee -a "$report_path"
else
  echo "✅ Default web.xml is not present" | tee -a "$report_path"
  echo "Exploitability: Low" | tee -a "$report_path"
fi

# [CIS 10.5 – 10.19] Review application-specific configurations
for control in {5..19}; do
  echo -e "\n[CIS 10.$control] Review application-specific configuration (manual)" | tee -a "$report_path"
  echo "Evidence: Application behavior and deployment configuration must be manually reviewed." | tee -a "$report_path"
  echo "❌ Manual review required" | tee -a "$report_path"
  echo "Exploitability: Variable based on application logic, access controls, and business requirements" | tee -a "$report_path"
  echo "Remediation: Harden each deployed web application individually per secure coding standards and business requirements." | tee -a "$report_path"
done

  # === Exit with result summary ===
  echo -e "REACH THE END"
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
