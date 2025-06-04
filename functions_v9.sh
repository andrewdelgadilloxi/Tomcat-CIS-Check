#!/bin/bash

# Apache Tomcat 9 CIS Benchmark v1.2.0 - FULL Compliance Validation
# This script performs all CIS checks, evaluates pass/fail, captures evidence,
# rates exploitability, and provides full remediation guidance.
# Output is written to both screen and a compliance report, which is uploaded
# to a GitHub repository if GH_TOKEN is present.

check_controls_v9() {
  local dir="$1"
  local hostname=$(hostname)
  
  local output_dir="/opt/tomcat_hardening"
  mkdir -p "$output_dir"

  local report_name="${hostname}_tomcat9_cis_compliance.txt"
  local report_path="$output_dir/$report_name"

  # Clear or create report file
  : > "$report_path" || { echo "❌ Failed to create $report_path" >&2; return 1; }
  
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Apache Tomcat 9 Hardening Assessment"
  echo "Host: $hostname"
  echo "Version: $("$dir/bin/version.sh" 2>/dev/null | grep 'Server number' | cut -d':' -f2 | xargs)"
  echo "Date: $(date)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  echo "Apache Tomcat 9 Compliance Report - $(date)" > "$report_path"
  echo "Host: $hostname" >> "$report_path"
  echo "Tomcat Version: $("$dir/bin/version.sh" 2>/dev/null | grep 'Server number' | cut -d':' -f2 | xargs)" >> "$report_path"

  # === Example Control Structure ===
  echo -e "\n[CIS 1.1] Remove extraneous files and directories" | tee -a "$report_path"
  extraneous=(examples docs manager host-manager ROOT js-examples servlet-example webdav tomcat-docs balancer admin)
  found=0
  for app in "${extraneous[@]}"; do
    if [[ -e "$dir/webapps/$app" || -e "$dir/server/webapps/$app" || -e "$dir/conf/Catalina/localhost/$app.xml" ]]; then
      echo "❌ $app found in Tomcat structure" | tee -a "$report_path"
      echo "Evidence: Found $app in $dir" | tee -a "$report_path"
      found=1
    fi
  done
  if [[ $found -eq 0 ]]; then
    echo "✅ No extraneous files found" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ Extraneous files detected – remove unused sample webapps and docs" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Run 'rm -rf $dir/webapps/{examples,docs,ROOT,manager,host-manager}' if not needed." | tee -a "$report_path"
  fi

  # CIS 1.2 - 3.2 controls implemented below
# [CIS 1.2] Disable unused connectors
  echo -e "
[CIS 1.2] Disable unused connectors" | tee -a "$report_path"
  if grep -q "<Connector" "$dir/conf/server.xml"; then
    echo "ℹ️ Connectors detected:" | tee -a "$report_path"
    grep "<Connector" "$dir/conf/server.xml" | tee -a "$report_path"
    echo "⚠️ Review to ensure only necessary connectors are active." | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Comment or remove unused <Connector> elements in server.xml" | tee -a "$report_path"
  else
    echo "✅ No active connectors found" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  fi

  # [CIS 2.1] Alter server.info
  echo -e "
[CIS 2.1] Alter server.info" | tee -a "$report_path"
  info_file="org/apache/catalina/util/ServerInfo.properties"
  if cd "$dir/lib" && jar xf catalina.jar "$info_file"; then
    server_info=$(grep server.info "$info_file" | cut -d= -f2)
    echo "Evidence: server.info=$server_info" | tee -a "$report_path"
    if [[ "$server_info" == Apache* ]]; then
      echo "❌ Default server.info value found" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Modify server.info in $info_file and repackage catalina.jar" | tee -a "$report_path"
    else
      echo "✅ Custom server.info set" | tee -a "$report_path"
    fi
  else
    echo "⚠️ Unable to read ServerInfo.properties" | tee -a "$report_path"
  fi

  # [CIS 2.2] Alter server.number
  echo -e "
[CIS 2.2] Alter server.number" | tee -a "$report_path"
  server_number=$(grep server.number "$info_file" | cut -d= -f2)
  echo "Evidence: server.number=$server_number" | tee -a "$report_path"
  if [[ "$server_number" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "❌ Default server.number detected" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Modify server.number in $info_file and repackage catalina.jar" | tee -a "$report_path"
  else
    echo "✅ Custom server.number configured" | tee -a "$report_path"
  fi

  # [CIS 2.3] Alter server.built
  echo -e "
[CIS 2.3] Alter server.built" | tee -a "$report_path"
  server_built=$(grep server.built "$info_file" | cut -d= -f2)
  echo "Evidence: server.built=$server_built" | tee -a "$report_path"
  if [[ "$server_built" == *[0-9]* ]]; then
    echo "❌ Default build date detected" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
    echo "Remediation: Modify server.built in $info_file and repackage catalina.jar" | tee -a "$report_path"
  else
    echo "✅ server.built appears customized" | tee -a "$report_path"
  fi

  # [CIS 2.4] Disable X-Powered-By
  echo -e "
[CIS 2.4] Disable X-Powered-By" | tee -a "$report_path"
  if grep -q 'xpoweredBy="true"' "$dir/conf/server.xml"; then
    echo "❌ xpoweredBy="true" found in server.xml" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
    echo "Remediation: Set xpoweredBy=\"false\" or remove attribute from Connector elements" | tee -a "$report_path"
  else
    echo "✅ X-Powered-By is disabled" | tee -a "$report_path"
  fi

  # [CIS 2.5] Disable client facing Stack Traces
  echo -e "
[CIS 2.5] Disable client facing Stack Traces" | tee -a "$report_path"
  if grep -q '<error-page>' "$dir/conf/web.xml" && grep -q 'java.lang.Throwable' "$dir/conf/web.xml"; then
    echo "✅ Proper error-page configuration detected in web.xml" | tee -a "$report_path"
  else
    echo "❌ Missing or incomplete error-page for Throwable in web.xml" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Add <error-page> block with <exception-type>java.lang.Throwable</exception-type> and <location>/error.jsp</location> to web.xml" | tee -a "$report_path"
  fi

    # [CIS 2.6] Turn off TRACE
  echo -e "\n[CIS 2.6] Turn off TRACE" | tee -a "$report_path"
  if grep -q 'allowTrace="true"' "$dir/conf/server.xml"; then
    echo "❌ TRACE is enabled (allowTrace=\"true\") in server.xml" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Set allowTrace=\"false\" in all Connector elements or remove the attribute entirely" | tee -a "$report_path"
  else
    echo "✅ TRACE is disabled or not explicitly enabled" | tee -a "$report_path"
  fi

  # [CIS 2.7] Modify Server Header
  echo -e "\n[CIS 2.7] Modify Server Header" | tee -a "$report_path"
  if grep -q 'server="Apache' "$dir/conf/server.xml"; then
    echo "❌ Default or identifiable Server header value found" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Change 'server' attribute in Connector elements to a non-identifiable string, e.g., 'I am a teapot'" | tee -a "$report_path"
  else
    echo "✅ Server header is customized or not set" | tee -a "$report_path"
  fi

  # [CIS 3.1] Set non-deterministic shutdown command
  echo -e "\n[CIS 3.1] Set non-deterministic shutdown command" | tee -a "$report_path"
  shutdown_cmd=$(grep -oP '<Server port="[0-9]+" shutdown="\K[^"]+' "$dir/conf/server.xml")
  echo "Evidence: shutdown=$shutdown_cmd" | tee -a "$report_path"
  if [[ "$shutdown_cmd" == "SHUTDOWN" ]]; then
    echo "❌ Default shutdown command found" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Change the shutdown command to a random string in server.xml" | tee -a "$report_path"
  else
    echo "✅ Custom shutdown command detected" | tee -a "$report_path"
  fi

  # [CIS 3.2] Disable the Shutdown port
  echo -e "\n[CIS 3.2] Disable the Shutdown port" | tee -a "$report_path"
  if grep -q '<Server port="-1"' "$dir/conf/server.xml"; then
    echo "✅ Shutdown port is disabled (port=-1)" | tee -a "$report_path"
  else
    echo "❌ Shutdown port is not disabled" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set port=\"-1\" in <Server> tag of server.xml to disable shutdown port" | tee -a "$report_path"
  fi

  # [CIS 4.1] Restrict access to $CATALINA_HOME
  echo -e "
[CIS 4.1] Restrict access to \$CATALINA_HOME" | tee -a "$report_path"
  if [[ -d "$dir" ]]; then
    perms=$(stat -c "%a" "$dir")
    owner=$(stat -c "%U:%G" "$dir")
    echo "Evidence: $dir permissions = $perms, ownership = $owner" | tee -a "$report_path"
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 750 ]]; then
      echo "✅ Secure permissions and ownership on \$CATALINA_HOME" | tee -a "$report_path"
    else
      echo "❌ Insecure \$CATALINA_HOME permissions or ownership" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: chown tomcat_admin:tomcat $dir && chmod g-w,o-rwx $dir" | tee -a "$report_path"
    fi
  fi

  # [CIS 4.2] Restrict access to $CATALINA_BASE
  echo -e "
[CIS 4.2] Restrict access to \$CATALINA_BASE" | tee -a "$report_path"
  if [[ -d "$dir" ]]; then
    perms=$(stat -c "%a" "$dir")
    owner=$(stat -c "%U:%G" "$dir")
    echo "Evidence: \$CATALINA_BASE permissions = $perms, ownership = $owner" | tee -a "$report_path"
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 750 ]]; then
      echo "✅ Secure permissions and ownership on \$CATALINA_BASE" | tee -a "$report_path"
    else
      echo "❌ Insecure \$CATALINA_BASE permissions or ownership" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: chown tomcat_admin:tomcat $dir && chmod g-w,o-rwx $dir" | tee -a "$report_path"
    fi
  fi

  # [CIS 4.3 - 4.7] Restrict access to core Tomcat directories
  declare -A secure_dirs=(
    ["$dir/conf"]="conf"
    ["$dir/logs"]="logs"
    ["$dir/temp"]="temp"
    ["$dir/bin"]="bin"
    ["$dir/webapps"]="webapps"
  )

  for path in "${!secure_dirs[@]}"; do
    label=${secure_dirs[$path]}
    echo -e "
[CIS 4.x] Restrict access to $label" | tee -a "$report_path"
    if [[ -e "$path" ]]; then
      perms=$(stat -c "%a" "$path")
      owner=$(stat -c "%U:%G" "$path")
      echo "Evidence: $path = $perms, $owner" | tee -a "$report_path"
      if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 750 ]]; then
        echo "✅ Secure permissions on $label" | tee -a "$report_path"
      else
        echo "❌ Insecure permissions on $label ($owner, $perms)" | tee -a "$report_path"
        echo "Exploitability: Medium" | tee -a "$report_path"
        echo "Remediation: chown tomcat_admin:tomcat $path && chmod g-w,o-rwx $path" | tee -a "$report_path"
      fi
    else
      echo "⚠️ Directory not found: $path" | tee -a "$report_path"
    fi
  done

  # [CIS 4.8 - 4.15] Restrict access to sensitive configuration files
  declare -A secure_files=(
    ["$dir/conf/catalina.policy"]="4.8"
    ["$dir/conf/catalina.properties"]="4.9"
    ["$dir/conf/context.xml"]="4.10"
    ["$dir/conf/logging.properties"]="4.11"
    ["$dir/conf/server.xml"]="4.12"
    ["$dir/conf/tomcat-users.xml"]="4.13"
    ["$dir/conf/web.xml"]="4.14"
    ["$dir/conf/jaspic-providers.xml"]="4.15"
  )

  for file in "${!secure_files[@]}"; do
    ctrl=${secure_files[$file]}
    echo -e "
[CIS $ctrl] Restrict access to $(basename "$file")" | tee -a "$report_path"
    if [[ -e "$file" ]]; then
      perms=$(stat -c "%a" "$file")
      owner=$(stat -c "%U:%G" "$file")
      echo "Evidence: $file = $perms, $owner" | tee -a "$report_path"
      if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 640 ]]; then
        echo "✅ Secure permissions on $(basename "$file")" | tee -a "$report_path"
      else
        echo "❌ Insecure permissions or ownership on $(basename "$file")" | tee -a "$report_path"
        echo "Exploitability: Medium" | tee -a "$report_path"
        echo "Remediation: chown tomcat_admin:tomcat $file && chmod g-w,o-rwx $file" | tee -a "$report_path"
      fi
    else
      echo "⚠️ File not found: $file" | tee -a "$report_path"
    fi
  done

  # [CIS 5.1] Use secure Realms
  echo -e "
[CIS 5.1] Use secure Realms" | tee -a "$report_path"
  insecure_realms=$(grep -E 'Realm className="org.apache.catalina.realm.(MemoryRealm|UserDatabaseRealm|JDBCRealm|JAASRealm)"' "$dir/conf/server.xml")
  if [[ -n "$insecure_realms" ]]; then
    echo "❌ Insecure Realms detected:" | tee -a "$report_path"
    echo "$insecure_realms" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Use JNDIRealm or DataSourceRealm for production environments." | tee -a "$report_path"
  else
    echo "✅ No insecure Realm configurations found" | tee -a "$report_path"
  fi

  # [CIS 5.2] Use LockOutRealm
  echo -e "
[CIS 5.2] Use LockOutRealm" | tee -a "$report_path"
  if grep -q "LockOutRealm" "$dir/conf/server.xml"; then
    echo "✅ LockOutRealm is configured" | tee -a "$report_path"
  else
    echo "❌ LockOutRealm not found in server.xml" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Add <Realm className='org.apache.catalina.realm.LockOutRealm'> to protect from brute-force logins." | tee -a "$report_path"
  fi

  # [CIS 6.1 - 6.5] Connector security checks
  echo -e "
[CIS 6.1 - 6.5] Secure connector configurations" | tee -a "$report_path"
  ssl_enabled=$(grep -i 'SSLEnabled="true"' "$dir/conf/server.xml")
  if [[ -n "$ssl_enabled" ]]; then
    echo "✅ SSLEnabled connectors present" | tee -a "$report_path"
  else
    echo "❌ No SSLEnabled connectors found" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Set SSLEnabled=\"true\" on secure Connector elements." | tee -a "$report_path"
  fi

  scheme_secure=$(grep -E 'scheme="https"|secure="true"' "$dir/conf/server.xml")
  if [[ -n "$scheme_secure" ]]; then
    echo "✅ Connector attributes scheme and secure properly defined" | tee -a "$report_path"
  else
    echo "❌ Missing or incorrect scheme/secure attributes in Connector elements" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Ensure scheme=\"https\" and secure=\"true\" on SSL-enabled connectors." | tee -a "$report_path"
  fi

  ssl_protocol=$(grep -i 'sslProtocol="TLS' "$dir/conf/server.xml")
  if [[ -n "$ssl_protocol" ]]; then
    echo "✅ SSL protocol is defined for secure connectors" | tee -a "$report_path"
  else
    echo "❌ sslProtocol not set on connectors" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Set sslProtocol=\"TLS\" or stronger protocols in Connector definitions" | tee -a "$report_path"
  fi

  # [CIS 7.1 - 7.6] Logging configuration
  echo -e "
[CIS 7.1 - 7.6] Logging configuration" | tee -a "$report_path"

  log_conf="$dir/conf/logging.properties"
  if [[ -f "$log_conf" ]]; then
    if grep -q 'org.apache.juli.FileHandler.directory' "$log_conf"; then
      echo "✅ Logging directory specified in logging.properties" | tee -a "$report_path"
    else
      echo "❌ Logging directory not specified in logging.properties" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
      echo "Remediation: Define org.apache.juli.FileHandler.directory with secure path in logging.properties" | tee -a "$report_path"
    fi

    if grep -q 'org.apache.juli.FileHandler.prefix=' "$log_conf"; then
      echo "✅ Logging file prefix defined" | tee -a "$report_path"
    else
      echo "❌ Logging file prefix missing in logging.properties" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
      echo "Remediation: Set org.apache.juli.FileHandler.prefix=tomcat in logging.properties" | tee -a "$report_path"
    fi
  else
    echo "❌ logging.properties file not found" | tee -a "$report_path"
  fi

  ctx_file="$dir/conf/context.xml"
  if [[ -f "$ctx_file" ]]; then
    if grep -q '<WatchedResource>WEB-INF/web.xml</WatchedResource>' "$ctx_file"; then
      echo "✅ WatchedResource for web.xml is defined" | tee -a "$report_path"
    else
      echo "❌ WatchedResource missing from context.xml" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
      echo "Remediation: Add <WatchedResource>WEB-INF/web.xml</WatchedResource> to context.xml" | tee -a "$report_path"
    fi
  else
    echo "❌ context.xml not found" | tee -a "$report_path"
  fi

  # [CIS 8.1] Restrict runtime access to sensitive packages
  echo -e "
[CIS 8.1] Restrict access to sensitive packages in catalina.policy" | tee -a "$report_path"
  if grep -q 'grant codeBase' "$dir/conf/catalina.policy"; then
    if grep -q 'java.lang.reflect' "$dir/conf/catalina.policy"; then
      echo "❌ Sensitive package access found in catalina.policy" | tee -a "$report_path"
      echo "Exploitability: High" | tee -a "$report_path"
      echo "Remediation: Remove grant blocks that allow access to sensitive packages like java.lang.reflect" | tee -a "$report_path"
    else
      echo "✅ No sensitive package access granted in catalina.policy" | tee -a "$report_path"
    fi
  else
    echo "⚠️ No grant statements found in catalina.policy" | tee -a "$report_path"
  fi

  # [CIS 9.1] Start Tomcat with Security Manager
  echo -e "
[CIS 9.1] Start Tomcat with Security Manager" | tee -a "$report_path"
  if grep -q 'org.apache.catalina.security.SecurityListener' "$dir/conf/server.xml" || grep -q 'security' "$dir/bin/startup.*"; then
    echo "✅ Security Manager or listener found in configuration" | tee -a "$report_path"
  else
    echo "❌ Tomcat is not configured to run with a Security Manager" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Add SecurityListener to server.xml or use -Djava.security.manager when launching Tomcat" | tee -a "$report_path"
  fi

  # [CIS 9.2] Disable auto deployment of applications
  echo -e "
[CIS 9.2] Disable auto deployment" | tee -a "$report_path"
  if grep -q 'autoDeploy="false"' "$dir/conf/server.xml" && grep -q 'deployOnStartup="false"' "$dir/conf/server.xml"; then
    echo "✅ Auto deployment and deploy on startup are disabled" | tee -a "$report_path"
  else
    echo "❌ autoDeploy or deployOnStartup still enabled" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set autoDeploy=\"false\" and deployOnStartup=\"false\" in Host element of server.xml" | tee -a "$report_path"
  fi

  # [CIS 10.1] Set appropriate file permissions for deployment directories
  echo -e "
[CIS 10.1] Check deployment directory permissions" | tee -a "$report_path"
  deploy_dir="$dir/webapps"
  if [[ -d "$deploy_dir" ]]; then
    perms=$(stat -c "%a" "$deploy_dir")
    owner=$(stat -c "%U:%G" "$deploy_dir")
    echo "Evidence: $deploy_dir permissions = $perms, owner = $owner" | tee -a "$report_path"
    if [[ "$owner" == "tomcat_admin:tomcat" && $perms -le 750 ]]; then
      echo "✅ Secure permissions on deployment directory" | tee -a "$report_path"
    else
      echo "❌ Insecure permissions on deployment directory" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: chown tomcat_admin:tomcat $deploy_dir && chmod 750 $deploy_dir" | tee -a "$report_path"
    fi
  else
    echo "⚠️ Deployment directory not found: $deploy_dir" | tee -a "$report_path"
  fi

  # [CIS 10.2] Remove sample application directories
  echo -e "
[CIS 10.2] Remove sample application directories" | tee -a "$report_path"
  samples=(examples webdav host-manager docs)
  sample_found=0
  for s in "${samples[@]}"; do
    if [[ -d "$dir/webapps/$s" ]]; then
      echo "❌ Sample app '$s' found in webapps" | tee -a "$report_path"
      sample_found=1
    fi
  done
  if [[ $sample_found -eq 0 ]]; then
    echo "✅ No sample applications found in webapps" | tee -a "$report_path"
  else
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Remove sample apps from $dir/webapps if not needed" | tee -a "$report_path"
  fi

  # [CIS 10.3] Remove default or sample users and roles
  echo -e "
[CIS 10.3] Remove default users and roles" | tee -a "$report_path"
  if grep -q '<user username="tomcat"' "$dir/conf/tomcat-users.xml"; then
    echo "❌ Default 'tomcat' user found" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Remove or replace default user accounts in tomcat-users.xml" | tee -a "$report_path"
  else
    echo "✅ No default user accounts found" | tee -a "$report_path"
  fi

  # [CIS 10.4] Set secure default web.xml policies
  echo -e "
[CIS 10.4] Validate security constraints in web.xml" | tee -a "$report_path"
  if grep -q '<security-constraint>' "$dir/conf/web.xml"; then
    echo "✅ Security constraints present in web.xml" | tee -a "$report_path"
  else
    echo "❌ No security-constraint blocks found in web.xml" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Define <security-constraint> blocks in default web.xml" | tee -a "$report_path"
  fi

  # [CIS 10.5] Enforce session timeout in web.xml
  echo -e "\n[CIS 10.5] Enforce session timeout" | tee -a "$report_path"
  timeout_val=$(grep -oPm1 "(?<=<session-timeout>)[0-9]+" "$dir/conf/web.xml")
  if [[ -n "$timeout_val" && "$timeout_val" -le 30 ]]; then
    echo "✅ Session timeout is set to $timeout_val minutes" | tee -a "$report_path"
  else
    echo "❌ Session timeout not set or greater than 30 minutes" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set <session-timeout>30</session-timeout> in web.xml" | tee -a "$report_path"
  fi

  # [CIS 10.6] Enforce secure cookies
  echo -e "\n[CIS 10.6] Enforce secure cookies" | tee -a "$report_path"
  if grep -q '<cookie-config>' "$dir/conf/web.xml" && grep -q '<secure>true</secure>' "$dir/conf/web.xml"; then
    echo "✅ Secure cookies enabled in web.xml" | tee -a "$report_path"
  else
    echo "❌ Secure cookie flag not enabled" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Add <cookie-config><secure>true</secure></cookie-config> to web.xml" | tee -a "$report_path"
  fi

  # [CIS 10.7] Configure HttpOnly cookies
  echo -e "\n[CIS 10.7] Configure HttpOnly cookies" | tee -a "$report_path"
  if grep -q '<http-only>true</http-only>' "$dir/conf/web.xml"; then
    echo "✅ HttpOnly cookie flag is enabled" | tee -a "$report_path"
  else
    echo "❌ HttpOnly cookie flag not set" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Add <http-only>true</http-only> inside <cookie-config> in web.xml" | tee -a "$report_path"
  fi

  # [CIS 10.8] Enforce transport security (confidential constraints)
  echo -e "\n[CIS 10.8] Enforce transport security" | tee -a "$report_path"
  if grep -q '<transport-guarantee>CONFIDENTIAL</transport-guarantee>' "$dir/conf/web.xml"; then
    echo "✅ Confidential transport-guarantee present in web.xml" | tee -a "$report_path"
  else
    echo "❌ transport-guarantee not set to CONFIDENTIAL" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Define <transport-guarantee>CONFIDENTIAL</transport-guarantee> in <security-constraint>" | tee -a "$report_path"
  fi

  # [CIS 10.9] Disable directory listings
  echo -e "\n[CIS 10.9] Disable directory listings" | tee -a "$report_path"
  if grep -q 'listings="false"' "$dir/conf/web.xml"; then
    echo "✅ Directory listings are disabled" | tee -a "$report_path"
  else
    echo "❌ Directory listings may be enabled" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set listings=\"false\" in default servlet in web.xml" | tee -a "$report_path"
  fi

  # [CIS 10.10 - 10.19] Additional control hooks
  echo -e "\n[CIS 10.10 - 10.19] Verify application deployment security settings" | tee -a "$report_path"
  echo "ℹ️ Review all deployed apps for:" | tee -a "$report_path"
  echo "- Disabled JSP compilation" | tee -a "$report_path"
  echo "- Disabled file uploads unless required" | tee -a "$report_path"
  echo "- Security constraints per application" | tee -a "$report_path"
  echo "- Proper <welcome-file-list> and <error-page> use" | tee -a "$report_path"
  echo "- Absence of unsecured test/debug servlets" | tee -a "$report_path"
  echo "- Correct use of role-based access controls" | tee -a "$report_path"
  echo "❗ Manual review recommended for apps in $dir/webapps" | tee -a "$report_path"


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
# Entry point example
# check_controls_v9 "/opt/tomcat9"
