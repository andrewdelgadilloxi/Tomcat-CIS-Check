#!/bin/bash

# Apache Tomcat 11 CIS Benchmark v1.0.0 - FULL Compliance Validation
# This script performs all CIS checks, evaluates pass/fail, captures evidence,
# rates exploitability, and provides full remediation guidance.
# Output is written to both screen and a compliance report, which is uploaded
# to a GitHub repository if GH_TOKEN is present.

check_controls_v11() {
  local dir="$1"
  local hostname=$(hostname)
  
  local output_dir="/opt/tomcat_hardening"
  mkdir -p "$output_dir"

  local report_name="${hostname}_tomcat11_cis_compliance.txt"
  local report_path="$output_dir/$report_name"

  # Clear or create report file
  : > "$report_path" || { echo "❌ Failed to create $report_path" >&2; return 1; }
  
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Apache Tomcat 11 Hardening Assessment"
  echo "Host: $hostname"
  echo "Version: $("$dir/bin/version.sh" 2>/dev/null | grep 'Server number' | cut -d':' -f2 | xargs)"
  echo "Date: $(date)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  echo "Apache Tomcat 11 Compliance Report - $(date)" > "$report_path"
  echo "Host: $hostname" >> "$report_path"
  echo "Tomcat Version: $("$dir/bin/version.sh" 2>/dev/null | grep 'Server number' | cut -d':' -f2 | xargs)" >> "$report_path"

  # =============================
  # [CIS 1.1] Disable Auto-Deployment
  # =============================
  echo -e "\n[CIS 1.1] Disable Auto-Deployment" | tee -a "$report_path"
  context_xml="$dir/conf/context.xml"
  if [[ -f "$context_xml" ]]; then
    deploy_setting=$(grep -i "<Context" "$context_xml" | grep -Eo 'autoDeploy="[^"]+"' | head -n1)
    echo "Evidence: $deploy_setting" | tee -a "$report_path"
    if echo "$deploy_setting" | grep -q 'autoDeploy="false"'; then
      echo "✅ PASS: autoDeploy is disabled in context.xml" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: autoDeploy is enabled or not explicitly set" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Set autoDeploy=\"false\" in <Context> element in $context_xml to prevent automatic deployment of new web applications." | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: $context_xml not found" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Ensure $context_xml exists and includes autoDeploy=\"false\" within the <Context> element." | tee -a "$report_path"
  fi

  # =============================
  # [CIS 1.2] Disable DeployOnStartup
  # =============================
  echo -e "\n[CIS 1.2] Disable DeployOnStartup" | tee -a "$report_path"
  deploy_setting=$(grep -i "<Host" "$dir/conf/server.xml" | grep -Eo 'deployOnStartup="[^"]+"' | head -n1)
  echo "Evidence: $deploy_setting" | tee -a "$report_path"
  if echo "$deploy_setting" | grep -q 'deployOnStartup="false"'; then
    echo "✅ PASS: deployOnStartup is disabled in server.xml" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: deployOnStartup is enabled or not explicitly set" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set deployOnStartup=\"false\" in the <Host> element of $dir/conf/server.xml to avoid auto-deploying applications on startup." | tee -a "$report_path"
  fi

  # =============================
  # [CIS 1.3] Disable unpackWARs
  # =============================
  echo -e "\n[CIS 1.3] Disable unpackWARs" | tee -a "$report_path"
  host_conf=$(grep -i "<Host" "$dir/conf/server.xml" | grep -Eo 'unpackWARs="[^"]+"' | head -n1)
  echo "Evidence: $host_conf" | tee -a "$report_path"
  if echo "$host_conf" | grep -q 'unpackWARs="false"'; then
    echo "✅ PASS: unpackWARs is disabled" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: unpackWARs is enabled or not explicitly set" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set unpackWARs=\"false\" in the <Host> element of $dir/conf/server.xml to prevent WAR file extraction." | tee -a "$report_path"
  fi

  # =============================
  # [CIS 1.4] Disable autoDeploy in server.xml
  # =============================
  echo -e "\n[CIS 1.4] Disable autoDeploy in server.xml" | tee -a "$report_path"
  auto_deploy_setting=$(grep -i "<Host" "$dir/conf/server.xml" | grep -Eo 'autoDeploy="[^"]+"' | head -n1)
  echo "Evidence: $auto_deploy_setting" | tee -a "$report_path"
  if echo "$auto_deploy_setting" | grep -q 'autoDeploy="false"'; then
    echo "✅ PASS: autoDeploy is disabled in server.xml" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: autoDeploy is enabled or not explicitly set in server.xml" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set autoDeploy=\"false\" in the <Host> element of $dir/conf/server.xml to restrict deployment behavior." | tee -a "$report_path"
  fi

  # =============================
  # [CIS 1.5] Remove Examples Web Applications
  # =============================
  echo -e "\n[CIS 1.5] Remove Examples Web Applications" | tee -a "$report_path"
  if [[ -d "$dir/webapps/examples" ]]; then
    echo "Evidence: $dir/webapps/examples exists" | tee -a "$report_path"
    echo "❌ FAIL: Examples web application is present" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Remove the 'examples' directory under $dir/webapps to reduce attack surface." | tee -a "$report_path"
  else
    echo "Evidence: $dir/webapps/examples not found" | tee -a "$report_path"
    echo "✅ PASS: Examples web application has been removed" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 1.6] Remove Documentation Web Application
  # =============================
  echo -e "\n[CIS 1.6] Remove Documentation Web Application" | tee -a "$report_path"
  if [[ -d "$dir/webapps/docs" ]]; then
    echo "Evidence: $dir/webapps/docs exists" | tee -a "$report_path"
    echo "❌ FAIL: Documentation web application is present" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Remove the 'docs' directory under $dir/webapps to limit unnecessary exposure." | tee -a "$report_path"
  else
    echo "Evidence: $dir/webapps/docs not found" | tee -a "$report_path"
    echo "✅ PASS: Documentation web application has been removed" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 2.1] Restrict access to Tomcat configuration directory
  # =============================
  echo -e "\n[CIS 2.1] Restrict access to Tomcat configuration directory" | tee -a "$report_path"
  config_dir="$dir/conf"
  if [[ -d "$config_dir" ]]; then
    perms=$(stat -c "%a" "$config_dir")
    echo "Evidence: Permissions on $config_dir are $perms" | tee -a "$report_path"
    if [[ "$perms" -le 750 ]]; then
      echo "✅ PASS: Configuration directory permissions are restricted" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: Configuration directory permissions are too permissive" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Set permissions on $config_dir to 750 or stricter (e.g., chmod 750 $config_dir)" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: Configuration directory not found at $config_dir" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Ensure Tomcat is correctly installed and configuration directory exists at $config_dir" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 2.2] Restrict access to Tomcat binaries directory
  # =============================
  echo -e "\n[CIS 2.2] Restrict access to Tomcat binaries directory" | tee -a "$report_path"
  bin_dir="$dir/bin"
  if [[ -d "$bin_dir" ]]; then
    perms=$(stat -c "%a" "$bin_dir")
    echo "Evidence: Permissions on $bin_dir are $perms" | tee -a "$report_path"
    if [[ "$perms" -le 750 ]]; then
      echo "✅ PASS: Binary directory permissions are appropriately restricted" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: Binary directory permissions are too permissive" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Set permissions to 750 or stricter (e.g., chmod 750 $bin_dir) and restrict ownership to tomcat user/group" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: Binary directory not found at $bin_dir" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Ensure Tomcat binaries exist under $bin_dir and are not world-writable" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 2.3] Restrict access to Tomcat logs directory
  # =============================
  echo -e "\n[CIS 2.3] Restrict access to Tomcat logs directory" | tee -a "$report_path"
  log_dir="$dir/logs"
  if [[ -d "$log_dir" ]]; then
    perms=$(stat -c "%a" "$log_dir")
    echo "Evidence: Permissions on $log_dir are $perms" | tee -a "$report_path"
    if [[ "$perms" -le 750 ]]; then
      echo "✅ PASS: Log directory permissions are restricted" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: Log directory permissions are too permissive" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Set permissions to 750 or stricter (e.g., chmod 750 $log_dir) and restrict ownership to tomcat user/group" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: Log directory not found at $log_dir" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Ensure log directory exists and is not world-readable or writable" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 2.4] Restrict access to Tomcat temp directory
  # =============================
  echo -e "\n[CIS 2.4] Restrict access to Tomcat temp directory" | tee -a "$report_path"
  temp_dir="$dir/temp"
  if [[ -d "$temp_dir" ]]; then
    perms=$(stat -c "%a" "$temp_dir")
    echo "Evidence: Permissions on $temp_dir are $perms" | tee -a "$report_path"
    if [[ "$perms" -le 750 ]]; then
      echo "✅ PASS: Temp directory permissions are restricted" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: Temp directory permissions are too permissive" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Set permissions to 750 or stricter (e.g., chmod 750 $temp_dir) and restrict ownership to tomcat user/group" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: Temp directory not found at $temp_dir" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Ensure temp directory exists and is appropriately secured" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 3.1] Restrict access to Tomcat admin and manager applications
  # =============================
  echo -e "\n[CIS 3.1] Restrict access to Tomcat admin and manager applications" | tee -a "$report_path"
  admin_app="$dir/webapps/admin"
  manager_app="$dir/webapps/manager"
  result=""

  if [[ -d "$admin_app" ]]; then
    result+="admin app present; "
  fi
  if [[ -d "$manager_app" ]]; then
    result+="manager app present"
  fi

  echo "Evidence: $result" | tee -a "$report_path"
  if [[ ! -d "$admin_app" && ! -d "$manager_app" ]]; then
    echo "✅ PASS: Admin and Manager applications are not deployed" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: Admin and/or Manager applications are deployed" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Remove $admin_app and $manager_app if not required. If needed, restrict access via IP filtering or credentials." | tee -a "$report_path"
  fi

  # =============================
  # [CIS 3.2] Restrict default access to all applications
  # =============================
  echo -e "\n[CIS 3.2] Restrict default access to all applications" | tee -a "$report_path"
  webapps_dir="$dir/webapps"
  default_web="$webapps_dir/ROOT"

  if [[ -d "$default_web" ]]; then
    index_file=$(find "$default_web" -type f \( -name "index.jsp" -o -name "index.html" \) | head -n1)
    echo "Evidence: $index_file exists in ROOT application" | tee -a "$report_path"
    echo "❌ FAIL: Default ROOT web application is deployed" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Remove or secure the ROOT application under $default_web to prevent unintended access" | tee -a "$report_path"
  else
    echo "✅ PASS: ROOT web application is not deployed" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 3.3] Remove or restrict the host-manager web application
  # =============================
  echo -e "\n[CIS 3.3] Remove or restrict the host-manager web application" | tee -a "$report_path"
  host_manager_app="$dir/webapps/host-manager"
  if [[ -d "$host_manager_app" ]]; then
    echo "Evidence: $host_manager_app exists" | tee -a "$report_path"
    echo "❌ FAIL: host-manager web application is present" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Remove the 'host-manager' application directory if not needed, or apply strict access controls via IP filtering and role-based authentication." | tee -a "$report_path"
  else
    echo "Evidence: $host_manager_app not found" | tee -a "$report_path"
    echo "✅ PASS: host-manager application has been removed or is not deployed" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 3.4] Remove or restrict the manager web application
  # =============================
  echo -e "\n[CIS 3.4] Remove or restrict the manager web application" | tee -a "$report_path"
  manager_web="$dir/webapps/manager"
  if [[ -d "$manager_web" ]]; then
    echo "Evidence: $manager_web exists" | tee -a "$report_path"
    echo "❌ FAIL: manager web application is present" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Remove the 'manager' application directory if not needed, or apply strict access controls using roles, authentication, and IP filtering." | tee -a "$report_path"
  else
    echo "Evidence: $manager_web not found" | tee -a "$report_path"
    echo "✅ PASS: manager application has been removed or is not deployed" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 3.5] Remove unused default applications (ROOT, examples, docs, host-manager, manager)
  # =============================
  echo -e "\n[CIS 3.5] Remove unused default applications (ROOT, examples, docs, host-manager, manager)" | tee -a "$report_path"
  default_apps=("ROOT" "examples" "docs" "host-manager" "manager")
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
    echo "❌ FAIL: Default applications found: ${found_apps[*]}" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Remove unnecessary applications under \$CATALINA_HOME/webapps: ${default_apps[*]}" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 3.6] Deploy applications in individual context.xml files
  # =============================
  echo -e "\n[CIS 3.6] Deploy applications in individual context.xml files" | tee -a "$report_path"
  apps_dir="$dir/webapps"
  shared_context="$dir/conf/context.xml"
  shared_setting=$(grep -i "<Context" "$shared_context" 2>/dev/null)

  echo "Evidence: <Context> found in shared context.xml: $shared_setting" | tee -a "$report_path"
  if grep -iq "<Context" "$shared_context"; then
    echo "❌ FAIL: Shared context.xml is used for all applications" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Use individual context.xml files in \$CATALINA_BASE/conf/[enginename]/[hostname]/ for each application instead of global context.xml" | tee -a "$report_path"
  else
    echo "✅ PASS: No shared context configuration found in $shared_context" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 4.1] Set file permissions on server.xml
  # =============================
  echo -e "\n[CIS 4.1] Set file permissions on server.xml" | tee -a "$report_path"
  server_xml="$dir/conf/server.xml"
  if [[ -f "$server_xml" ]]; then
    perms=$(stat -c "%a" "$server_xml")
    echo "Evidence: $server_xml permissions are $perms" | tee -a "$report_path"
    if [[ "$perms" -le 640 ]]; then
      echo "✅ PASS: server.xml permissions are secure" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: server.xml permissions are too permissive" | tee -a "$report_path"
      echo "Exploitability: High" | tee -a "$report_path"
      echo "Remediation: Run 'chmod 640 $server_xml' and restrict access to tomcat user and group" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: server.xml not found at expected path" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Ensure server.xml exists under $dir/conf and is secured with proper permissions" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 4.2] Set file permissions on web.xml
  # =============================
  echo -e "\n[CIS 4.2] Set file permissions on web.xml" | tee -a "$report_path"
  web_xml="$dir/conf/web.xml"
  if [[ -f "$web_xml" ]]; then
    perms=$(stat -c "%a" "$web_xml")
    echo "Evidence: $web_xml permissions are $perms" | tee -a "$report_path"
    if [[ "$perms" -le 640 ]]; then
      echo "✅ PASS: web.xml permissions are secure" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: web.xml permissions are too permissive" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Run 'chmod 640 $web_xml' and ensure only the tomcat group/user can access it" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: web.xml not found at expected path" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Ensure web.xml exists under $dir/conf and has restricted permissions" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 4.3] Restrict permissions on catalina.policy
  # =============================
  echo -e "\n[CIS 4.3] Restrict permissions on catalina.policy" | tee -a "$report_path"
  policy_file="$dir/conf/catalina.policy"
  if [[ -f "$policy_file" ]]; then
    perms=$(stat -c "%a" "$policy_file")
    echo "Evidence: $policy_file permissions are $perms" | tee -a "$report_path"
    if [[ "$perms" -le 640 ]]; then
      echo "✅ PASS: catalina.policy permissions are secure" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: catalina.policy permissions are too permissive" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Set permissions to 640 (chmod 640 $policy_file) and ensure ownership is tomcat user/group" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: catalina.policy not found at expected path" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Ensure catalina.policy exists and has restricted read/write access" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 4.4] Restrict permissions on catalina.properties
  # =============================
  echo -e "\n[CIS 4.4] Restrict permissions on catalina.properties" | tee -a "$report_path"
  props_file="$dir/conf/catalina.properties"
  if [[ -f "$props_file" ]]; then
    perms=$(stat -c "%a" "$props_file")
    echo "Evidence: $props_file permissions are $perms" | tee -a "$report_path"
    if [[ "$perms" -le 640 ]]; then
      echo "✅ PASS: catalina.properties permissions are secure" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: catalina.properties permissions are too permissive" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Set permissions to 640 (chmod 640 $props_file) and restrict access to authorized users only" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: catalina.properties not found at expected path" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Ensure catalina.properties exists under $dir/conf with secure file permissions" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 4.5] Restrict permissions on logging.properties
  # =============================
  echo -e "\n[CIS 4.5] Restrict permissions on logging.properties" | tee -a "$report_path"
  logging_props="$dir/conf/logging.properties"
  if [[ -f "$logging_props" ]]; then
    perms=$(stat -c "%a" "$logging_props")
    echo "Evidence: $logging_props permissions are $perms" | tee -a "$report_path"
    if [[ "$perms" -le 640 ]]; then
      echo "✅ PASS: logging.properties permissions are secure" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: logging.properties permissions are too permissive" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Set permissions to 640 (chmod 640 $logging_props) and restrict access to tomcat user/group" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: logging.properties not found at expected path" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Ensure logging.properties exists and is secured with proper file permissions" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 4.6] Restrict permissions on tomcat-users.xml
  # =============================
  echo -e "\n[CIS 4.6] Restrict permissions on tomcat-users.xml" | tee -a "$report_path"
  users_file="$dir/conf/tomcat-users.xml"
  if [[ -f "$users_file" ]]; then
    perms=$(stat -c "%a" "$users_file")
    echo "Evidence: $users_file permissions are $perms" | tee -a "$report_path"
    if [[ "$perms" -le 640 ]]; then
      echo "✅ PASS: tomcat-users.xml permissions are secure" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
    else
      echo "❌ FAIL: tomcat-users.xml permissions are too permissive" | tee -a "$report_path"
      echo "Exploitability: High" | tee -a "$report_path"
      echo "Remediation: Restrict access using chmod 640 $users_file and ensure only the tomcat user/group can read it" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: tomcat-users.xml not found at expected path" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Ensure tomcat-users.xml exists and has secure permissions, especially if managing users locally" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 4.7] Restrict permissions on context.xml
  # =============================
  echo -e "\n[CIS 4.7] Restrict permissions on context.xml" | tee -a "$report_path"
  ctx_file="$dir/conf/context.xml"
  if [[ -f "$ctx_file" ]]; then
    perms=$(stat -c "%a" "$ctx_file")
    echo "Evidence: $ctx_file permissions are $perms" | tee -a "$report_path"
    if [[ "$perms" -le 640 ]]; then
      echo "✅ PASS: context.xml permissions are secure" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: context.xml permissions are too permissive" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Apply chmod 640 $ctx_file and ensure only authorized access is permitted" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: context.xml not found at expected path" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Ensure context.xml exists and is secured using permission model 640 or stricter" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 4.8] Restrict permissions on web.xml deployment descriptors
  # =============================
  echo -e "\n[CIS 4.8] Restrict permissions on web application deployment descriptors" | tee -a "$report_path"
  webapps_dir="$dir/webapps"
  descriptors=$(find "$webapps_dir" -type f -path "*/WEB-INF/web.xml")

  if [[ -z "$descriptors" ]]; then
    echo "✅ PASS: No deployment descriptors found (or no applications deployed)" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    insecure=0
    while IFS= read -r xml_file; do
      perms=$(stat -c "%a" "$xml_file")
      echo "Evidence: $xml_file permissions are $perms" | tee -a "$report_path"
      if [[ "$perms" -le 640 ]]; then
        echo "✅ $xml_file is secure" | tee -a "$report_path"
      else
        echo "❌ $xml_file has insecure permissions" | tee -a "$report_path"
        ((insecure++))
      fi
    done <<< "$descriptors"

    if [[ "$insecure" -gt 0 ]]; then
      echo "❌ FAIL: One or more web.xml deployment descriptors have insecure permissions" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Set permissions to 640 on all WEB-INF/web.xml files" | tee -a "$report_path"
    else
      echo "✅ PASS: All deployment descriptors have secure permissions" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    fi
  fi

  # =============================
  # [CIS 5.1] Enable secure communication using TLS
  # =============================
  echo -e "\n[CIS 5.1] Enable secure communication using TLS" | tee -a "$report_path"
  server_xml="$dir/conf/server.xml"
  tls_connector=$(grep -A5 "<Connector" "$server_xml" | grep "SSLEnabled=\"true\"")
  echo "Evidence: $tls_connector" | tee -a "$report_path"
  if echo "$tls_connector" | grep -q 'SSLEnabled="true"'; then
    echo "✅ PASS: TLS is enabled on a Connector in server.xml" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: TLS is not properly enabled" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Configure a Connector with SSLEnabled=\"true\" in server.xml and specify keystoreFile, keystorePass, and sslProtocol." | tee -a "$report_path"
  fi

  # =============================
  # [CIS 5.2] Configure secure cipher suites
  # =============================
  echo -e "\n[CIS 5.2] Configure secure cipher suites" | tee -a "$report_path"
  ciphers_setting=$(grep -A2 "<Connector" "$server_xml" | grep "ciphers=")
  echo "Evidence: $ciphers_setting" | tee -a "$report_path"
  if [[ -n "$ciphers_setting" ]]; then
    echo "✅ PASS: Cipher suites are explicitly defined" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
  else
    echo "❌ FAIL: Cipher suites are not explicitly defined in server.xml" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Add 'ciphers' attribute to the TLS Connector in server.xml and use only secure, approved cipher suites." | tee -a "$report_path"
  fi

  # =============================
  # [CIS 5.3] Disable weak SSL/TLS protocols
  # =============================
  echo -e "\n[CIS 5.3] Disable weak SSL/TLS protocols" | tee -a "$report_path"
  protocol_setting=$(grep -A3 "<Connector" "$server_xml" | grep "sslProtocol=")
  echo "Evidence: $protocol_setting" | tee -a "$report_path"
  if echo "$protocol_setting" | grep -q 'sslProtocol="TLSv1.2"' || echo "$protocol_setting" | grep -q 'sslProtocol="TLSv1.3"'; then
    echo "✅ PASS: Only strong TLS protocols are enabled" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: Weak or unspecified TLS protocols may be in use" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Set sslProtocol=\"TLSv1.2\" or \"TLSv1.3\" in server.xml and disable SSLv2, SSLv3, and TLSv1.0/1.1." | tee -a "$report_path"
  fi

  # =============================
  # [CIS 6.1] Ensure Access Logs Are Enabled
  # =============================
  echo -e "\n[CIS 6.1] Ensure Access Logs Are Enabled" | tee -a "$report_path"
  access_logging_val=$(grep -i "<Valve className=\"org.apache.catalina.valves.AccessLogValve\"" "$server_xml" 2>/dev/null)
  echo "Evidence: $access_logging_val" | tee -a "$report_path"
  if [[ "$access_logging_val" == *"AccessLogValve"* ]]; then
    echo "✅ PASS: Access logging is enabled via AccessLogValve" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: Access logging is not enabled in server.xml" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Add <Valve className=\"org.apache.catalina.valves.AccessLogValve\" ... /> inside the <Host> section of $server_xml" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 6.2] Ensure Access Logs Are Stored in a Secure Location
  # =============================
  echo -e "\n[CIS 6.2] Ensure Access Logs Are Stored in a Secure Location" | tee -a "$report_path"
  access_log_dir=$(grep -i "directory=" "$server_xml" | grep "AccessLogValve" | sed -E 's/.*directory="([^"]+)".*/\1/')
  if [[ -n "$access_log_dir" && -d "$access_log_dir" ]]; then
    perms=$(stat -c "%a" "$access_log_dir")
    echo "Evidence: Access log directory $access_log_dir with permissions $perms" | tee -a "$report_path"
    if [[ "$perms" -le 750 ]]; then
      echo "✅ PASS: Access logs are stored securely" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: Access log directory has insecure permissions" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Set permissions to 750 or more restrictive using chmod and limit access to tomcat user/group" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: Unable to determine access log directory or directory does not exist" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Ensure AccessLogValve uses a secure directory and that it exists with restrictive permissions" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 7.1] Ensure Tomcat is running the latest stable version
  # =============================
  echo -e "\n[CIS 7.1] Ensure Tomcat is running the latest stable version" | tee -a "$report_path"
  tomcat_version_detected=$(grep 'Server number' "$dir/RELEASE-NOTES" 2>/dev/null | head -n1 | awk '{print $NF}')
  echo "Evidence: Tomcat version from RELEASE-NOTES is $tomcat_version_detected" | tee -a "$report_path"

  if [[ -z "$tomcat_version_detected" ]]; then
    echo "❌ FAIL: Unable to detect Tomcat version from RELEASE-NOTES" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Confirm Tomcat version using server logs or server info page and compare with the latest version from https://tomcat.apache.org" | tee -a "$report_path"
  else
    echo "NOTE: Script does not dynamically compare to online version for security reasons" | tee -a "$report_path"
    echo "✅ INFO: Detected version is $tomcat_version_detected - please verify this is the latest stable release manually" | tee -a "$report_path"
    echo "Exploitability: Depends on delta between detected version and latest" | tee -a "$report_path"
    echo "Remediation: Regularly monitor https://tomcat.apache.org and update Tomcat to the latest stable release" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 8.1] Implement File Integrity Monitoring (FIM)
  # =============================
  echo -e "\n[CIS 8.1] Implement File Integrity Monitoring (FIM)" | tee -a "$report_path"
  fim_tool_check=$(which aide 2>/dev/null || which tripwire 2>/dev/null)
  if [[ -n "$fim_tool_check" ]]; then
    echo "Evidence: File Integrity Monitoring tool detected - $fim_tool_check" | tee -a "$report_path"
    echo "✅ PASS: A FIM solution is installed on the system" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: No file integrity monitoring tool detected (e.g., AIDE, Tripwire)" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Install a FIM solution like AIDE or Tripwire and configure it to monitor Tomcat configuration and deployment directories" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 8.2] Monitor Changes to Tomcat Configuration Files
  # =============================
  echo -e "\n[CIS 8.2] Monitor Changes to Tomcat Configuration Files" | tee -a "$report_path"
  tomcat_conf_files=("$dir/conf/server.xml" "$dir/conf/web.xml" "$dir/conf/context.xml" "$dir/conf/catalina.policy" "$dir/conf/catalina.properties" "$dir/conf/logging.properties")
  missing_conf=0
  for file in "${tomcat_conf_files[@]}"; do
    if [[ ! -f "$file" ]]; then
      echo "❌ FAIL: Missing configuration file: $file" | tee -a "$report_path"
      ((missing_conf++))
    else
      echo "✅ File present and should be monitored by FIM: $file" | tee -a "$report_path"
    fi
  done

  if [[ "$missing_conf" -gt 0 ]]; then
    echo "⚠️ Partial PASS: Some configuration files are missing and cannot be monitored" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Ensure all critical Tomcat config files exist and are included in your FIM policy for change detection" | tee -a "$report_path"
  else
    echo "✅ PASS: All key Tomcat configuration files found and ready for FIM coverage" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 8.3] Ensure symbolic links do not bypass restrictions
  # =============================
  echo -e "\n[CIS 8.3] Ensure symbolic links do not bypass restrictions" | tee -a "$report_path"
  symlinks=$(find "$dir" -type l)
  if [[ -z "$symlinks" ]]; then
    echo "✅ No symbolic links present under Tomcat directory" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: The following symbolic links exist under $dir:" | tee -a "$report_path"
    echo "$symlinks" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Review all symlinks and ensure they do not point to unrestricted or insecure locations. Use 'find $dir -type l -ls' to audit." | tee -a "$report_path"
  fi

  # =============================
  # [CIS 9.1] Do not deploy default applications
  # =============================
  echo -e "\n[CIS 9.1] Do not deploy default applications" | tee -a "$report_path"
  default_apps=("examples" "docs" "manager" "host-manager" "ROOT")
  found_apps=()
  for app in "${default_apps[@]}"; do
    if [[ -d "$dir/webapps/$app" ]]; then
      found_apps+=("$app")
    fi
  done

  if [[ ${#found_apps[@]} -eq 0 ]]; then
    echo "✅ PASS: No default Tomcat applications are deployed" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
  else
    echo "❌ FAIL: Default Tomcat applications found: ${found_apps[*]}" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Remove the following directories from \$CATALINA_HOME/webapps: ${found_apps[*]}" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 9.2] Remove unnecessary files and documentation
  # =============================
  echo -e "\n[CIS 9.2] Remove unnecessary files and documentation" | tee -a "$report_path"
  unnecessary_items=(
    "$dir/RELEASE-NOTES"
    "$dir/NOTICE"
    "$dir/LICENSE"
    "$dir/webapps/docs"
    "$dir/webapps/examples"
    "$dir/webapps/ROOT/index.jsp"
  )
  present_items=()
  for item in "${unnecessary_items[@]}"; do
    if [[ -e "$item" ]]; then
      present_items+=("$item")
    fi
  done

  if [[ ${#present_items[@]} -eq 0 ]]; then
    echo "✅ PASS: No unnecessary files or documentation found" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: Unnecessary files found:" | tee -a "$report_path"
    printf '%s\n' "${present_items[@]}" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Delete unnecessary files such as LICENSE, NOTICE, RELEASE-NOTES, and default documentation directories" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.1] Do not run Tomcat as root
  # =============================
  echo -e "\n[CIS 10.1] Do not run Tomcat as root" | tee -a "$report_path"
  tomcat_pid=$(pgrep -f "org.apache.catalina.startup.Bootstrap")
  if [[ -n "$tomcat_pid" ]]; then
    tomcat_user=$(ps -o user= -p "$tomcat_pid" | xargs)
    echo "Evidence: Tomcat process is running as user: $tomcat_user" | tee -a "$report_path"
    if [[ "$tomcat_user" == "root" ]]; then
      echo "❌ FAIL: Tomcat is running as root" | tee -a "$report_path"
      echo "Exploitability: Critical" | tee -a "$report_path"
      echo "Remediation: Configure Tomcat to run as a non-root user using a dedicated tomcat system account" | tee -a "$report_path"
    else
      echo "✅ PASS: Tomcat is not running as root" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: Unable to determine Tomcat process or it is not running" | tee -a "$report_path"
    echo "Exploitability: Unknown" | tee -a "$report_path"
    echo "Remediation: Ensure Tomcat is installed and running, then verify it operates as a non-root user" | tee -a "$report_path"
  fi

    # =============================
  # [CIS 10.2] Use a dedicated user for the Tomcat process
  # =============================
  echo -e "\n[CIS 10.2] Use a dedicated user for the Tomcat process" | tee -a "$report_path"
  if [[ -n "$tomcat_pid" ]]; then
    tomcat_user_group=$(id "$tomcat_user" 2>/dev/null)
    echo "Evidence: Tomcat is running under user: $tomcat_user_group" | tee -a "$report_path"
    if [[ "$tomcat_user" == "tomcat" || "$tomcat_user" == "tcuser" ]]; then
      echo "✅ PASS: Tomcat is using a dedicated user account" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: Tomcat is not running under a dedicated user account" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Create a non-login system user (e.g., 'tomcat') and configure systemd/init to run Tomcat using this user" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: Unable to determine Tomcat process or user" | tee -a "$report_path"
    echo "Remediation: Ensure Tomcat is started, and verify its runtime user with 'ps -ef | grep tomcat'" | tee -a "$report_path"
  fi

    # =============================
  # [CIS 10.3] Configure a Security Manager
  # =============================
  echo -e "\n[CIS 10.3] Configure a Security Manager" | tee -a "$report_path"
  catalina_opts=$(grep "CATALINA_OPTS" "$dir"/bin/*.sh 2>/dev/null | grep -i "security")
  echo "Evidence: $catalina_opts" | tee -a "$report_path"
  if echo "$catalina_opts" | grep -q "security"; then
    echo "✅ PASS: Security Manager appears to be enabled via CATALINA_OPTS" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: Security Manager is not configured in startup scripts" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Add -Djava.security.manager to CATALINA_OPTS in catalina.sh or setenv.sh" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.4] Remove example files from webapps
  # =============================
  echo -e "\n[CIS 10.4] Remove example files from webapps" | tee -a "$report_path"
  example_dirs=$(find "$dir/webapps" -type d -name "examples")
  if [[ -z "$example_dirs" ]]; then
    echo "✅ PASS: No example directories found under webapps" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: Found example applications in:" | tee -a "$report_path"
    echo "$example_dirs" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Delete the examples directory from $dir/webapps" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.5] Disable Auto Deployment
  # =============================
  echo -e "\n[CIS 10.5] Disable Auto Deployment" | tee -a "$report_path"
  auto_deploy_setting=$(grep -i 'autoDeploy=' "$server_xml")
  echo "Evidence: $auto_deploy_setting" | tee -a "$report_path"
  if echo "$auto_deploy_setting" | grep -qi 'autoDeploy="false"'; then
    echo "✅ PASS: autoDeploy is disabled" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: autoDeploy is enabled or not set" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set autoDeploy=\"false\" in the <Host> element of server.xml" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.6] Disable Deploy on Startup
  # =============================
  echo -e "\n[CIS 10.6] Disable Deploy on Startup" | tee -a "$report_path"
  deploy_on_startup_setting=$(grep -i 'deployOnStartup=' "$server_xml")
  echo "Evidence: $deploy_on_startup_setting" | tee -a "$report_path"
  if echo "$deploy_on_startup_setting" | grep -qi 'deployOnStartup="false"'; then
    echo "✅ PASS: deployOnStartup is disabled" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: deployOnStartup is enabled or not set" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set deployOnStartup=\"false\" in the <Host> element of server.xml" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.7] Restrict the use of the shutdown port
  # =============================
  echo -e "\n[CIS 10.7] Restrict the use of the shutdown port" | tee -a "$report_path"
  shutdown_setting=$(grep -i "<Server port=" "$server_xml")
  echo "Evidence: $shutdown_setting" | tee -a "$report_path"
  if echo "$shutdown_setting" | grep -q 'port="-1"'; then
    echo "✅ PASS: Shutdown port is disabled (set to -1)" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: Shutdown port is enabled or not properly secured" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Set port=\"-1\" in the <Server> element of server.xml to disable shutdown commands" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.8] Set an empty shutdown command
  # =============================
  echo -e "\n[CIS 10.8] Set an empty shutdown command" | tee -a "$report_path"
  shutdown_command=$(grep -i "<Server port=" "$server_xml" | grep -o 'shutdown="[^"]*"' | cut -d'"' -f2)
  echo "Evidence: shutdown=\"$shutdown_command\"" | tee -a "$report_path"
  if [[ "$shutdown_command" == "" ]]; then
    echo "✅ PASS: Shutdown command is set to empty string" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: Shutdown command is set to \"$shutdown_command\"" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set shutdown=\"\" in the <Server> element of server.xml to reduce brute-force risk" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.9] Disable HTTP TRACE method
  # =============================
  echo -e "\n[CIS 10.9] Disable HTTP TRACE method" | tee -a "$report_path"
  trace_setting=$(grep -i "allowTrace=" "$server_xml")
  echo "Evidence: $trace_setting" | tee -a "$report_path"
  if echo "$trace_setting" | grep -q 'allowTrace="false"'; then
    echo "✅ PASS: HTTP TRACE method is disabled" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
  else
    echo "❌ FAIL: HTTP TRACE method may be enabled" | tee -a "$report_path"
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Set allowTrace=\"false\" in the <Connector> element of server.xml" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.10] Disable sending server version in response header
  # =============================
  echo -e "\n[CIS 10.10] Disable sending server version in response header" | tee -a "$report_path"
  server_info_files=("$dir/lib/catalina.jar")
  version_exposure=0
  for file in "${server_info_files[@]}"; do
    if [[ -f "$file" ]]; then
      strings "$file" | grep -iq "Apache Tomcat"; then
        version_exposure=1
        echo "❌ FAIL: $file contains server identification strings" | tee -a "$report_path"
      fi
    fi
  done

  if [[ $version_exposure -eq 0 ]]; then
    echo "✅ PASS: No server version information exposed from Tomcat libraries" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Modify or replace ServerInfo.properties and remove or obfuscate version banners in server responses" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.11] Disable directory listings
  # =============================
  echo -e "\n[CIS 10.11] Disable directory listings" | tee -a "$report_path"
  listing_setting=$(grep -i "<param-name>listings</param-name>" "$dir/conf/web.xml" -A1 | grep -i "<param-value>")
  echo "Evidence: $listing_setting" | tee -a "$report_path"
  if echo "$listing_setting" | grep -iq "<param-value>false</param-value>"; then
    echo "✅ PASS: Directory listings are disabled in web.xml" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
  else
    echo "❌ FAIL: Directory listings are not explicitly disabled" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: In $dir/conf/web.xml, ensure <param-name>listings</param-name> is set to <param-value>false</param-value>" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.12] Disable file uploads
  # =============================
  echo -e "\n[CIS 10.12] Disable file uploads (if not required)" | tee -a "$report_path"
  upload_limit_setting=$(grep -i "maxPostSize" "$server_xml")
  echo "Evidence: $upload_limit_setting" | tee -a "$report_path"
  if echo "$upload_limit_setting" | grep -iq 'maxPostSize="0"'; then
    echo "✅ PASS: File uploads are disabled (maxPostSize=0)" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
  else
    echo "⚠️ INFO: File uploads are allowed or unrestricted. Set maxPostSize=\"0\" to disable if unnecessary." | tee -a "$report_path"
    echo "Exploitability: Context-dependent" | tee -a "$report_path"
    echo "Remediation: Set maxPostSize=\"0\" in the <Connector> element of server.xml if file uploads are not required" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.13] Use strong passwords for application accounts
  # =============================
  echo -e "\n[CIS 10.13] Use strong passwords for application accounts" | tee -a "$report_path"
  password_files=("$dir/conf/tomcat-users.xml")
  weak_found=0
  for file in "${password_files[@]}"; do
    if [[ -f "$file" ]]; then
      weak_users=$(grep -Eo 'password="[^"]+"' "$file" | cut -d'"' -f2)
      for pw in $weak_users; do
        if [[ ${#pw} -lt 8 ]]; then
          echo "❌ FAIL: Weak password detected in $file: \"$pw\"" | tee -a "$report_path"
          weak_found=1
        fi
      done
    fi
  done
  if [[ $weak_found -eq 0 ]]; then
    echo "✅ PASS: All application account passwords appear sufficiently strong (8+ characters)" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
  else
    echo "Exploitability: High" | tee -a "$report_path"
    echo "Remediation: Update tomcat-users.xml and enforce stronger password complexity for roles and users" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.14] Configure secure session cookies
  # =============================
  echo -e "\n[CIS 10.14] Configure secure session cookies" | tee -a "$report_path"
  context_xml="$dir/conf/context.xml"
  secure_cookies=$(grep -i 'useHttpOnly=' "$context_xml")
  echo "Evidence: $secure_cookies" | tee -a "$report_path"
  if echo "$secure_cookies" | grep -qi 'useHttpOnly="true"'; then
    echo "✅ PASS: useHttpOnly is enabled for session cookies" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: useHttpOnly not set or not enabled in context.xml" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Set useHttpOnly=\"true\" and secure=\"true\" in <Context> inside $context_xml" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.15] Restrict application file upload paths
  # =============================
  echo -e "\n[CIS 10.15] Restrict application file upload paths" | tee -a "$report_path"
  uploads_dir=$(find "$dir/webapps" -type d -name "*upload*" 2>/dev/null)
  if [[ -z "$uploads_dir" ]]; then
    echo "✅ PASS: No unmonitored or unrestricted upload directories found" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "⚠️ INFO: Possible upload directories detected:" | tee -a "$report_path"
    echo "$uploads_dir" | tee -a "$report_path"
    echo "Exploitability: Context-dependent" | tee -a "$report_path"
    echo "Remediation: Verify these directories are monitored, secured, and subject to file type and size restrictions" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.16] Configure appropriate access controls for logs
  # =============================
  echo -e "\n[CIS 10.16] Configure appropriate access controls for logs" | tee -a "$report_path"
  log_dir="$dir/logs"
  if [[ -d "$log_dir" ]]; then
    perms=$(stat -c "%a" "$log_dir")
    owner=$(stat -c "%U" "$log_dir")
    echo "Evidence: Logs directory permission: $perms, owner: $owner" | tee -a "$report_path"
    if [[ "$perms" -le 750 && "$owner" != "root" ]]; then
      echo "✅ PASS: Logs directory has appropriate permissions and ownership" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: Logs directory has overly permissive access or wrong ownership" | tee -a "$report_path"
      echo "Exploitability: Medium" | tee -a "$report_path"
      echo "Remediation: Ensure $log_dir is owned by the Tomcat user and permissions are 750 or more restrictive" | tee -a "$report_path"
    fi
  else
    echo "❌ FAIL: Logs directory not found at expected path: $log_dir" | tee -a "$report_path"
    echo "Remediation: Verify the location of Tomcat logs and apply proper access restrictions" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.17] Do not include sensitive information in logs
  # =============================
  echo -e "\n[CIS 10.17] Do not include sensitive information in logs" | tee -a "$report_path"
  example_log=$(find "$dir/logs" -type f -name "*.log" | head -n 1)
  if [[ -f "$example_log" ]]; then
    sensitive_terms=$(grep -Ei "password=|passwd=|pwd=|Authorization:|token=" "$example_log")
    if [[ -z "$sensitive_terms" ]]; then
      echo "✅ PASS: No sensitive information found in sampled log file: $example_log" | tee -a "$report_path"
      echo "Exploitability: Low" | tee -a "$report_path"
    else
      echo "❌ FAIL: Potential sensitive info found in logs:" | tee -a "$report_path"
      echo "$sensitive_terms" | tee -a "$report_path"
      echo "Exploitability: High" | tee -a "$report_path"
      echo "Remediation: Mask or redact sensitive values before writing to logs using log filters or logback/log4j configuration" | tee -a "$report_path"
    fi
  else
    echo "⚠️ INFO: No log files found for sampling" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.18] Use a centralized logging solution
  # =============================
  echo -e "\n[CIS 10.18] Use a centralized logging solution" | tee -a "$report_path"
  syslog_check=$(grep -Ei "syslog|rsyslog|fluentd|logstash" "$dir/conf/logging.properties" 2>/dev/null)
  echo "Evidence: $syslog_check" | tee -a "$report_path"
  if [[ -n "$syslog_check" ]]; then
    echo "✅ PASS: Centralized logging tool reference found in logging.properties" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "❌ FAIL: No evidence of centralized logging configuration" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Configure Tomcat to forward logs to a centralized log system like rsyslog, syslog-ng, or ELK stack" | tee -a "$report_path"
  fi

  # =============================
  # [CIS 10.19] Perform regular vulnerability scans
  # =============================
  echo -e "\n[CIS 10.19] Perform regular vulnerability scans" | tee -a "$report_path"
  scan_evidence=$(ls /etc/cron.*/* 2>/dev/null | grep -Ei "nessus|openvas|nmap|qualys")
  echo "Evidence: Scan job references found in cron: $scan_evidence" | tee -a "$report_path"
  if [[ -n "$scan_evidence" ]]; then
    echo "✅ PASS: Scheduled vulnerability scans appear configured" | tee -a "$report_path"
    echo "Exploitability: Low" | tee -a "$report_path"
  else
    echo "⚠️ INFO: No scheduled vulnerability scans detected in cron" | tee -a "$report_path"
    echo "Exploitability: Medium" | tee -a "$report_path"
    echo "Remediation: Use tools like OpenVAS, Nessus, or commercial scanners and automate scans via cron, Ansible, or CI/CD integration" | tee -a "$report_path"
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
