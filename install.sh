#!/bin/bash

set -e
set -o pipefail

# --- Configuration Variables ---
APP_DIR="/opt/moodle-blocker"
VENV_DIR="${APP_DIR}/venv"
PYTHON_SCRIPT_URL="https://raw.githubusercontent.com/justncodes/moodle-auto-ip-blocker/refs/heads/master/moodle_ip_blocker.py"
PHP_CLI_SCRIPT_URL="https://raw.githubusercontent.com/justncodes/moodle-auto-ip-blocker/refs/heads/master/block_ip.php"

PYTHON_SCRIPT_NAME="moodle_ip_blocker.py"
CONFIG_NAME="config.ini"
PHP_CLI_SCRIPT_NAME="block_ip.php"
STATE_FILE_NAME="moodle_blocker_state.dat"
LOG_FILE_NAME="moodle_ip_blocker.log"
CRON_LOG_NAME="cron.log"
FAIL2BAN_LOG_NAME="moodle_failed_logins.log"
FAIL2BAN_FILTER_NAME="moodle-auth-custom"
FAIL2BAN_JAIL_NAME="moodle-custom"
CRON_FILE_NAME="moodle-blocker"

DEFAULT_MOODLE_ROOT="/var/www/html/moodle"
DEFAULT_WEB_USER="www-data"
DEFAULT_PHP_EXEC_FALLBACK="/usr/bin/php"
MOODLE_CLI_REL_PATH="local/customscripts/cli"

MOODLE_ROOT=""
DB_HOST=""
DB_NAME=""
DB_USER=""
DB_PREFIX=""
WEB_USER=""
PHP_EXEC=""
FAIL2BAN_LOG_PATH="/var/log/${FAIL2BAN_LOG_NAME}"

# --- Helper Functions ---
print_info() { echo "INFO: $1"; }
print_warning() { echo "WARNING: $1"; }
print_error() { echo "ERROR: $1" >&2; }
check_root() { if [ "$(id -u)" -ne 0 ]; then print_error "This script must be run as root (e.g., using sudo)."; exit 1; fi }

# --- Main Setup Logic ---
check_root
print_info "Starting Moodle Auto IP Blocker Setup..."

# Step 1: Install Dependencies
print_info "Updating package lists..."
apt-get update -y
print_info "Installing dependencies (python3, python3-pip, python3-venv, fail2ban, cron, iptables)..."
apt-get install -y python3 python3-pip python3-venv fail2ban cron iptables

# Step 2: Create Application Directory and Virtual Environment
print_info "Creating application directory: ${APP_DIR}"
mkdir -p "${APP_DIR}"
cd "${APP_DIR}"
print_info "Creating Python virtual environment in ${VENV_DIR}..."
python3 -m venv "${VENV_DIR}"

# Step 3: Install Python Dependencies
print_info "Activating virtual environment..."
source "${VENV_DIR}/bin/activate"
print_info "Installing mysql-connector-python into the virtual environment..."
pip install mysql-connector-python
deactivate
print_info "Deactivated virtual environment."

# Step 4: Determine Moodle Directory Path
DEFAULT_CONFIG_PATH="${DEFAULT_MOODLE_ROOT}/config.php"
if [[ -f "$DEFAULT_CONFIG_PATH" ]]; then
    print_info "Found Moodle config at default location: ${DEFAULT_MOODLE_ROOT}"
    MOODLE_ROOT="$DEFAULT_MOODLE_ROOT"
else
    print_warning "Moodle config.php not found at default location (${DEFAULT_MOODLE_ROOT})."
    print_error "Cannot proceed without Moodle config.php found at ${DEFAULT_MOODLE_ROOT}."
    exit 1
fi
MOODLE_CONFIG_PATH="${MOODLE_ROOT}/config.php"

# Step 5: Determine PHP Executable Path
print_info "Attempting to find PHP CLI executable using 'which php'..."
PHP_EXEC=$(which php || echo "")
if [[ -z "$PHP_EXEC" ]]; then
    print_warning "Could not find 'php' in PATH. Using fallback: ${DEFAULT_PHP_EXEC_FALLBACK}"
    PHP_EXEC="$DEFAULT_PHP_EXEC_FALLBACK"
    if [[ ! -x "$PHP_EXEC" ]]; then print_error "Fallback PHP '$PHP_EXEC' not executable."; exit 1; fi
else
    print_info "Using PHP executable found at: ${PHP_EXEC}"
fi
if [[ ! -x "$PHP_EXEC" ]]; then print_error "PHP executable path '$PHP_EXEC' is not executable."; exit 1; fi

# Step 6: Read Moodle config.php using PHP
print_info "Verifying PHP executable: $PHP_EXEC"; if [[ ! -x "$PHP_EXEC" ]]; then print_error "...failed."; exit 1; fi
print_info "Verifying Moodle config readability: $MOODLE_CONFIG_PATH"; if [[ ! -r "$MOODLE_CONFIG_PATH" ]]; then print_error "...failed."; exit 1; fi
PHP_TEMP_SCRIPT=$(mktemp --suffix=.php); trap 'echo "INFO: Cleaning up temp PHP script ${PHP_TEMP_SCRIPT}..."; rm -f "$PHP_TEMP_SCRIPT"' EXIT INT TERM
print_info "Reading Moodle config (excluding password)..."
cat << EOF > "$PHP_TEMP_SCRIPT"
<?php
error_reporting(E_ALL); ini_set('display_errors', 'stderr');
define('CLI_SCRIPT', true);
\$configfile = '$MOODLE_CONFIG_PATH';
@require_once(\$configfile);
if (!isset(\$CFG) || !is_object(\$CFG)) { fwrite(STDERR, "ERROR: Failed to load Moodle config.\n"); exit(1); }
if (!isset(\$CFG->dbhost, \$CFG->dbname, \$CFG->dbuser, \$CFG->prefix)) { fwrite(STDERR, "ERROR: Missing DB config values.\n"); exit(1); }
echo 'dbhost=' . \$CFG->dbhost . "\n"; echo 'dbname=' . \$CFG->dbname . "\n"; echo 'dbuser=' . \$CFG->dbuser . "\n"; echo 'prefix=' . \$CFG->prefix . "\n"; exit(0);
EOF
chmod 644 "$PHP_TEMP_SCRIPT"
print_info "Executing PHP script to get config..."
set +e; COMBINED_OUTPUT=$($PHP_EXEC -d display_errors=stderr -d error_reporting=E_ALL "$PHP_TEMP_SCRIPT" 2>&1); PHP_EXIT_CODE=$?; set -e
print_info "PHP execution finished. Exit Code: ${PHP_EXIT_CODE}"
if [[ $PHP_EXIT_CODE -ne 0 ]]; then print_error "PHP script FAILED. Output:"; print_error "$COMBINED_OUTPUT" >&2; exit 1; fi
rm -f "$PHP_TEMP_SCRIPT"; trap - EXIT INT TERM
CONFIG_OUTPUT=$(echo "$COMBINED_OUTPUT" | grep '=')
if [[ -z "$CONFIG_OUTPUT" ]]; then print_error "PHP script succeeded but no output."; print_error "Output was:"; print_error "$COMBINED_OUTPUT" >&2; exit 1; fi
while IFS='=' read -r key value; do case "$key" in dbhost) DB_HOST="$value" ;; dbname) DB_NAME="$value" ;; dbuser) DB_USER="$value" ;; prefix) DB_PREFIX="$value" ;; esac; done <<< "$CONFIG_OUTPUT"
if [[ -z "$DB_HOST" || -z "$DB_NAME" || -z "$DB_USER" || -z "$DB_PREFIX" ]]; then print_error "Could not extract DB variables."; exit 1; fi
print_info "Successfully extracted Moodle DB config (excluding password)."

# Step 7: Determine Web Server User
print_info "Determining web server user..."
DETECTED_WEB_USER=""
if ps aux | grep -E 'apache2|httpd' | grep -v grep > /dev/null && id -u "www-data" > /dev/null 2>&1; then DETECTED_WEB_USER="www-data"; print_info "Detected Apache/www-data.";
elif ps aux | grep 'nginx' | grep -v grep > /dev/null && id -u "www-data" > /dev/null 2>&1; then DETECTED_WEB_USER="www-data"; print_info "Detected Nginx/www-data.";
elif id -u "daemon" > /dev/null 2>&1; then DETECTED_WEB_USER="daemon"; print_info "Detected daemon user.";
fi
if [[ -z "$DETECTED_WEB_USER" ]]; then WEB_USER="${DEFAULT_WEB_USER}"; print_warning "Could not detect web user. Using default: '${WEB_USER}'.";
else WEB_USER="$DETECTED_WEB_USER"; print_info "Using detected user: ${WEB_USER}";
fi
print_info "Verifying user '${WEB_USER}' exists..."
if ! id -u "$WEB_USER" > /dev/null 2>&1; then print_error "FATAL: User '${WEB_USER}' not found!"; exit 1;
else print_info "User '${WEB_USER}' confirmed.";
fi

# Step 8: Download Scripts
print_info "Downloading Python script..."
cd "${APP_DIR}"
curl -fsSL "${PYTHON_SCRIPT_URL}" -o "${PYTHON_SCRIPT_NAME}"
chmod +x "${PYTHON_SCRIPT_NAME}"
print_info "Downloading PHP CLI script..."
curl -fsSL "${PHP_CLI_SCRIPT_URL}" -o "${PHP_CLI_SCRIPT_NAME}"

# Step 9: Generate config.ini
print_info "Checking config file: ${APP_DIR}/${CONFIG_NAME}"
if [[ ! -f "${APP_DIR}/${CONFIG_NAME}" ]]; then
    print_info "Generating configuration file: ${APP_DIR}/${CONFIG_NAME}"
    cat << EOF > "${APP_DIR}/${CONFIG_NAME}"
[database]
# These parameters are retrieved from Moodle config.php automatically
host = ${DB_HOST}
user = ${DB_USER}
name = ${DB_NAME}

# Adjust if using a different prefix
table_prefix = ${DB_PREFIX}

[rules]
# Number of failures from one IP since last check to trigger block
failure_threshold = 10

[moodle]
# Adjust if using a different Moodle installation path
wwwroot = ${MOODLE_ROOT}

# Path to PHP CLI executable
php_executable = ${PHP_EXEC}

# User the web server runs as (e.g., www-data, apache, nginx) - Needed for sudo
web_server_user = ${WEB_USER}

# Relative path within Moodle dir to the CLI script
cli_script_path = ${MOODLE_CLI_REL_PATH}/${PHP_CLI_SCRIPT_NAME}

# Enable email notifications for Moodle blocks (requires address below)
enable_email_notification = false

# Email address of an existing Moodle user to send notifications to (must be set if above is true)
notification_email_address =

[fail2ban]
# Path Fail2ban will monitor (if enabled below)
log_path = ${FAIL2BAN_LOG_PATH}

[actions]
# Set to true to block IPs using Moodle's internal IP Blocker (visible in UI)
enable_moodle_ip_blocking = true

# Set to true to block IPs using Fail2ban and firewall rules (e.g., iptables)
# Default is false as Moodle IP blocking is generally preferred.
enable_fail2ban_blocking = false
EOF
    chmod 600 "${CONFIG_NAME}"
    print_info "Generated ${CONFIG_NAME}."
else
    print_warning "Config file ${APP_DIR}/${CONFIG_NAME} exists. Skipping generation."
    print_warning "Verify settings manually, especially [actions] and [moodle] email options."
fi

# Step 10: Place Moodle CLI Script
MOODLE_CLI_TARGET_DIR="${MOODLE_ROOT}/${MOODLE_CLI_REL_PATH}"
MOODLE_CLI_FULL_PATH="${MOODLE_CLI_TARGET_DIR}/${PHP_CLI_SCRIPT_NAME}"
print_info "Checking Moodle CLI script: ${MOODLE_CLI_FULL_PATH}"
if [[ ! -f "$MOODLE_CLI_FULL_PATH" ]]; then
    print_info "Creating Moodle CLI script directory: ${MOODLE_CLI_TARGET_DIR}"
    mkdir -p "${MOODLE_CLI_TARGET_DIR}"
    print_info "Moving PHP script to ${MOODLE_CLI_FULL_PATH}"
    mv "${PHP_CLI_SCRIPT_NAME}" "${MOODLE_CLI_FULL_PATH}"
    chown root:"${WEB_USER}" "${MOODLE_CLI_FULL_PATH}"
    chmod 640 "${MOODLE_CLI_FULL_PATH}"
    print_info "Set ownership of Moodle CLI script."
else
    print_warning "Moodle CLI script ${MOODLE_CLI_FULL_PATH} exists. Skipping placement."
    if [[ -f "${APP_DIR}/${PHP_CLI_SCRIPT_NAME}" ]]; then rm -f "${APP_DIR}/${PHP_CLI_SCRIPT_NAME}"; fi
fi

# Step 11: Create Log Files and Set Permissions
print_info "Creating log/state files and setting permissions..."
touch "${APP_DIR}/${LOG_FILE_NAME}" \
      "${APP_DIR}/${CRON_LOG_NAME}" \
      "${FAIL2BAN_LOG_PATH}" \
      "${APP_DIR}/${STATE_FILE_NAME}" \
      "${APP_DIR}/${CONFIG_NAME}"

chown root:root "${APP_DIR}"; chmod 755 "${APP_DIR}"
chown root:root "${VENV_DIR}" -R
chown root:root "${APP_DIR}/${LOG_FILE_NAME}" "${APP_DIR}/${CRON_LOG_NAME}" "${APP_DIR}/${STATE_FILE_NAME}" "${APP_DIR}/${CONFIG_NAME}"
chmod 600 "${APP_DIR}/${CONFIG_NAME}"
chmod 644 "${APP_DIR}/${LOG_FILE_NAME}" "${APP_DIR}/${CRON_LOG_NAME}" "${APP_DIR}/${STATE_FILE_NAME}"
chown root:adm "${FAIL2BAN_LOG_PATH}" || { print_warning "Failed setting group 'adm' for ${FAIL2BAN_LOG_PATH}, using root:root. Check file access for fail2ban."; chown root:root "${FAIL2BAN_LOG_PATH}"; }
chmod 640 "${FAIL2BAN_LOG_PATH}"
print_info "Permissions set."

# Step 12: Configure Fail2ban
FAIL2BAN_FILTER_PATH="/etc/fail2ban/filter.d/${FAIL2BAN_FILTER_NAME}.conf"
FAIL2BAN_JAIL_PATH="/etc/fail2ban/jail.d/${FAIL2BAN_JAIL_NAME}.conf"
print_info "Checking Fail2ban filter: ${FAIL2BAN_FILTER_PATH}"
if [[ ! -f "$FAIL2BAN_FILTER_PATH" ]]; then
    print_info "Configuring Fail2ban filter...";
    cat << EOF > "${FAIL2BAN_FILTER_PATH}"
[Definition]
failregex = ^\s*.*MoodleLoginFail \[IP: <HOST>\]
ignoreregex =
EOF
else print_warning "Fail2ban filter ${FAIL2BAN_FILTER_PATH} exists."; fi

print_info "Checking Fail2ban jail: ${FAIL2BAN_JAIL_PATH}"
if [[ ! -f "$FAIL2BAN_JAIL_PATH" ]]; then
    print_info "Configuring Fail2ban jail...";
    cat << EOF > "${FAIL2BAN_JAIL_PATH}"
[${FAIL2BAN_JAIL_NAME}]
# Enabled setting here is for Fail2ban itself. Actual blocking depends on
# enable_fail2ban_blocking=true in /opt/moodle-blocker/config.ini which controls
# whether IPs are written to the logpath below.
enabled = true
port = http,https
filter = ${FAIL2BAN_FILTER_NAME}
logpath = ${FAIL2BAN_LOG_PATH}
maxretry = 1
findtime = 300
bantime = 3600
action = iptables-multiport[name=MoodleAuthCustom, port="http,https"]
EOF
else print_warning "Fail2ban jail ${FAIL2BAN_JAIL_PATH} exists."; fi

print_info "Reloading Fail2ban configuration..."
if ! command -v iptables &> /dev/null; then print_warning "iptables command not found."; fi
if systemctl is-active --quiet fail2ban; then systemctl reload fail2ban; else systemctl enable fail2ban; systemctl restart fail2ban; fi

# Step 13: Setup Cron Job
CRON_FILE_PATH="/etc/cron.d/${CRON_FILE_NAME}"
PYTHON_EXEC_VENV="${VENV_DIR}/bin/python3"
print_info "Setting up cron job: ${CRON_FILE_PATH}"
cat << EOF > "${CRON_FILE_PATH}"
# Run Moodle IP Blocker script every minute using virtual environment
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* * * * * root ${PYTHON_EXEC_VENV} ${APP_DIR}/${PYTHON_SCRIPT_NAME} >> ${APP_DIR}/${CRON_LOG_NAME} 2>&1
EOF
chmod 0644 "${CRON_FILE_PATH}"
systemctl enable cron; systemctl restart cron

# --- Final Instructions ---
echo ""
print_info "---------------------------------------------------------------------"
print_info " Moodle Auto IP Blocker Setup Complete!"
print_info "---------------------------------------------------------------------"
echo ""
print_info "Configuration Summary:"
echo "  - App Directory:      ${APP_DIR}"
echo "  - Moodle Directory:   ${MOODLE_ROOT}"
echo "  - Web User Used:      ${WEB_USER}"
echo "  - PHP Path Used:      ${PHP_EXEC}"
echo "  - Config File:        ${APP_DIR}/${CONFIG_NAME}"
echo "  - Python Script:      ${APP_DIR}/${PYTHON_SCRIPT_NAME}"
echo "  - Moodle CLI Script:  ${MOODLE_CLI_FULL_PATH}"
echo "  - Cron Job:           ${CRON_FILE_PATH}"
echo ""
print_warning "!!!!!!!!!!!!!!!!!!!! IMPORTANT VERIFICATION !!!!!!!!!!!!!!!!!!!!"
echo ""
print_warning "Verify settings in ${APP_DIR}/${CONFIG_NAME}, especially:"
print_warning "  - php_executable = ${PHP_EXEC}"
print_warning "  - web_server_user = ${WEB_USER}"
print_warning "If Web User is wrong, also run: 'sudo chown root:CORRECT_USER ${MOODLE_CLI_FULL_PATH}'"
echo ""
print_warning "!!!!!!!!!!!!!!!!!!!! BLOCKING & NOTIFICATION CONFIGURATION !!!!!!!!!!!!!!!!"
echo ""
print_warning "Review ${APP_DIR}/${CONFIG_NAME} to configure:"
echo "  - [actions] enable_moodle_ip_blocking = true    (Default: Moodle internal blocking ENABLED)"
echo "  - [actions] enable_fail2ban_blocking = false  (Default: Fail2ban firewall blocking DISABLED)"
echo "  - [moodle] enable_email_notification = false  (Default: Email DISABLED)"
echo "  - [moodle] notification_email_address =      (Default: No recipient)"
print_warning "To enable Fail2ban, set enable_fail2ban_blocking=true and ensure iptables works."
print_warning "To enable email, set enable_email_notification=true, provide a valid Moodle user's email"
print_warning "in notification_email_address, and ensure Moodle mail is configured."
echo ""
print_info "CHECK LOGS:"
echo "  - Script Log:      ${APP_DIR}/${LOG_FILE_NAME}"
echo "  - Cron Output Log: ${APP_DIR}/${CRON_LOG_NAME} (Should be empty unless script crashes)"
echo "  - Fail2ban Log:    /var/log/fail2ban.log (General Fail2ban activity)"
echo "  - Fail2ban Target: ${FAIL2BAN_LOG_PATH} (Only logs IPs if enable_fail2ban_blocking=true)"
echo ""
print_info "Cron job is now active and runs every minute."
print_info "---------------------------------------------------------------------"

exit 0