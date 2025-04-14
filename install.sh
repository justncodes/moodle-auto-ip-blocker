#!/bin/bash

# Stop script on any error
set -e
# Ensure commands in pipelines return non-zero status if they fail
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

# Default values, some will be overwritten
DEFAULT_MOODLE_ROOT="/var/www/html/moodle"
DEFAULT_WEB_USER="www-data"
DEFAULT_PHP_EXEC_FALLBACK="/usr/bin/php"
MOODLE_CLI_REL_PATH="local/customscripts/cli"

# Variables to be populated from config.php or user input
MOODLE_ROOT=""
DB_HOST=""
DB_NAME=""
DB_USER=""
DB_PASS=""
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

# 1. Install Dependencies (cron ADDED, awk removed)
print_info "Updating package lists..."
apt-get update -y
print_info "Installing dependencies (python3, python3-pip, python3-venv, fail2ban, cron)..."
apt-get install -y python3 python3-pip python3-venv fail2ban cron

# 2. Create Application Directory and Virtual Environment
print_info "Creating application directory: ${APP_DIR}"
mkdir -p "${APP_DIR}"
cd "${APP_DIR}"
print_info "Creating Python virtual environment in ${VENV_DIR}..."
python3 -m venv "${VENV_DIR}"

# 3. Install Python Dependencies into Virtual Environment
print_info "Installing mysql-connector-python into the virtual environment..."
source "${VENV_DIR}/bin/activate"
pip install mysql-connector-python

# 4. Determine Moodle Directory Path
DEFAULT_CONFIG_PATH="${DEFAULT_MOODLE_ROOT}/config.php"
if [[ -f "$DEFAULT_CONFIG_PATH" ]]; then print_info "Found Moodle config at default location: ${DEFAULT_MOODLE_ROOT}"; MOODLE_ROOT="$DEFAULT_MOODLE_ROOT"; else
    print_warning "Moodle config.php not found at default location (${DEFAULT_MOODLE_ROOT})."
    while true; do read -p "Please enter the full path to your Moodle directory: " USER_MOODLE_ROOT; USER_MOODLE_ROOT=${USER_MOODLE_ROOT%/}
        if [[ -f "${USER_MOODLE_ROOT}/config.php" ]]; then MOODLE_ROOT="$USER_MOODLE_ROOT"; print_info "Using Moodle directory: ${MOODLE_ROOT}"; break
        else print_error "Error: config.php not found in '${USER_MOODLE_ROOT}'. Please try again."; fi
    done; fi
MOODLE_CONFIG_PATH="${MOODLE_ROOT}/config.php"

# 5. Determine PHP Executable Path
print_info "Attempting to find PHP CLI executable using 'which php'..."
PHP_EXEC=$(which php || echo "")
if [[ -z "$PHP_EXEC" ]]; then print_warning "Could not find 'php' in PATH. Using fallback: ${DEFAULT_PHP_EXEC_FALLBACK}"; PHP_EXEC="$DEFAULT_PHP_EXEC_FALLBACK"; if [[ ! -x "$PHP_EXEC" ]]; then print_error "Fallback PHP executable '$PHP_EXEC' not found or not executable."; exit 1; fi
else print_info "Using PHP executable found at: ${PHP_EXEC}"; fi
if [[ ! -x "$PHP_EXEC" ]]; then print_error "The determined PHP executable path '$PHP_EXEC' is not executable."; exit 1; fi

# 6. Read Moodle config.php using PHP (DB details and prefix)
print_info "Verifying executable permission for PHP: $PHP_EXEC"; if [[ ! -x "$PHP_EXEC" ]]; then print_error "...failed."; exit 1; fi
print_info "Verifying read permission for Moodle config: $MOODLE_CONFIG_PATH"; if [[ ! -r "$MOODLE_CONFIG_PATH" ]]; then print_error "...failed."; exit 1; fi
PHP_TEMP_SCRIPT=$(mktemp --suffix=.php); trap 'echo "INFO: Cleaning up temp PHP script ${PHP_TEMP_SCRIPT}..."; rm -f "$PHP_TEMP_SCRIPT"' EXIT INT TERM
print_info "Reading database credentials and table prefix from ${MOODLE_CONFIG_PATH} (using $PHP_EXEC)..."
cat << EOF > "$PHP_TEMP_SCRIPT"
<?php error_reporting(E_ALL); ini_set('display_errors', 'stderr'); define('CLI_SCRIPT', true); \$configfile = '$MOODLE_CONFIG_PATH'; require(\$configfile); if (!isset(\$CFG) || !is_object(\$CFG)) { exit(1); } if (!isset(\$CFG->dbhost, \$CFG->dbname, \$CFG->dbuser, \$CFG->dbpass, \$CFG->prefix)) { exit(1); } echo 'dbhost=' . \$CFG->dbhost . "\n"; echo 'dbname=' . \$CFG->dbname . "\n"; echo 'dbuser=' . \$CFG->dbuser . "\n"; echo 'dbpass=' . \$CFG->dbpass . "\n"; echo 'prefix=' . \$CFG->prefix . "\n"; exit(0);
EOF
print_info "Temporary PHP script created at: ${PHP_TEMP_SCRIPT}"; chmod 644 "$PHP_TEMP_SCRIPT"
print_info "Executing: $PHP_EXEC -d display_errors=stderr -d error_reporting=E_ALL $PHP_TEMP_SCRIPT"
set +e; COMBINED_OUTPUT=$($PHP_EXEC -d display_errors=stderr -d error_reporting=E_ALL "$PHP_TEMP_SCRIPT" 2>&1); PHP_EXIT_CODE=$?; set -e
print_info "PHP execution finished. Exit Code: ${PHP_EXIT_CODE}"
if [[ $PHP_EXIT_CODE -ne 0 ]]; then print_error "PHP script execution FAILED with non-zero exit code ($PHP_EXIT_CODE)."; print_error "Combined output (stdout/stderr) from PHP:"; print_error "-------------------- PHP Output Start --------------------"; printf '%s\n' "$COMBINED_OUTPUT" >&2; print_error "-------------------- PHP Output End ----------------------"; exit 1; fi
rm -f "$PHP_TEMP_SCRIPT"; trap - EXIT INT TERM
CONFIG_OUTPUT=$(echo "$COMBINED_OUTPUT" | grep '=')
if [[ -z "$CONFIG_OUTPUT" ]]; then print_error "PHP script execution succeeded (exit code 0) but produced NO expected output (key=value)."; print_error "Combined output was:"; print_error "-------------------- PHP Output Start --------------------"; printf '%s\n' "$COMBINED_OUTPUT" >&2; print_error "-------------------- PHP Output End ----------------------"; exit 1; fi
while IFS='=' read -r key value; do case "$key" in dbhost) DB_HOST="$value" ;; dbname) DB_NAME="$value" ;; dbuser) DB_USER="$value" ;; dbpass) DB_PASS="$value" ;; prefix) DB_PREFIX="$value" ;; esac; done <<< "$CONFIG_OUTPUT"
if [[ -z "$DB_HOST" || -z "$DB_NAME" || -z "$DB_USER" || -z "$DB_PASS" || -z "$DB_PREFIX" ]]; then print_error "Could not extract all required DB variables/prefix from the PHP script output."; exit 1; fi
print_info "Successfully extracted Moodle DB configuration and prefix."

# 7. Get Web Server User
print_info "Attempting to determine web server user (needed for sudo)..."
if ps aux | grep -E 'apache2|httpd' | grep -v grep > /dev/null; then DETECTED_WEB_USER="www-data"; print_info "Detected Apache process, suggesting user '${DETECTED_WEB_USER}'.";
elif ps aux | grep 'nginx' | grep -v grep > /dev/null; then DETECTED_WEB_USER="www-data"; print_info "Detected Nginx process, suggesting user '${DETECTED_WEB_USER}'.";
else DETECTED_WEB_USER="www-data"; print_warning "Could not detect common web server process. Suggesting default '${DETECTED_WEB_USER}'."; fi
read -p "Please enter the username your web server runs as [${DETECTED_WEB_USER}]: " USER_WEB_USER
WEB_USER=${USER_WEB_USER:-$DETECTED_WEB_USER}
print_info "Using web server user: ${WEB_USER}"

# 8. Download Scripts
print_info "Downloading Python script..."
cd "${APP_DIR}"
curl -fsSL "${PYTHON_SCRIPT_URL}" -o "${PYTHON_SCRIPT_NAME}"
chmod +x "${VENV_DIR}/bin/python"
chmod +x "${PYTHON_SCRIPT_NAME}"
print_info "Downloading PHP CLI script (temporary location)..."
curl -fsSL "${PHP_CLI_SCRIPT_URL}" -o "${PHP_CLI_SCRIPT_NAME}"

# 9. Generate config.ini
print_info "Checking for existing configuration file: ${APP_DIR}/${CONFIG_NAME}"
if [[ ! -f "${APP_DIR}/${CONFIG_NAME}" ]]; then
    print_info "Generating configuration file: ${APP_DIR}/${CONFIG_NAME}"
    cat << EOF > "${APP_DIR}/${CONFIG_NAME}"
[database]
host = ${DB_HOST}
user = ${DB_USER}
password = ${DB_PASS}
name = ${DB_NAME}
table_prefix = ${DB_PREFIX}

[rules]
failure_threshold = 10

[moodle]
wwwroot = ${MOODLE_ROOT}
php_executable = ${PHP_EXEC}
web_server_user = ${WEB_USER}
cli_script_path = ${MOODLE_CLI_REL_PATH}/${PHP_CLI_SCRIPT_NAME}

[fail2ban]
log_path = ${FAIL2BAN_LOG_PATH}
EOF
    chmod 600 "${CONFIG_NAME}"
    print_info "Generated ${CONFIG_NAME}."
else
    print_warning "Configuration file ${APP_DIR}/${CONFIG_NAME} already exists. Skipping generation."
    print_warning "Review this file manually to ensure settings like 'failure_threshold' are correct."
fi

# 10. Place Moodle CLI Script
MOODLE_CLI_TARGET_DIR="${MOODLE_ROOT}/${MOODLE_CLI_REL_PATH}"
MOODLE_CLI_FULL_PATH="${MOODLE_CLI_TARGET_DIR}/${PHP_CLI_SCRIPT_NAME}"
print_info "Checking for existing Moodle CLI script: ${MOODLE_CLI_FULL_PATH}"
if [[ ! -f "$MOODLE_CLI_FULL_PATH" ]]; then
    print_info "Creating Moodle CLI script directory: ${MOODLE_CLI_TARGET_DIR}"
    mkdir -p "${MOODLE_CLI_TARGET_DIR}"
    print_info "Moving PHP CLI script to ${MOODLE_CLI_FULL_PATH}"
    mv "${PHP_CLI_SCRIPT_NAME}" "${MOODLE_CLI_FULL_PATH}"
    chown root:"${WEB_USER}" "${MOODLE_CLI_FULL_PATH}"
    chmod 640 "${MOODLE_CLI_FULL_PATH}"
    print_info "Set ownership of Moodle CLI script to root:${WEB_USER}."
else
    print_warning "Moodle CLI script ${MOODLE_CLI_FULL_PATH} already exists. Skipping placement."
    rm -f "${APP_DIR}/${PHP_CLI_SCRIPT_NAME}"
fi

# 11. Configure sudo
SUDOERS_LINE="root ALL=(${WEB_USER}) NOPASSWD: ${PHP_EXEC} ${MOODLE_CLI_FULL_PATH} --ip=*"
SUDOERS_FILE="/etc/sudoers"
SUDOERS_TEMP_FILE=$(mktemp)
print_info "Configuring sudoers..."
if ! grep -Fxq "${SUDOERS_LINE}" "${SUDOERS_FILE}"; then
    print_info "Adding sudo rule for root to run Moodle CLI script as ${WEB_USER}."; cp "${SUDOERS_FILE}" "${SUDOERS_TEMP_FILE}"; echo "${SUDOERS_LINE}" >> "${SUDOERS_TEMP_FILE}"
    if visudo -qcf "${SUDOERS_TEMP_FILE}"; then print_info "Sudoers syntax check passed. Applying changes."; cp "${SUDOERS_TEMP_FILE}" "${SUDOERS_FILE}"; else print_error "Sudoers syntax check failed! Reverting changes."; rm "${SUDOERS_TEMP_FILE}"; exit 1; fi; rm "${SUDOERS_TEMP_FILE}"
else print_info "Sudoers rule already exists or is similar."; rm "${SUDOERS_TEMP_FILE}"; fi

# 12. Configure Fail2ban (with checks)
FAIL2BAN_FILTER_PATH="/etc/fail2ban/filter.d/${FAIL2BAN_FILTER_NAME}.conf"
FAIL2BAN_JAIL_PATH="/etc/fail2ban/jail.d/${FAIL2BAN_JAIL_NAME}.conf"
print_info "Checking for existing Fail2ban filter: ${FAIL2BAN_FILTER_PATH}"
if [[ ! -f "$FAIL2BAN_FILTER_PATH" ]]; then
    print_info "Configuring Fail2ban filter: ${FAIL2BAN_FILTER_PATH}"
    cat << EOF > "${FAIL2BAN_FILTER_PATH}"
[Definition]
failregex = ^\s*.*MoodleLoginFail \[IP: <HOST>\]
ignoreregex =
EOF
else
    print_warning "Fail2ban filter ${FAIL2BAN_FILTER_PATH} already exists. Skipping creation."
fi

print_info "Checking for existing Fail2ban jail: ${FAIL2BAN_JAIL_PATH}"
if [[ ! -f "$FAIL2BAN_JAIL_PATH" ]]; then
    print_info "Configuring Fail2ban jail: ${FAIL2BAN_JAIL_PATH}"
    cat << EOF > "${FAIL2BAN_JAIL_PATH}"
[${FAIL2BAN_JAIL_NAME}]
enabled = true
port = http,https
filter = ${FAIL2BAN_FILTER_NAME}
logpath = ${FAIL2BAN_LOG_PATH}
maxretry = 1
findtime = 300
bantime = 3600
action = iptables-multiport[name=MoodleAuthCustom, port="http,https"]
EOF
else
     print_warning "Fail2ban jail ${FAIL2BAN_JAIL_PATH} already exists. Skipping creation."
     print_warning "Ensure settings like 'bantime' and 'logpath' are correct manually if needed."
fi

print_info "Reloading Fail2ban configuration..."
if systemctl is-active --quiet fail2ban; then systemctl reload fail2ban;
else systemctl enable fail2ban; systemctl restart fail2ban; fi

# 13. Setup Cron Job
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

# 14. Create Log Files and Set Initial Permissions
print_info "Creating log files and setting initial permissions..."
touch "${APP_DIR}/${LOG_FILE_NAME}"
touch "${APP_DIR}/${CRON_LOG_NAME}"
touch "${FAIL2BAN_LOG_PATH}"
chown root:root "${APP_DIR}/${LOG_FILE_NAME}" "${APP_DIR}/${CRON_LOG_NAME}" "${VENV_DIR}" -R
chmod 644 "${APP_DIR}/${LOG_FILE_NAME}" "${APP_DIR}/${CRON_LOG_NAME}"
chown root:root "${FAIL2BAN_LOG_PATH}"
chgrp adm "${FAIL2BAN_LOG_PATH}" || true
chmod 640 "${FAIL2BAN_LOG_PATH}"


# --- Final Instructions ---
echo ""
print_info "---------------------------------------------------------------------"
print_info " Moodle Auto IP Blocker Setup Complete!"
print_info "---------------------------------------------------------------------"
echo ""
print_info "Configuration based on:"
echo "  - Moodle Directory: ${MOODLE_ROOT}"
echo "  - Moodle config:    ${MOODLE_CONFIG_PATH}"
echo "  - Web User:         ${WEB_USER}"
echo "  - PHP Path Used:    ${PHP_EXEC}"
echo ""
print_info "Python dependencies installed in virtual environment: ${VENV_DIR}"
echo ""
print_warning "!!!!!!!!!!!!!!!!!!!! IMPORTANT VERIFICATION !!!!!!!!!!!!!!!!!!!!"
echo ""
print_warning "The setup automatically used the PHP executable found at: '${PHP_EXEC}'."
print_warning "PLEASE VERIFY that this is the correct PHP CLI version for your Moodle installation."
print_warning "If it's incorrect, the IP blocking process (calling the PHP script) might fail."
echo ""
print_warning "To change it, edit 'php_executable' in ${APP_DIR}/${CONFIG_NAME}"
print_warning "And ALSO update the corresponding path in the sudoers rule using 'sudo visudo'."
echo ""
print_warning "Review ${APP_DIR}/${CONFIG_NAME} and Fail2ban configs if you need to adjust thresholds/bantime."
echo ""
print_info "CHECK LOGS:"
echo "  - Script execution log: ${APP_DIR}/${LOG_FILE_NAME}"
echo "  - Cron execution log: ${APP_DIR}/${CRON_LOG_NAME}"
echo "  - Fail2ban log: /var/log/fail2ban.log (for general activity)"
echo "  - Log monitored by Fail2ban: ${FAIL2BAN_LOG_PATH}"
echo ""
print_info "The cron job is set to run every minute. Blocking should start occurring"
print_info "once the script runs successfully and thresholds are met."
print_info "Check Moodle's IP Blocker page to verify IPs are being added."
print_info "---------------------------------------------------------------------"

exit 0