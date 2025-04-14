#!/bin/bash

# Stop script on any error
set -e
# Ensure commands in pipelines return non-zero status if they fail
set -o pipefail

# --- Configuration Variables ---
APP_DIR="/opt/moodle-blocker"
PYTHON_SCRIPT_URL="https://raw.githubusercontent.com/justncodes/moodle-auto-ip-blocker/refs/heads/master/moodle_ip_blocker.py"
CONFIG_EXAMPLE_URL="https://raw.githubusercontent.com/justncodes/moodle-auto-ip-blocker/refs/heads/master/config.ini.example"
PHP_CLI_SCRIPT_URL="https://raw.githubusercontent.com/justncodes/moodle-auto-ip-blocker/refs/heads/master/block_ip.php"

PYTHON_SCRIPT_NAME="moodle_ip_blocker.py"
CONFIG_NAME="config.ini"
CONFIG_EXAMPLE_NAME="config.ini.example"
PHP_CLI_SCRIPT_NAME="block_ip.php"
STATE_FILE_NAME="moodle_blocker_state.dat"
LOG_FILE_NAME="moodle_ip_blocker.log"
CRON_LOG_NAME="cron.log"
FAIL2BAN_LOG_NAME="moodle_failed_logins.log" # Must match default in config.ini.example
FAIL2BAN_FILTER_NAME="moodle-auth-custom"
FAIL2BAN_JAIL_NAME="moodle-custom"
CRON_FILE_NAME="moodle-blocker"

# Default values (User MUST verify/edit these in config.ini later)
DEFAULT_MOODLE_ROOT="/var/www/html/moodle"
DEFAULT_WEB_USER="www-data"
DEFAULT_PHP_EXEC="/usr/bin/php"
MOODLE_CLI_REL_PATH="local/customscripts/cli" # Relative to Moodle root

# --- Helper Functions ---
print_info() {
    echo "INFO: $1"
}

print_warning() {
    echo "WARNING: $1"
}

print_error() {
    echo "ERROR: $1" >&2
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root (e.g., using sudo)."
        exit 1
    fi
}

# --- Main Setup Logic ---
check_root

print_info "Starting Moodle Auto IP Blocker Setup..."

# 1. Install Dependencies
print_info "Updating package lists and installing dependencies (python3, pip, mysql-connector-python, fail2ban, sudo, curl)..."
apt-get update
# Install python3-mysql.connector instead of using pip for system package management consistency
apt-get install -y python3 python3-pip python3-mysql.connector fail2ban sudo curl

# 2. Create Application Directory
print_info "Creating application directory: ${APP_DIR}"
mkdir -p "${APP_DIR}"
cd "${APP_DIR}"

# 3. Download Scripts and Config
print_info "Downloading scripts and configuration example..."
curl -fsSL "${PYTHON_SCRIPT_URL}" -o "${PYTHON_SCRIPT_NAME}"
curl -fsSL "${CONFIG_EXAMPLE_URL}" -o "${CONFIG_EXAMPLE_NAME}"
curl -fsSL "${PHP_CLI_SCRIPT_URL}" -o "${PHP_CLI_SCRIPT_NAME}" # Download temporarily here

# Make Python script executable
chmod +x "${PYTHON_SCRIPT_NAME}"

# Copy example config to actual config
cp "${CONFIG_EXAMPLE_NAME}" "${CONFIG_NAME}"
print_warning "Downloaded example configuration to ${APP_DIR}/${CONFIG_NAME}."
print_warning ">>>> YOU MUST EDIT ${APP_DIR}/${CONFIG_NAME} with your database credentials, Moodle path, etc. AFTER this script finishes. <<<<"

# Set permissions for config file (readable only by owner - root initially)
chmod 600 "${CONFIG_NAME}"

# 4. Place Moodle CLI Script
# User *MUST* ensure the path in config.ini is correct later. We use the default for placement.
MOODLE_CLI_TARGET_DIR="${DEFAULT_MOODLE_ROOT}/${MOODLE_CLI_REL_PATH}"
print_info "Creating Moodle CLI script directory (using default path): ${MOODLE_CLI_TARGET_DIR}"
mkdir -p "${MOODLE_CLI_TARGET_DIR}"

print_info "Moving PHP CLI script to ${MOODLE_CLI_TARGET_DIR}/${PHP_CLI_SCRIPT_NAME}"
mv "${PHP_CLI_SCRIPT_NAME}" "${MOODLE_CLI_TARGET_DIR}/${PHP_CLI_SCRIPT_NAME}"

# Set ownership/permissions for Moodle script (assuming web user needs read access)
# We chown to root:web_user and allow group read. Adjust if your setup differs.
chown root:"${DEFAULT_WEB_USER}" "${MOODLE_CLI_TARGET_DIR}/${PHP_CLI_SCRIPT_NAME}"
chmod 640 "${MOODLE_CLI_TARGET_DIR}/${PHP_CLI_SCRIPT_NAME}"
print_warning "Set ownership of Moodle CLI script to root:${DEFAULT_WEB_USER}. Ensure '${DEFAULT_WEB_USER}' is correct for your system!"

# 5. Configure sudo
SUDOERS_LINE="root ALL=(${DEFAULT_WEB_USER}) NOPASSWD: ${DEFAULT_PHP_EXEC} ${MOODLE_CLI_TARGET_DIR}/${PHP_CLI_SCRIPT_NAME} --ip=*"
SUDOERS_FILE="/etc/sudoers"
print_info "Configuring sudoers..."
# Check if the line already exists to avoid duplicates
if ! grep -Fxq "${SUDOERS_LINE}" "${SUDOERS_FILE}"; then
    print_info "Adding sudo rule for root to run Moodle CLI script as ${DEFAULT_WEB_USER}."
    # Use tee to append reliably
    echo "${SUDOERS_LINE}" | tee -a "${SUDOERS_FILE}" > /dev/null
else
    print_info "Sudoers rule already exists."
fi
print_warning "Added sudo rule using default Moodle path and web user. Verify these in /etc/sudoers if you change config.ini!"

# 6. Configure Fail2ban
FAIL2BAN_FILTER_PATH="/etc/fail2ban/filter.d/${FAIL2BAN_FILTER_NAME}.conf"
FAIL2BAN_JAIL_PATH="/etc/fail2ban/jail.d/${FAIL2BAN_JAIL_NAME}.conf"
FAIL2BAN_LOG_PATH="/var/log/${FAIL2BAN_LOG_NAME}" # Must match default in config.ini

print_info "Configuring Fail2ban filter: ${FAIL2BAN_FILTER_PATH}"
cat << EOF > "${FAIL2BAN_FILTER_PATH}"
[Definition]
# Example log line from python script: 2023-10-27 15:30:00,123 MoodleLoginFail [IP: 1.2.3.4] Threshold exceeded
failregex = ^\s*.*MoodleLoginFail \[IP: <HOST>\]
ignoreregex =
EOF

print_info "Configuring Fail2ban jail: ${FAIL2BAN_JAIL_PATH}"
# Create or overwrite the dedicated jail file
cat << EOF > "${FAIL2BAN_JAIL_PATH}"
[${FAIL2BAN_JAIL_NAME}]
enabled = true
port = http,https
filter = ${FAIL2BAN_FILTER_NAME}
logpath = ${FAIL2BAN_LOG_PATH}
maxretry = 1       # Python script handles threshold
findtime = 300     # Check last 5 minutes (adjust if needed)
bantime = 3600     # Ban for 1 hour (adjust if needed)
action = iptables-multiport[name=MoodleAuthCustom, port="http,https"]
EOF

print_info "Reloading Fail2ban configuration..."
systemctl reload fail2ban

# 7. Setup Cron Job
CRON_FILE_PATH="/etc/cron.d/${CRON_FILE_NAME}"
PYTHON_EXEC=$(which python3) # Find python3 executable path

print_info "Setting up cron job: ${CRON_FILE_PATH}"
cat << EOF > "${CRON_FILE_PATH}"
# Run Moodle IP Blocker script every minute
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* * * * * root cd ${APP_DIR} && ${PYTHON_EXEC} ${APP_DIR}/${PYTHON_SCRIPT_NAME} >> ${APP_DIR}/${CRON_LOG_NAME} 2>&1
EOF

# Set correct permissions for cron file
chmod 0644 "${CRON_FILE_PATH}"
# Restarting cron service might not be strictly necessary for /etc/cron.d files on modern Debian,
# but can be done for good measure if issues arise.
# systemctl restart cron

# 8. Create Log Files and Set Initial Permissions
print_info "Creating log files and setting initial permissions..."
touch "${APP_DIR}/${LOG_FILE_NAME}"
touch "${APP_DIR}/${CRON_LOG_NAME}"
touch "${FAIL2BAN_LOG_PATH}" # Create the log fail2ban monitors

# Allow root (cron user) and potentially others (like fail2ban process user) to write.
# Fail2ban log needs to be accessible by the user fail2ban runs as (often root).
# Python script log and cron log owned by root.
chown root:root "${APP_DIR}/${LOG_FILE_NAME}" "${APP_DIR}/${CRON_LOG_NAME}"
chmod 644 "${APP_DIR}/${LOG_FILE_NAME}" "${APP_DIR}/${CRON_LOG_NAME}"
# Fail2ban log permissions can be tricky. Root ownership with group read might be needed
# depending on how fail2ban accesses it. Let's start with root ownership.
chown root:root "${FAIL2BAN_LOG_PATH}"
chmod 644 "${FAIL2BAN_LOG_PATH}"

# --- Final Instructions ---
echo ""
print_info "---------------------------------------------------------------------"
print_info " Moodle Auto IP Blocker Setup Complete!"
print_info "---------------------------------------------------------------------"
echo ""
print_warning "!!!!!!!!!!!!!!!!!!!! IMPORTANT NEXT STEPS !!!!!!!!!!!!!!!!!!!!"
echo ""
print_warning "1. EDIT THE CONFIGURATION FILE:"
echo "   sudo nano ${APP_DIR}/${CONFIG_NAME}"
echo ""
print_warning "   You MUST update the following settings:"
echo "     - [database] user, password, name (use your Moodle DB details)"
echo "     - [database] table_prefix (if not 'mdl_')"
echo "     - [moodle] wwwroot (MUST match your Moodle installation path)"
echo "     - [moodle] web_server_user (MUST match the user your webserver runs as, e.g., www-data, apache)"
echo ""
print_warning "2. VERIFY PATHS AND USERS:"
echo "   - Double-check that '${DEFAULT_MOODLE_ROOT}' used for placing the PHP script is correct."
echo "     If not, manually move '${MOODLE_CLI_TARGET_DIR}/${PHP_CLI_SCRIPT_NAME}' to the correct location"
echo "     within your actual Moodle path under '${MOODLE_CLI_REL_PATH}' and UPDATE config.ini."
echo "   - Ensure the web server user '${DEFAULT_WEB_USER}' is correct. If you change it in config.ini,"
echo "     you may ALSO need to update the sudoers rule added to '${SUDOERS_FILE}' and the ownership of the PHP script."
echo ""
print_warning "3. CHECK LOGS:"
echo "   - Script execution log: ${APP_DIR}/${LOG_FILE_NAME}"
echo "   - Cron execution log: ${APP_DIR}/${CRON_LOG_NAME}"
echo "   - Fail2ban log: /var/log/fail2ban.log (for general fail2ban activity)"
echo "   - Log monitored by Fail2ban: ${FAIL2BAN_LOG_PATH}"
echo ""
print_info "The cron job is set to run every minute. Blocking should start occurring"
print_info "once the script runs successfully and thresholds are met, assuming your"
print_info "configuration in ${CONFIG_NAME} is correct."
print_info "---------------------------------------------------------------------"

exit 0