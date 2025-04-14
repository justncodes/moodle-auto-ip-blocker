#!/usr/bin/env python3
import mysql.connector
import configparser
import logging
import logging.handlers
import os
import sys
import subprocess
from datetime import datetime

# --- Configuration ---
CONFIG_FILE = 'config.ini'
STATE_FILE = 'moodle_blocker_state.dat' # Stores the last processed log ID

# --- Setup Logging ---
# General operational logging
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
log_handler = logging.handlers.RotatingFileHandler(
    'moodle_ip_blocker.log',
    maxBytes=1024*1024*5, # 5 MB
    backupCount=3
)
log_handler.setFormatter(log_formatter)

logger = logging.getLogger('MoodleBlocker')
logger.setLevel(logging.INFO) # Set to logging.DEBUG for more detail
logger.addHandler(log_handler)

# Specific logger for Fail2ban output
fail2ban_log_formatter = logging.Formatter('%(asctime)s MoodleLoginFail [IP: %(message)s] Threshold exceeded')
# Note: Fail2ban needs a specific file path defined in its jail.conf
# We will configure this path in config.ini
fail2ban_logger = logging.getLogger('Fail2banTarget')
fail2ban_logger.setLevel(logging.INFO)
# We will add the file handler after reading config

# --- Functions ---
def read_last_id(filepath):
    """Reads the last processed log ID from the state file."""
    try:
        if not os.path.exists(filepath):
            logger.info(f"State file '{filepath}' not found, starting from ID 0.")
            return 0
        with open(filepath, 'r') as f:
            content = f.read().strip()
            if not content:
                 logger.warning(f"State file '{filepath}' is empty, starting from ID 0.")
                 return 0
            last_id = int(content)
            logger.debug(f"Read last processed ID {last_id} from {filepath}")
            return last_id
    except ValueError:
        logger.error(f"Invalid integer value found in state file '{filepath}'. Cannot proceed.", exc_info=True)
        sys.exit(1)
    except Exception:
        logger.error(f"Error reading state file '{filepath}'. Cannot proceed.", exc_info=True)
        sys.exit(1)

def write_last_id(filepath, last_id):
    """Writes the last processed log ID to the state file."""
    try:
        with open(filepath, 'w') as f:
            f.write(str(last_id))
        logger.debug(f"Wrote last processed ID {last_id} to {filepath}")
    except Exception:
        logger.error(f"Error writing state file '{filepath}'. Last ID {last_id} might not be saved.", exc_info=True)

def call_moodle_cli(config, ip_address):
    """Calls the Moodle CLI script to block the IP."""
    try:
        php_bin = config.get('moodle', 'php_executable', fallback='/usr/bin/php')
        moodle_root = config.get('moodle', 'wwwroot')
        cli_script = config.get('moodle', 'cli_script_path', fallback='local/customscripts/cli/block_ip.php')
        web_user = config.get('moodle', 'web_server_user', fallback='www-data')

        cli_script_full_path = os.path.join(moodle_root, cli_script)

        if not os.path.exists(cli_script_full_path):
             logger.error(f"Moodle CLI script not found at: {cli_script_full_path}")
             return False

        command = [
            'sudo', '-u', web_user,
            php_bin,
            cli_script_full_path,
            f'--ip={ip_address}'
        ]

        logger.info(f"Attempting to block IP {ip_address} via Moodle CLI.")
        logger.debug(f"Executing command: {' '.join(command)}")

        result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.returncode == 0:
            logger.info(f"Successfully requested blocking of IP {ip_address} via Moodle CLI.")
            logger.debug(f"Moodle CLI stdout:\n{result.stdout}")
            return True
        else:
            logger.error(f"Failed to block IP {ip_address} via Moodle CLI. Return code: {result.returncode}")
            logger.error(f"Moodle CLI stderr:\n{result.stderr}")
            logger.error(f"Moodle CLI stdout:\n{result.stdout}")
            return False

    except Exception as e:
        logger.error(f"Error executing Moodle CLI command for IP {ip_address}.", exc_info=True)
        return False

if __name__ == "__main__":
    logger.info("Moodle IP Blocker script started.")

    # Load configuration
    config = configparser.ConfigParser()
    try:
        if not config.read(CONFIG_FILE):
            logger.error(f"Configuration file '{CONFIG_FILE}' not found or empty.")
            sys.exit(1)
    except configparser.Error as e:
        logger.error(f"Error parsing configuration file '{CONFIG_FILE}': {e}")
        sys.exit(1)

    # Setup Fail2ban logger based on config
    try:
        fail2ban_log_path = config.get('fail2ban', 'log_path')
        fail2ban_handler = logging.FileHandler(fail2ban_log_path)
        fail2ban_handler.setFormatter(fail2ban_log_formatter)
        fail2ban_logger.addHandler(fail2ban_handler)
    except (configparser.NoSectionError, configparser.NoOptionError):
        logger.error(f"Missing [fail2ban] section or 'log_path' option in {CONFIG_FILE}")
        sys.exit(1)
    except Exception as e:
         logger.error(f"Error setting up Fail2ban logger for path {fail2ban_log_path}: {e}")
         sys.exit(1)

    # Get settings from config
    try:
        db_host = config.get('database', 'host')
        db_user = config.get('database', 'user')
        db_password = config.get('database', 'password')
        db_name = config.get('database', 'name')
        db_table_prefix = config.get('database', 'table_prefix', fallback='mdl_')
        failure_threshold = config.getint('rules', 'failure_threshold', fallback=10)
        # Time window is implicit based on cron frequency and state file ID tracking
    except (configparser.NoSectionError, configparser.NoOptionError, ValueError) as e:
        logger.error(f"Missing or invalid configuration in '{CONFIG_FILE}'. Check sections [database], [rules]. Error: {e}")
        sys.exit(1)

    # Read the last processed ID
    state_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), STATE_FILE)
    last_processed_id = read_last_id(state_file_path)

    cnx = None
    cursor = None
    new_max_id = last_processed_id
    ip_failures = {} # Dictionary to store failure counts for this run

    try:
        # Connect to database
        logger.debug(f"Connecting to database {db_name} on {db_host} as {db_user}")
        cnx = mysql.connector.connect(
            user=db_user,
            password=db_password,
            host=db_host,
            database=db_name
        )
        cursor = cnx.cursor(dictionary=True) # Get results as dictionaries

        # Construct table name with prefix
        log_table = f"{db_table_prefix}logstore_standard_log"

        # Query for new failed login events since the last run
        query = f"""
            SELECT id, ip
            FROM {log_table}
            WHERE eventname = '\\\\core\\\\event\\\\user_login_failed'
              AND id > %s
            ORDER BY id ASC
        """
        # Note the double backslash needed for the event name in the SQL string within Python f-string/query param

        logger.debug(f"Executing query with last_processed_id = {last_processed_id}")
        cursor.execute(query, (last_processed_id,))

        # Process results
        processed_count = 0
        for row in cursor:
            processed_count += 1
            log_id = row['id']
            ip_address = row['ip']

            # Update the highest ID seen in this batch
            if log_id > new_max_id:
                new_max_id = log_id

            # Aggregate failures per IP
            if ip_address: # Ignore entries with no IP
                ip_failures[ip_address] = ip_failures.get(ip_address, 0) + 1
            else:
                 logger.debug(f"Log entry ID {log_id} has no IP address, skipping.")

        logger.info(f"Processed {processed_count} new failed login events. Max ID encountered: {new_max_id}")

        # Check thresholds and trigger actions
        blocked_ips_this_run = set() # Prevent multiple block attempts per IP per run
        for ip, count in ip_failures.items():
            if count >= failure_threshold:
                if ip not in blocked_ips_this_run:
                    logger.warning(f"IP address {ip} exceeded threshold with {count} failures.")
                    # Log specifically for Fail2ban first
                    fail2ban_logger.info(ip) # Only log the IP itself for the Fail2ban logger format

                    # Call Moodle CLI to add to internal block list
                    if call_moodle_cli(config, ip):
                         blocked_ips_this_run.add(ip)
                    else:
                         logger.error(f"Skipping further actions for {ip} in this run due to CLI execution failure.")
                else:
                    logger.debug(f"IP {ip} already processed for blocking in this run.")

    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}", exc_info=True)
        # Don't update state file on DB error, retry next time
        sys.exit(1) # Exit with error for cron
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        # Don't update state file on unknown error
        sys.exit(1) # Exit with error for cron
    finally:
        # Close database connection
        if cursor:
            cursor.close()
            logger.debug("Database cursor closed.")
        if cnx and cnx.is_connected():
            cnx.close()
            logger.debug("Database connection closed.")

        # Save the new max ID if processing was successful (no critical errors)
        if new_max_id > last_processed_id:
             write_last_id(state_file_path, new_max_id)
        else:
             logger.info("No new log entries processed or max ID did not increase.")

    logger.info("Moodle IP Blocker script finished.")
    sys.exit(0) # Exit successfully