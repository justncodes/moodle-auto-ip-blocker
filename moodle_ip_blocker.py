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
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(APP_DIR, 'config.ini')
STATE_FILE = os.path.join(APP_DIR, 'moodle_blocker_state.dat') # Stores the last processed log ID
LOG_FILE = os.path.join(APP_DIR, 'moodle_ip_blocker.log')

# --- Setup Logging ---
# General operational logging
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
log_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE,
    maxBytes=1024*1024*5, # 5 MB
    backupCount=3
)
log_handler.setFormatter(log_formatter)

logger = logging.getLogger('MoodleBlocker')
logger.setLevel(logging.INFO) # Set to logging.DEBUG for more detail
logger.addHandler(log_handler)

# Specific logger for Fail2ban output (configured later based on config file)
fail2ban_log_formatter = logging.Formatter('%(asctime)s MoodleLoginFail [IP: %(message)s] Threshold exceeded')
fail2ban_logger = logging.getLogger('Fail2banTarget')
fail2ban_logger.setLevel(logging.INFO)
fail2ban_handler = None

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
    """Calls the Moodle CLI script to block the IP, potentially passing email info."""
    try:
        php_bin = config.get('moodle', 'php_executable', fallback='/usr/bin/php')
        moodle_root = config.get('moodle', 'wwwroot')
        cli_script = config.get('moodle', 'cli_script_path', fallback='local/customscripts/cli/block_ip.php')
        web_user = config.get('moodle', 'web_server_user', fallback='www-data')

        # Check for email notification settings
        send_email = config.getboolean('moodle', 'enable_email_notification', fallback=False)
        notify_email_addr = config.get('moodle', 'notification_email_address', fallback='').strip()

        cli_script_full_path = os.path.join(moodle_root, cli_script)

        if not os.path.exists(cli_script_full_path):
             logger.error(f"Moodle CLI script not found at: {cli_script_full_path}")
             return False

        # Base command
        command = [
            'sudo', '-u', web_user,
            php_bin,
            cli_script_full_path,
            f'--ip={ip_address}'
        ]

        # Add email argument if enabled and address provided
        cli_log_extra = ""
        if send_email and notify_email_addr:
            command.append(f'--notify-email={notify_email_addr}')
            cli_log_extra = f" (with notification to {notify_email_addr})"
            logger.debug(f"Email notification enabled, adding --notify-email argument.")
        elif send_email and not notify_email_addr:
            logger.warning(f"Email notification enabled but 'notification_email_address' is empty in config. Skipping email argument.")
        else:
             logger.debug(f"Email notification disabled or no address configured.")


        logger.info(f"Attempting to block IP {ip_address} via Moodle CLI (Core List){cli_log_extra}.")
        logger.debug(f"Executing command: {' '.join(command)}")

        result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.returncode == 0:
            logger.info(f"Successfully requested blocking of IP {ip_address} via Moodle CLI.")
            logger.debug(f"Moodle CLI stdout:\n{result.stdout}")
            if send_email and notify_email_addr and "Successfully sent notification" not in result.stdout:
                 logger.warning(f"Moodle CLI reported success, but email notification confirmation message not found in output.")
            return True
        else:
            logger.error(f"Failed to block IP {ip_address} via Moodle CLI. Return code: {result.returncode}")
            logger.error(f"Moodle CLI stderr:\n{result.stderr}")
            logger.error(f"Moodle CLI stdout:\n{result.stdout}")
            return False

    except configparser.Error as e:
        logger.error(f"Configuration error reading email settings: {e}", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"Error executing Moodle CLI command for IP {ip_address}.", exc_info=True)
        return False


# --- Main Execution ---
if __name__ == "__main__":
    start_time = datetime.now()
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
    end_time = None
    duration = None
    cnx = None
    cursor = None
    config = configparser.ConfigParser()
    enable_moodle_blocking = False
    enable_fail2ban_blocking = False
    last_processed_id = 0

    try:
        logger.info(f"Script execution started at: {start_time_str}")

        # Load configuration
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config.read_file(f)
        except FileNotFoundError:
            logger.error(f"Configuration file '{CONFIG_FILE}' not found.")
            sys.exit(1)
        except configparser.Error as e:
            logger.error(f"Error parsing configuration file '{CONFIG_FILE}': {e}")
            sys.exit(1)

        # Get desired actions from config
        try:
            enable_moodle_blocking = config.getboolean('actions', 'enable_moodle_ip_blocking', fallback=False)
            enable_fail2ban_blocking = config.getboolean('actions', 'enable_fail2ban_blocking', fallback=False)
            logger.info(f"Action Settings: Moodle Core Blocking: {enable_moodle_blocking}, Fail2ban Blocking: {enable_fail2ban_blocking}")
        except (configparser.NoSectionError, configparser.NoOptionError):
            logger.warning(f"Missing [actions] section or options in {CONFIG_FILE}. Defaulting both blocking methods to False.")
            enable_moodle_blocking = False
            enable_fail2ban_blocking = False
        except ValueError as e:
             logger.error(f"Invalid boolean value in [actions] section of {CONFIG_FILE}: {e}. Defaulting both blocking methods to False.")
             enable_moodle_blocking = False
             enable_fail2ban_blocking = False

        # Setup Fail2ban logger if enabled
        if enable_fail2ban_blocking:
            try:
                fail2ban_log_path = config.get('fail2ban', 'log_path')
                if not os.path.isabs(fail2ban_log_path):
                    fail2ban_log_path = os.path.join(APP_DIR, fail2ban_log_path)
                fail2ban_handler = logging.FileHandler(fail2ban_log_path, encoding='utf-8')
                fail2ban_handler.setFormatter(fail2ban_log_formatter)
                fail2ban_logger.addHandler(fail2ban_handler)
                logger.info(f"Fail2ban logging enabled, target: {fail2ban_log_path}")
            except (configparser.NoSectionError, configparser.NoOptionError):
                logger.error(f"Fail2ban blocking enabled, but missing [fail2ban] section or 'log_path' option in {CONFIG_FILE}. Disabling Fail2ban logging for this run.")
                enable_fail2ban_blocking = False
            except Exception as e:
                 logger.error(f"Error setting up Fail2ban logger for path {fail2ban_log_path}: {e}. Disabling Fail2ban logging for this run.", exc_info=True)
                 enable_fail2ban_blocking = False
        else:
             logger.info("Fail2ban logging is disabled via config.")


        # Get other settings from config
        db_host = config.get('database', 'host')
        db_user = config.get('database', 'user')
        db_password = config.get('database', 'password')
        db_name = config.get('database', 'name')
        db_table_prefix = config.get('database', 'table_prefix', fallback='mdl_')
        failure_threshold = config.getint('rules', 'failure_threshold', fallback=10)

        # Read the last processed ID
        last_processed_id = read_last_id(STATE_FILE)

        cnx = None
        cursor = None
        new_max_id = last_processed_id
        ip_failures = {}

        # Connect to database
        logger.debug(f"Connecting to database {db_name} on {db_host} as {db_user}")
        cnx = mysql.connector.connect(
            user=db_user, password=db_password, host=db_host, database=db_name
        )
        cursor = cnx.cursor(dictionary=True)

        # Query for new failed login events
        log_table = f"{db_table_prefix}logstore_standard_log"
        query = f"""
            SELECT id, ip FROM {log_table}
            WHERE eventname = '\\\\core\\\\event\\\\user_login_failed' AND id > %s
            ORDER BY id ASC
        """
        logger.debug(f"Executing query with last_processed_id = {last_processed_id}")
        cursor.execute(query, (last_processed_id,))

        # Process results
        processed_count = 0
        for row in cursor:
            processed_count += 1
            log_id = row['id']
            ip_address = row['ip']
            if log_id > new_max_id: new_max_id = log_id
            if ip_address: ip_failures[ip_address] = ip_failures.get(ip_address, 0) + 1
            else: logger.debug(f"Log entry ID {log_id} has no IP address, skipping.")

        logger.info(f"Processed {processed_count} new failed login events. Max ID encountered: {new_max_id}")

        # Check thresholds and trigger enabled actions
        processed_ips_this_run = set()
        for ip, count in ip_failures.items():
            if count >= failure_threshold:
                if ip not in processed_ips_this_run:
                    logger.warning(f"IP address {ip} exceeded threshold with {count} failures.")
                    action_taken_f2b = False
                    action_taken_moodle = False

                    # Action 1: Log for Fail2ban (if enabled)
                    if enable_fail2ban_blocking and fail2ban_handler: # Check handler exists too
                        try:
                            logger.info(f"Logging IP {ip} for Fail2ban.")
                            fail2ban_logger.info(ip)
                            action_taken_f2b = True
                        except Exception as e:
                            logger.error(f"Failed to write IP {ip} to Fail2ban log.", exc_info=True)

                    # Action 2: Block via Moodle CLI (if enabled)
                    if enable_moodle_blocking:
                        if call_moodle_cli(config, ip):
                             action_taken_moodle = True
                        else:
                             logger.error(f"Moodle CLI block failed for {ip}. Check specific errors above.")

                    # Mark IP as processed if *either* action succeeded
                    if action_taken_f2b or action_taken_moodle:
                        processed_ips_this_run.add(ip)
                    elif not enable_fail2ban_blocking and not enable_moodle_blocking:
                         logger.warning(f"IP {ip} met threshold ({count}) but no blocking actions were enabled.")
                    else:
                         logger.warning(f"IP {ip} met threshold ({count}) but all enabled blocking actions failed.")

                else:
                    logger.debug(f"IP {ip} already processed for blocking in this run.")

        if processed_count > 0 and not ip_failures:
             logger.info("Processed new log entries, but no IPs reached the failure threshold in this run.")
        elif not processed_count:
             logger.info("No new failed login events found since last run.")


    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}", exc_info=True)
        new_max_id = last_processed_id
        sys.exit(1)
    except configparser.Error as e:
         logger.error(f"Configuration error: {e}", exc_info=True)
         new_max_id = last_processed_id
         sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        new_max_id = last_processed_id
        sys.exit(1)

    finally:
        end_time = datetime.now()
        end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
        duration = end_time - start_time

        if cursor:
            try:
                cursor.close()
                logger.debug("Database cursor closed.")
            except Exception as e:
                 logger.warning(f"Error closing database cursor: {e}")
        if cnx and cnx.is_connected():
            try:
                cnx.close()
                logger.debug("Database connection closed.")
            except Exception as e:
                 logger.warning(f"Error closing database connection: {e}")

        # Close fail2ban handler if it was opened
        if fail2ban_handler:
            try:
                fail2ban_logger.removeHandler(fail2ban_handler)
                fail2ban_handler.close()
                logger.debug("Fail2ban log handler closed.")
            except Exception as e:
                 logger.warning(f"Error closing Fail2ban handler: {e}")

        if 'new_max_id' in locals() and 'last_processed_id' in locals():
             if new_max_id > last_processed_id:
                 write_last_id(STATE_FILE, new_max_id)
             else:
                 if 'processed_count' in locals() and processed_count > 0:
                      logger.info("Max ID did not increase. State file unchanged.")
                 elif 'processed_count' not in locals():
                      logger.warning("Processed count unknown, state file likely unchanged.")
        else:
             logger.warning("State variables missing, could not determine whether to update state file.")


        logger.info(f"Script execution finished at: {end_time_str} (Duration: {duration})")