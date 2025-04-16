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
STATE_FILE = os.path.join(APP_DIR, 'moodle_blocker_state.dat')
LOG_FILE = os.path.join(APP_DIR, 'moodle_ip_blocker.log')

# --- Setup Logging ---
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
log_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE,
    maxBytes=1024*1024*5, # 5 MB
    backupCount=3,
    encoding='utf-8'
)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger('MoodleBlocker')
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

fail2ban_log_formatter = logging.Formatter('%(asctime)s MoodleLoginFail [IP: %(message)s] Threshold exceeded')
fail2ban_logger = logging.getLogger('Fail2banTarget')
fail2ban_logger.setLevel(logging.INFO)
fail2ban_handler = None

# --- Functions ---
def read_last_id(filepath):
    try:
        if not os.path.exists(filepath):
            logger.info(f"State file '{filepath}' not found, starting from ID 0.")
            return 0
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                 logger.warning(f"State file '{filepath}' is empty, starting from ID 0.")
                 return 0
            last_id = int(content)
            logger.debug(f"Read last processed ID {last_id} from {filepath}")
            return last_id
    except ValueError:
        logger.error(f"Invalid integer value in state file '{filepath}'. Cannot proceed.", exc_info=True)
        sys.exit(1)
    except Exception:
        logger.error(f"Error reading state file '{filepath}'. Cannot proceed.", exc_info=True)
        sys.exit(1)

def write_last_id(filepath, last_id):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(str(last_id))
        logger.debug(f"Wrote last processed ID {last_id} to {filepath}")
    except Exception:
        logger.error(f"Error writing state file '{filepath}'.", exc_info=True)

def get_moodle_db_password(config):
    try:
        php_bin = config.get('moodle', 'php_executable')
        moodle_root = config.get('moodle', 'wwwroot')
        config_php_path = os.path.join(moodle_root, 'config.php')

        if not os.path.isfile(config_php_path):
            raise FileNotFoundError(f"Moodle config.php not found: {config_php_path}")
        if not os.access(config_php_path, os.R_OK):
             if os.geteuid() == 0:
                 logger.warning(f"Read access check failed for {config_php_path} (running as root), attempting anyway.")
             else:
                 raise PermissionError(f"Read permission denied for {config_php_path}")

        config_php_path_norm = os.path.normpath(config_php_path).replace('\\', '/')

        php_code = f"""
        error_reporting(0);
        define('CLI_SCRIPT', true);
        @require_once('{config_php_path_norm}');
        if (!isset($CFG) || !is_object($CFG) || !isset($CFG->dbpass)) {{
            fwrite(STDERR, 'Error: Could not load config ({config_php_path_norm}) or find $CFG->dbpass\\n');
            exit(1);
        }}
        echo $CFG->dbpass;
        exit(0);
        """

        logger.debug(f"PHP code to execute for password retrieval:\n---\n{php_code}\n---")
        logger.debug(f"Attempting password retrieval via PHP CLI: {php_bin}")
        result = subprocess.run([php_bin, "-r", php_code],
                                capture_output=True, text=True, check=False, encoding='utf-8')

        if result.returncode != 0:
            logger.error(f"PHP code executed (failed):\n---\n{php_code}\n---")
            raise RuntimeError(f"PHP failed (RC {result.returncode}) getting password. Stderr: {result.stderr.strip()}")

        password = result.stdout.strip()
        logger.info("Successfully retrieved DB password from Moodle config.php.")
        return password

    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        logger.error(f"Missing required config in config.ini: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve Moodle DB password: {e}", exc_info=True)
        raise

def call_moodle_cli(config, ip_address):
    try:
        php_bin = config.get('moodle', 'php_executable')
        moodle_root = config.get('moodle', 'wwwroot')
        cli_script = config.get('moodle', 'cli_script_path')
        web_user = config.get('moodle', 'web_server_user')
        send_email = config.getboolean('moodle', 'enable_email_notification', fallback=False)
        notify_email_addr_str = config.get('moodle', 'notification_email_address', fallback='').strip()
        cli_script_full_path = os.path.join(moodle_root, cli_script)

        if not os.path.exists(cli_script_full_path):
             logger.error(f"Moodle CLI script not found: {cli_script_full_path}")
             return False

        command = ['sudo', '-u', web_user, php_bin, cli_script_full_path, f'--ip={ip_address}']
        cli_log_extra = ""
        if send_email and notify_email_addr_str:
            command.append(f'--notify-email={notify_email_addr_str}')
            cli_log_extra = f" (with notification(s))"
            logger.debug(f"Email notification enabled, adding --notify-email.")
        elif send_email and not notify_email_addr_str:
            logger.warning(f"Email notification enabled but 'notification_email_address' empty.")
        else: logger.debug(f"Email notification disabled.")

        logger.info(f"Attempting Moodle IP block for {ip_address}{cli_log_extra}.")
        logger.debug(f"Executing command: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=False, encoding='utf-8')

        if result.returncode == 0:
            logger.info(f"Successfully requested Moodle IP block for {ip_address}.")
            logger.debug(f"Moodle CLI stdout:\n{result.stdout}")
            if send_email and notify_email_addr_str and "Successfully sent notification email" not in result.stdout:
                 logger.warning(f"Moodle CLI success, but email confirmation message missing.")
            return True
        else:
            logger.error(f"Moodle IP block failed for {ip_address}. RC: {result.returncode}")
            logger.error(f"Moodle CLI stderr:\n{result.stderr}")
            logger.error(f"Moodle CLI stdout:\n{result.stdout}")
            return False
    except configparser.Error as e:
        logger.error(f"Config error reading Moodle CLI settings: {e}", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"Error executing Moodle CLI for {ip_address}.", exc_info=True)
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
    enable_moodle_blocking_action = False
    enable_fail2ban_blocking_action = False
    last_processed_id = 0
    exit_code = 0

    try:
        logger.info(f"Script execution started at: {start_time_str}")

        # Load configuration
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config.read_file(f)
        except FileNotFoundError:
            logger.error(f"Configuration file '{CONFIG_FILE}' not found.")
            exit_code = 1; sys.exit(exit_code)
        except configparser.Error as e:
            logger.error(f"Error parsing configuration file '{CONFIG_FILE}': {e}")
            exit_code = 1; sys.exit(exit_code)

        # Get desired actions
        try:
            enable_moodle_blocking_action = config.getboolean('actions', 'enable_moodle_ip_blocking', fallback=False)
            enable_fail2ban_blocking_action = config.getboolean('actions', 'enable_fail2ban_blocking', fallback=False)
            logger.info(f"Action Settings: Moodle IP Blocking: {enable_moodle_blocking_action}, Fail2ban Blocking: {enable_fail2ban_blocking_action}")
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError) as e:
             logger.error(f"Error reading [actions] flags: {e}. Defaulting both to False.")
             enable_moodle_blocking_action = False; enable_fail2ban_blocking_action = False

        # Setup Fail2ban logger
        if enable_fail2ban_blocking_action:
            try:
                fail2ban_log_path = config.get('fail2ban', 'log_path')
                fail2ban_handler = logging.FileHandler(fail2ban_log_path, encoding='utf-8')
                fail2ban_handler.setFormatter(fail2ban_log_formatter)
                fail2ban_logger.addHandler(fail2ban_handler)
                logger.info(f"Fail2ban logging enabled, target: {fail2ban_log_path}")
            except (configparser.NoSectionError, configparser.NoOptionError) as e:
                logger.error(f"Fail2ban enabled, but missing config: {e}. Disabling.")
                enable_fail2ban_blocking_action = False
            except Exception as e:
                 logger.error(f"Error setting up Fail2ban logger: {e}. Disabling.", exc_info=True)
                 enable_fail2ban_blocking_action = False
        else: logger.info("Fail2ban logging disabled.")

        # Get DB settings
        db_host = config.get('database', 'host')
        db_user = config.get('database', 'user')
        db_name = config.get('database', 'name')
        db_table_prefix = config.get('database', 'table_prefix', fallback='mdl_')
        failure_threshold = config.getint('rules', 'failure_threshold', fallback=10)
        db_port = config.getint('database', 'port', fallback=3306)

        # Get password from Moodle
        db_password = get_moodle_db_password(config)

        # Get last processed ID
        last_processed_id = read_last_id(STATE_FILE)

        # Connect to database
        cnx = None
        cursor = None
        new_max_id = last_processed_id
        ip_failures = {}

        # Base connection arguments
        connection_args = {
            'user': db_user,
            'password': db_password,
            'database': db_name,
            'connection_timeout': 10
        }
        default_socket_path = '/run/mysqld/mysqld.sock'
        use_socket = False

        if db_host.lower() == 'localhost' or db_host == '127.0.0.1':
            if os.path.exists(default_socket_path):
                 logger.info(f"Host is local and socket '{default_socket_path}' exists. Attempting connection via socket.")
                 connection_args['unix_socket'] = default_socket_path
                 use_socket = True
            else:
                 logger.warning(f"Host is local but default socket '{default_socket_path}' not found. Will attempt TCP/IP to {db_host}:{db_port}.")
                 connection_args['host'] = db_host
                 connection_args['port'] = db_port
                 use_socket = False
        else:
             logger.info(f"Host '{db_host}' is not local. Attempting TCP/IP connection.")
             connection_args['host'] = db_host
             connection_args['port'] = db_port
             use_socket = False

        try:
            logger.debug(f"Attempting connection with args: {connection_args}")
            cnx = mysql.connector.connect(**connection_args)
            cursor = cnx.cursor(dictionary=True)
            logger.info(f"Database connection successful {'via socket' if use_socket else 'via TCP/IP'}.")
        except mysql.connector.Error as err:
            # If we TRIED the socket and it failed, attempt TCP fallback
            if use_socket:
                logger.warning(f"Socket connection failed ({err}). Retrying via TCP/IP to {db_host}:{db_port}...")
                del connection_args['unix_socket']
                connection_args['host'] = db_host
                connection_args['port'] = db_port
                try:
                    logger.debug(f"Retrying connection with TCP args: {connection_args}")
                    cnx = mysql.connector.connect(**connection_args)
                    cursor = cnx.cursor(dictionary=True)
                    logger.info("Database connection successful via TCP/IP fallback.")
                except mysql.connector.Error as err_tcp:
                    logger.error(f"TCP/IP fallback connection also failed: {err_tcp}", exc_info=True)
                    raise err_tcp
            else:
                logger.error(f"Database connection failed: {err}", exc_info=True)
                raise err


        # Query for new failed logins
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
            else: logger.debug(f"Log entry ID {log_id} has no IP.")

        logger.info(f"Processed {processed_count} new failed login events. Max ID: {new_max_id}")

        # Check thresholds and trigger actions
        processed_ips_this_run = set()
        for ip, count in ip_failures.items():
            if count >= failure_threshold:
                if ip not in processed_ips_this_run:
                    logger.warning(f"IP {ip} exceeded threshold ({count} failures).")
                    action_taken_f2b = False
                    action_taken_moodle = False

                    if enable_fail2ban_blocking_action and fail2ban_handler:
                        try:
                            logger.info(f"Logging IP {ip} for Fail2ban.")
                            fail2ban_logger.info(ip)
                            action_taken_f2b = True
                        except Exception as e: logger.error(f"Failed writing IP {ip} to F2B log.", exc_info=True)

                    if enable_moodle_blocking_action:
                        if call_moodle_cli(config, ip): action_taken_moodle = True
                        else: logger.error(f"Moodle IP block action failed for {ip}.")

                    if action_taken_f2b or action_taken_moodle: processed_ips_this_run.add(ip)
                    elif not enable_fail2ban_blocking_action and not enable_moodle_blocking_action: logger.warning(f"IP {ip} met threshold but no actions enabled.")
                    else: logger.warning(f"IP {ip} met threshold but all enabled actions failed.")
                else: logger.debug(f"IP {ip} already processed.")

        if processed_count > 0 and not ip_failures: logger.info("Processed logs, no IPs reached threshold.")
        elif not processed_count: logger.info("No new failed login events found.")


    except mysql.connector.Error as err:
        new_max_id = last_processed_id; exit_code = 1
    except configparser.Error as e:
         logger.error(f"Configuration error: {e}", exc_info=True)
         new_max_id = last_processed_id; exit_code = 1
    except (FileNotFoundError, PermissionError, RuntimeError) as e:
         logger.error(f"Failed getting required info: {e}")
         new_max_id = last_processed_id; exit_code = 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        new_max_id = last_processed_id; exit_code = 1

    finally:
        end_time = datetime.now()
        duration = end_time - start_time

        if cursor:
            try: cursor.close(); logger.debug("DB cursor closed.")
            except Exception as e: logger.warning(f"Error closing cursor: {e}")
        if cnx and cnx.is_connected():
            try: cnx.close(); logger.debug("DB connection closed.")
            except Exception as e: logger.warning(f"Error closing connection: {e}")
        if fail2ban_handler:
            try: fail2ban_logger.removeHandler(fail2ban_handler); fail2ban_handler.close(); logger.debug("F2B handler closed.")
            except Exception as e: logger.warning(f"Error closing F2B handler: {e}")

        if exit_code == 0:
            if 'new_max_id' in locals() and 'last_processed_id' in locals():
                 if new_max_id > last_processed_id:
                     write_last_id(STATE_FILE, new_max_id)
                 else:
                     if 'processed_count' in locals() and processed_count > 0:
                          logger.info("Max ID unchanged. State file not updated.")
            else: logger.warning("State variables missing; state file not updated.")
        else:
            logger.warning(f"Finished with errors (Exit Code {exit_code}). State file NOT updated.")

        logger.info(f"Script execution finished at: {end_time.strftime('%Y-%m-%d %H:%M:%S')} (Duration: {duration}) - Exit Code: {exit_code}")
        sys.exit(exit_code)