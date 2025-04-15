# Moodle Auto IP Blocker

This project provides a mechanism to automatically block IP addresses that generate excessive failed login attempts on a Moodle site within a certain amount of time. It uses a Python script to monitor Moodle logs and can trigger blocking via **Moodle's internal IP blocker** and/or **Fail2ban** for firewall-level blocking. The blocking methods are fully configurable via the included `config.ini` file.

## Goal

Publicly accessible Moodle sites often face brute-force login attempts. Moodle's built-in account lockout isn't sufficient against attackers cycling usernames. This solution aims to:

1.  Monitor Moodle's database logs for failed login events (`\\core\\event\\user_login_failed`).
2.  Identify IP addresses exceeding a configured number of failed logins within a short period.
3.  **Optionally (Default: Enabled):** Add the offending IP to Moodle's internal block list (`mdl_config` table, `blockedip` setting) via a Moodle CLI script. This makes the block visible and manageable by Moodle administrators via the UI.
4.  **Optionally (Default: Enabled):** Log these offending IPs to a dedicated file monitored by Fail2ban.
5.  **If Fail2ban logging is enabled:** Trigger Fail2ban to add an immediate firewall rule (e.g., using `iptables`) to block the IP.

**Primary Benefit of Moodle Internal Blocking:** Allows Moodle administrators (without server access) to view and manage blocked IPs via `Site administration > Server > IP blocker`, facilitating the handling of potential false positives.

## Features

*   **Database Log Monitoring:** Directly queries the Moodle log store (`mdl_logstore_standard_log`).
*   **IP-Based Threshold:** Counts failures per IP address across script runs.
*   **Configurable Blocking Methods:** Independently enable or disable:
    *   Adding IPs to Moodle's core block list (`blockedip` setting).
    *   Logging IPs for Fail2ban firewall blocking.
*   **Automated Installation:** Provides an `install.sh` script for easy setup on Debian-based systems (installs dependencies including `fail2ban` and `iptables`).
*   **Automatic Configuration:** Attempts to read Moodle database credentials and paths from `config.php`.
*   **Python Virtual Environment:** Installs Python dependencies in an isolated `venv`.
*   **Log Rotation:** The main Python script log (`moodle_ip_blocker.log`) uses automatic log rotation.

## Requirements

*   **Operating System:** Debian-based Linux (e.g., Debian 11/12, Ubuntu 20.04/22.04). Tested primarily on Debian 12.
*   **Moodle Installation:** A working Moodle site. The installer assumes the default path (`/var/www/html/moodle`).
*   **Root/Sudo Access:** Required for installing packages, creating configurations, setting up cron, and running the main script.
*   **PHP CLI:** The **correct** PHP Command Line Interface executable matching the version used by your Moodle web server must be installed and accessible in the system `PATH`. Necessary PHP extensions (like `mysqli` or `pgsql` depending on your Moodle DB) must be enabled for this CLI version.
*   **Python:** Python 3, Pip, and Venv (`python3`, `python3-pip`, `python3-venv`) installed by the script.
*   **Fail2ban:** The Fail2ban service (installed by the script).
*   **iptables:** The `iptables` command/package (installed by the script). Required *if* `enable_fail2ban_blocking` is `true`. The installer attempts to install it, but ensure it's functioning correctly on your system if you rely on Fail2ban blocking.
*   **Database Access:** The script needs credentials to connect to your Moodle database (obtained from Moodle's `config.php`).
*   **Web Server User:** You need to know the user your web server (Apache/Nginx) runs as (e.g., `www-data`, `daemon`).

## Installation

The installation is automated via the `install.sh` script. It installs dependencies like `python3`, `fail2ban`, and `iptables` by default.

**WARNING:** Always inspect scripts downloaded from the internet before executing them with `sudo`. This script installs packages, creates files, modifies system configurations (Fail2ban, Cron), and requires root privileges.

1.  **Review the Script:** Open the `install.sh` URL in your browser or download it and review its contents thoroughly.
    ```
    https://raw.githubusercontent.com/justncodes/moodle-auto-ip-blocker/refs/heads/master/install.sh
    ```
2.  **Execute the Installer:** Run the following command on your Moodle server terminal:
    ```bash
    curl -fsSL https://raw.githubusercontent.com/justncodes/moodle-auto-ip-blocker/refs/heads/master/install.sh | sudo bash
    ```
3.  **Follow Prompts (If Any):**
    *   The script automatically detects Moodle path (`/var/www/html/moodle`), PHP path (`which php`), and web server user (`www-data` or `daemon`).
    *   It will **verify** the detected web server user exists. If the auto-detected user is incorrect or doesn't exist, the script will error out with instructions.
4.  **Post-Installation Verification (CRITICAL):** After the script finishes, carefully review the final output messages:
    *   **Verify PHP Path:** Ensure the `PHP Path Used` matches the version your Moodle web server uses. If not, update `/opt/moodle-blocker/config.ini` (`php_executable`) manually.
    *   **Verify Web User:** Ensure the `Web User` is correct. If not, update `/opt/moodle-blocker/config.ini` (`web_server_user`) AND manually correct the group ownership of the CLI script (`sudo chown root:CORRECT_USER /path/to/moodle/local/customscripts/cli/block_ip.php`).
    *   **Review Blocking Options:** Note that both Moodle internal blocking and Fail2ban logging are **enabled by default**. Edit `/opt/moodle-blocker/config.ini` and set the flags under `[actions]` to `false` if you wish to disable either method.

## Configuration

The main configuration is done in `/opt/moodle-blocker/config.ini`. The installer generates this file automatically.

Key settings you might review or adjust:

*   `[database]` section: Automatically populated from Moodle's `config.php`.
*   `[rules]` section:
    *   `failure_threshold = 10`: Number of failed logins from an IP since the last check needed to trigger a block.
*   `[moodle]` section:
    *   `wwwroot = /var/www/html/moodle`: Filesystem path to your Moodle directory.
    *   `php_executable = /usr/bin/php`: **CRITICAL:** Path to the correct PHP CLI executable.
    *   `web_server_user = www-data`: **CRITICAL:** User your web server runs as.
    *   `cli_script_path = local/customscripts/cli/block_ip.php`: Path relative to Moodle root for the helper script.
*   `[fail2ban]` section:
    *   `log_path = /var/log/moodle_failed_logins.log`: Path to the log file Fail2ban monitors. Only relevant if `enable_fail2ban_blocking = true`.
*   `[actions]` section (**NEW**):
    *   `enable_moodle_core_blocking = true`: Set to `true` to add offending IPs to Moodle's internal `blockedip` list (visible in UI). Set to `false` to disable this.
    *   `enable_fail2ban_blocking = true`: Set to `true` to log offending IPs to the `log_path` for Fail2ban to act upon (requires `iptables`). Set to `false` to disable this.

Fail2ban configuration is located at:

*   Filter: `/etc/fail2ban/filter.d/moodle-auth-custom.conf`
*   Jail: `/etc/fail2ban/jail.d/moodle-custom.conf` (Adjust `bantime` here if needed. Only active if `enable_fail2ban_blocking = true`).

## How it Works

1.  **Cron Job (`/etc/cron.d/moodle-blocker`):** Runs `/opt/moodle-blocker/moodle_ip_blocker.py` as `root` every minute.
2.  **Python Script (`moodle_ip_blocker.py`):**
    *   Reads config, including `[actions]` flags (`enable_moodle_core_blocking`, `enable_fail2ban_blocking`).
    *   Reads last processed log ID from `/opt/moodle-blocker/moodle_blocker_state.dat`.
    *   Connects to Moodle DB and queries `mdl_logstore_standard_log` for new `\\core\\event\\user_login_failed` events.
    *   Counts failures per IP.
    *   If an IP exceeds `failure_threshold`:
        *   **If `enable_fail2ban_blocking = true`:** Logs the IP to `/var/log/moodle_failed_logins.log`.
        *   **If `enable_moodle_core_blocking = true`:** Calls the Moodle CLI script (`block_ip.php`) via `sudo -u <web_user>` to add the IP to Moodle's internal block list.
    *   Updates the last processed ID in `moodle_blocker_state.dat`.
    *   Logs its own activity to `/opt/moodle-blocker/moodle_ip_blocker.log`.
3.  **Moodle CLI Script (`block_ip.php`):**
    *   Executed as the web server user *only if* called by the Python script (when `enable_moodle_core_blocking = true`).
    *   Uses Moodle API functions to append the IP to the **core** `blockedip` setting in `mdl_config`.
    *   Attempts to purge the core config cache.
4.  **Fail2ban:**
    *   *Only if* `enable_fail2ban_blocking = true` in `config.ini`:
        *   The `moodle-custom` jail monitors `/var/log/moodle_failed_logins.log`.
        *   The `moodle-auth-custom` filter matches the log lines.
        *   Fail2ban uses `iptables` (via the `iptables-multiport` action by default) to add a firewall rule blocking the IP.

## Management and Usage

*   **Checking Logs:**
    *   **Main Script Log:** `/opt/moodle-blocker/moodle_ip_blocker.log` (Shows overall activity, thresholds met, calls to actions)
    *   **Cron Execution Log:** `/opt/moodle-blocker/cron.log` (Should normally be empty unless Python script crashes)
    *   **Fail2ban Target Log:** `/var/log/moodle_failed_logins.log` (Only relevant if `enable_fail2ban_blocking = true`)
    *   **Fail2ban Main Log:** `/var/log/fail2ban.log` (Shows Fail2ban's own actions like starting jails, banning/unbanning)
*   **Viewing Blocked IPs:**
    *   **Moodle UI (Primary Method if `enable_moodle_core_blocking = true`):** Go to `Site administration > Server > IP blocker`. Purge caches (`Site administration > Development > Purge caches`) if the list doesn't seem up-to-date.
    *   **Moodle Database (If `enable_moodle_core_blocking = true`):** `SELECT value FROM mdl_config WHERE name = 'blockedip';`
    *   **Fail2ban (If `enable_fail2ban_blocking = true`):** Check the status of the jail:
        ```bash
        sudo fail2ban-client status moodle-custom
        ```
*   **Unblocking IPs:**
    1.  **Moodle (If `enable_moodle_core_blocking` was `true` when the IP was blocked):**
        *   **Via UI (Recommended):** Go to the IP Blocker page (`Site administration > Server > IP blocker`), delete the IP, and save changes. Purge caches afterward.
        *   **Via Database (Advanced):** Manually edit the `blockedip` value in the `mdl_config` table (as described in the original README) and purge caches.
    2.  **Fail2ban (If `enable_fail2ban_blocking` was `true` when the IP was blocked):**
        *   Remove the immediate firewall rule:
          ```bash
          sudo fail2ban-client set moodle-custom unbanip <IP_ADDRESS>
          ```

## Troubleshooting

*   **Script not running / `cron.log` empty:** Check cron service (`systemctl status cron`), permissions on `/etc/cron.d/moodle-blocker`, main script log (`/opt/moodle-blocker/moodle_ip_blocker.log`), and run manually as root (`sudo /opt/moodle-blocker/venv/bin/python3 /opt/moodle-blocker/moodle_ip_blocker.py`).
*   **IPs not appearing in Moodle UI Blocker:**
    *   Verify `enable_moodle_core_blocking = true` in `/opt/moodle-blocker/config.ini`.
    *   Check `/opt/moodle-blocker/moodle_ip_blocker.log` for errors calling the Moodle CLI script (`call_moodle_cli`). Look for \"Failed to block IP ... via Moodle CLI\".
    *   Check the stderr output mentioned in the log message.
    *   Verify `php_executable` and `web_server_user` in `config.ini`.
    *   Verify permissions on `/var/www/html/moodle/config.php` (readable by `web_server_user`).
    *   Test the CLI script manually: `sudo -u <web_user> <php_executable> <moodle_root>/local/customscripts/cli/block_ip.php --ip=1.2.3.4`.
    *   Purge Moodle caches (`Site administration > Development > Purge caches`).
*   **IPs not being blocked by Firewall (Fail2ban/iptables):**
    *   Verify `enable_fail2ban_blocking = true` in `/opt/moodle-blocker/config.ini`.
    *   Check if IPs are being written to `/var/log/moodle_failed_logins.log` (the file monitored by Fail2ban). If not, check `/opt/moodle-blocker/moodle_ip_blocker.log` for errors.
    *   Check `/var/log/fail2ban.log` for errors related to the `moodle-custom` jail or `iptables` actions.
    *   Ensure `iptables` is installed and the service/command is functional. Run `sudo iptables -L -n` to see active firewall rules. The `MoodleAuthCustom` chain should exist if Fail2ban has banned IPs.
    *   Check Fail2ban status: `sudo fail2ban-client status moodle-custom`.
*   **DB Connection Errors in `moodle_ip_blocker.log`:** Check database credentials in `/opt/moodle-blocker/config.ini` match Moodle's `config.php`. Ensure the database server is running and accessible from the server where the script runs.