# Moodle Auto IP Blocker

This project provides a mechanism to automatically block IP addresses that generate excessive failed login attempts on a Moodle site within a certain amount of time. It uses a Python script to monitor Moodle logs and can trigger blocking via **Moodle's internal IP blocker** (recommended, enabled by default) and/or **Fail2ban** for firewall-level blocking (optional, disabled by default). Email notifications can also be configured.

## Goal

Publicly accessible Moodle sites often face brute-force login attempts. Moodle's built-in account lockout isn't sufficient against attackers cycling usernames. This solution aims to:

1.  Monitor Moodle's database logs for failed login events (`\\core\\event\\user_login_failed`).
2.  Identify IP addresses exceeding a configured number of failed logins within a short period.
3.  **Add the offending IP to Moodle's internal block list** (`mdl_config` table, `blockedip` setting) via a Moodle CLI script. This is **enabled by default** and makes the block visible and manageable by Moodle administrators via the UI.
4.  **Optionally (Default: Disabled):** Log offending IPs to a dedicated file monitored by Fail2ban to trigger immediate firewall rules (e.g., using `iptables`).
5.  **Optionally (Default: Disabled):** Send an email notification using Moodle's mail configuration when an IP is blocked via the Moodle internal list.

**Primary Benefit:** The default Moodle IP blocking allows administrators (without server access) to view and manage blocked IPs via `Site administration > General > Security > IP blocker`, facilitating the handling of potential false positives.

## Features

*   **Database Log Monitoring:** Directly queries the Moodle log store (`mdl_logstore_standard_log`).
*   **IP-Based Threshold:** Counts failures per IP address across script runs.
*   **Configurable Blocking Methods:** Independently enable/disable Moodle internal blocking and/or Fail2ban firewall blocking via `config.ini`.
*   **Email Notifications:** Optionally send an email (using Moodle's mail system) to a specified address when an IP is added to the Moodle block list.
*   **Secure Password Handling:** Database password is *not* stored in the script's config file; it's read directly from Moodle's `config.php` at runtime.
*   **Automated Installation:** Provides an `install.sh` script for easy setup on Debian-based systems (installs dependencies including `fail2ban` and `iptables`).
*   **Automatic Configuration:** Attempts to read Moodle database credentials (excluding password) and paths from `config.php`.
*   **Python Virtual Environment:** Installs Python dependencies in an isolated `venv`.
*   **Log Rotation:** The main Python script log (`moodle_ip_blocker.log`) uses automatic log rotation.

## Requirements

*   **Operating System:** Debian-based Linux (e.g., Debian 11/12, Ubuntu 20.04/22.04). Tested primarily on Debian 12.
*   **Moodle Installation:** A working Moodle site. The installer assumes the default path (`/var/www/html/moodle`).
*   **Root/Sudo Access:** Required for installing packages, creating configurations, setting up cron, and running the main script.
*   **PHP CLI:** The **correct** PHP Command Line Interface executable matching the version used by your Moodle web server must be installed and accessible in the system `PATH`. Necessary PHP extensions must be enabled for this CLI version.
*   **Python:** Python 3, Pip, and Venv (installed by the script).
*   **Fail2ban & iptables:** The Fail2ban service and `iptables` command/package (installed by the script). Only actively used if `enable_fail2ban_blocking = true` in `config.ini`.
*   **Database Access:** The script needs credentials (read directly from Moodle's `config.php`) to connect to your Moodle database. The Moodle DB user needs `SELECT` permissions on `mdl_logstore_standard_log` and `UPDATE` permissions on `mdl_config`, which it should already have.
*   **Web Server User:** You need to know the user your web server (Apache/Nginx) runs as (e.g., `www-data`, `daemon`).
*   **(Optional) Moodle Mail Configuration:** Required if enabling email notifications. The system needs to be able to send emails via the settings under `Site administration > Server > Email > Outgoing mail configuration`.
*   **(Optional) Moodle User Account:** If enabling email notifications, the recipient email address must belong to an active Moodle user account.

## Installation

The installation is automated via the `install.sh` script. It downloads and installs all dependencies by default, as well as the python and php files from this github site.

**WARNING:** Always inspect scripts downloaded from the internet before executing them with `sudo`. This script installs packages, creates files, modifies system configurations (Fail2ban, Cron), and requires root privileges.

1.  **Review the Script:** Open the `install.sh` URL in your browser or download it and review its contents thoroughly.
    ```
    https://raw.githubusercontent.com/justncodes/moodle-auto-ip-blocker/refs/heads/master/install.sh
    ```
2.  **Execute the Installer:** Run the following command on your Moodle server terminal:
    ```bash
    curl -fsSL https://raw.githubusercontent.com/justncodes/moodle-auto-ip-blocker/refs/heads/master/install.sh | sudo bash
    ```
3.  **Review Output:** The script automatically detects Moodle path, PHP path, and web server user. It verifies the user exists. Any errors will stop the script.
4.  **Post-Installation Verification (CRITICAL):** After the script finishes, carefully review the final output messages and verify settings in `/opt/moodle-blocker/config.ini`:
    *   **Verify PHP Path (`php_executable`):** Ensure this matches the version your Moodle web server uses. If not, update manually.
    *   **Verify Web User (`web_server_user`):** Ensure this is correct. If not, update manually AND correct the group ownership of the CLI script (`sudo chown root:CORRECT_USER /path/to/moodle/local/customscripts/cli/block_ip.php`).
    *   **Review Blocking Options (`[actions]` section):**
        *   `enable_moodle_ip_blocking` defaults to `true` (recommended).
        *   `enable_fail2ban_blocking` defaults to `false`. Set to `true` if you want firewall-level blocking via Fail2ban/iptables.
    *   **Configure Email Notifications (`[moodle]` section):**
        *   Set `enable_email_notification = true`.
        *   Set `notification_email_address` to the email address of an *existing Moodle user* who should receive the alerts.
        *   Ensure Moodle's mail system is configured and working.

## Configuration (`/opt/moodle-blocker/config.ini`)

```ini
[database]
# These parameters are retrieved from Moodle config.php automatically
host = ...
user = ...
name = ...

# Adjust if using a different prefix
table_prefix = mdl_

[rules]
# Number of failures from one IP since last check to trigger block
failure_threshold = 10

[moodle]
# Adjust if using a different Moodle installation path
wwwroot = /var/www/html/moodle

# Path to PHP CLI executable
php_executable = /usr/bin/php

# User the web server runs as (e.g., www-data, apache, nginx) - Needed for sudo
web_server_user = www-data

# Relative path within Moodle dir to the CLI script
cli_script_path = local/customscripts/cli/block_ip.php

# Enable email notifications for Moodle blocks (requires address below)
enable_email_notification = false

# Email address of an existing Moodle user to send notifications to (must be set if above is true)
notification_email_address =

[fail2ban]
# Path Fail2ban will monitor (if enabled below)
log_path = /var/log/moodle_failed_logins.log

[actions]
# Set to true to block IPs using Moodle's internal IP Blocker (visible in UI)
enable_moodle_ip_blocking = true

# Set to true to block IPs using Fail2ban and firewall rules (e.g., iptables)
# Default is false as Moodle IP blocking is generally preferred.
enable_fail2ban_blocking = false
```

Fail2ban configuration files are still created but only used if `enable_fail2ban_blocking = true`:

*   Filter: `/etc/fail2ban/filter.d/moodle-auth-custom.conf`
*   Jail: `/etc/fail2ban/jail.d/moodle-custom.conf` (Adjust `bantime` here if needed).

## How it Works

1.  **Cron Job (`/etc/cron.d/moodle-blocker`):** Runs `/opt/moodle-blocker/moodle_ip_blocker.py` as `root` every minute.
2.  **Python Script (`moodle_ip_blocker.py`):**
    *   Reads settings from `config.ini`.
    *   Reads last processed log ID from `moodle_blocker_state.dat`.
    *   Reads Moodle DB password directly from `config.php` using PHP CLI.
    *   Connects to Moodle DB and queries `mdl_logstore_standard_log` for new `\\core\\event\\user_login_failed` events.
    *   Counts failures per IP.
    *   If an IP exceeds `failure_threshold`:
        *   **If `enable_fail2ban_blocking = true`:** Logs the IP to `/var/log/moodle_failed_logins.log`.
        *   **If `enable_moodle_ip_blocking = true`:** Calls the Moodle CLI script (`block_ip.php`) via `sudo -u <web_user>`, passing the IP and notification email (if configured).
    *   Updates the last processed ID in `moodle_blocker_state.dat`.
    *   Logs its own activity to `/opt/moodle-blocker/moodle_ip_blocker.log`.
3.  **Moodle CLI Script (`block_ip.php`):**
    *   Executed as the web server user *only if* called by the Python script (`enable_moodle_ip_blocking = true`).
    *   Uses Moodle `adminlib` functions (`get_config`, `set_config`) to append the IP to the `blockedip` setting in `mdl_config`.
    *   Attempts to purge the core config cache.
    *   If a notification email address was passed and belongs to a valid Moodle user:
        *   Uses Moodle's core mailing mechanism (direct PHPMailer configured via `$CFG`) to send a notification email.
        *   The email includes details and a direct link to Moodle's IP Blocker page.
4.  **Fail2ban:**
    *   *Only if* `enable_fail2ban_blocking = true` in `config.ini`:
        *   The `moodle-custom` jail monitors `/var/log/moodle_failed_logins.log`.
        *   The filter matches the log lines.
        *   Fail2ban uses `iptables` to add a firewall rule blocking the IP.

## Management and Usage

*   **Checking Logs:**
    *   **Main Script Log:** `/opt/moodle-blocker/moodle_ip_blocker.log`
    *   **Cron Execution Log:** `/opt/moodle-blocker/cron.log` (Only contains output if Python script crashes)
    *   **Fail2ban Target Log:** `/var/log/moodle_failed_logins.log` (Only relevant if Fail2ban blocking is enabled)
    *   **Fail2ban Main Log:** `/var/log/fail2ban.log`
*   **Viewing Blocked IPs:**
    *   **Moodle UI (Primary Method):** `Site administration > General > Security > IP blocker`.
    *   **Moodle Database:** `SELECT value FROM mdl_config WHERE name = 'blockedip';`
    *   **Fail2ban (If Enabled):** `sudo fail2ban-client status moodle-custom`
*   **Unblocking IPs:**
    1.  **Moodle (If `enable_moodle_ip_blocking` was true):**
        *   **Via UI (Recommended):** Go to the IP Blocker page (`Site administration > General > Security > IP blocker`), delete the IP, and save changes. Purge caches afterward.
        *   **Via Database (Advanced):** Manually edit the `blockedip` value in the `mdl_config` table and purge caches.
    2.  **Fail2ban (If `enable_fail2ban_blocking` was true):**
        *   Remove the firewall rule: `sudo fail2ban-client set moodle-custom unbanip <IP_ADDRESS>`

## Troubleshooting

*   **Script Not Running / Cron Log Empty:** Check cron service (`systemctl status cron`), permissions on `/etc/cron.d/moodle-blocker`, main script log (`moodle_ip_blocker.log`), and run Python script manually as root. Check Python script exit code in main log.
*   **IPs Not Blocked in Moodle UI:**
    *   Verify `enable_moodle_ip_blocking = true` in `config.ini`.
    *   Check `moodle_ip_blocker.log` for errors calling the Moodle CLI script (e.g., \"Moodle IP block failed...\"). Examine `stderr` and `stdout` printed in the log.
    *   Check Moodle DB user permissions (`UPDATE` on `mdl_config`).
    *   Test `block_ip.php` manually (see previous logs for command).
    *   Purge Moodle caches.
*   **Email Notifications Not Sent:**
    *   Verify `enable_email_notification = true` and `notification_email_address` (must be a Moodle user's email) are set in `config.ini`.
    *   Check `moodle_ip_blocker.log` for errors related to the Moodle CLI call.
    *   Run `block_ip.php` manually and check its output for specific mail errors (e.g., \"PHPMailer failed...\", \"Could not find active Moodle user...\").
    *   Verify Moodle's outgoing mail configuration (`Site administration > Server > Email > Outgoing mail configuration`) and ensure Moodle can send *any* email.
    *   Check system mail logs (`/var/log/mail.log`, `/var/log/maillog`) or web server error logs for lower-level mail delivery issues.
    *   Note the script disables SMTP SSL certificate verification by default (`SMTPOptions` in `block_ip.php`) which might be needed for internal relays but is less secure for external servers.
*   **IPs Not Blocked by Firewall (Fail2ban/iptables):**
    *   Verify `enable_fail2ban_blocking = true` in `config.ini`.
    *   Check if IPs are written to `/var/log/moodle_failed_logins.log`.
    *   Check `/var/log/fail2ban.log` for errors.
    *   Ensure `iptables` service is functional. Check `sudo iptables -L -n`.
    *   Check Fail2ban status: `sudo fail2ban-client status moodle-custom`.
*   **DB Connection Errors (Python Script):** Check Moodle's `config.php` permissions (readable by root for password retrieval step). Verify DB host/user/name in `config.ini`. Ensure DB server is running and accessible.
*   **PHP Deprecated Warnings:** These can generally be ignored. They relate to Moodle code using older PHP features and don't typically affect functionality. They will likely be addressed in future Moodle updates.