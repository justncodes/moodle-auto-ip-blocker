<?php
// This script is designed to be run from the command line.

define('CLI_SCRIPT', true);
// Determine Moodle path dynamically relative to this script's location
$scriptpath = dirname(__FILE__);
$moodleroot = dirname(dirname(dirname($scriptpath)));
$configfile = $moodleroot . '/config.php';

// Fallback if dynamic path fails
if (!file_exists($configfile)) {
    $configfile = '/var/www/html/moodle/config.php';
}

if (!file_exists($configfile)) {
    fwrite(STDERR, "ERROR: Moodle config file not found at '$configfile' or derived path.\n");
    exit(1);
}
if (!is_readable($configfile)) {
     fwrite(STDERR, "ERROR: Moodle config file exists but is not readable by user " . getmyuid() . " at '$configfile'. Check permissions.\n");
     exit(1);
}

// Load Moodle config first
require_once($configfile);

// Verify $CFG before loading other libs
if (!isset($CFG) || !is_object($CFG) || !isset($CFG->libdir)) {
     fwrite(STDERR, "ERROR: Moodle config file loaded but \$CFG object or \$CFG->libdir is not set correctly.\n");
     exit(1);
}

// Now load required Moodle libraries
require_once($CFG->libdir.'/clilib.php');
require_once($CFG->libdir.'/adminlib.php'); // Needed for get/set_config
require_once($CFG->libdir.'/messagelib.php'); // Needed for send_email()

// --- Parse command line options ---
$cli_options_definition = [
    'ip' => '',
    'notify-email' => '',
    'help' => false,
];
$cli_short_options = ['h' => 'help'];

list($options, $unrecognised) = cli_get_params($cli_options_definition, $cli_short_options);

if ($unrecognised) {
    $unrecognised_str = implode("\n  ", $unrecognised);
    cli_error(get_string('cliunknowoption', 'admin', $unrecognised_str));
}

if ($options['help'] || empty($options['ip'])) {
    $help = <<<EOT
Add IP to Moodle CORE 'blockedip' list and optionally send notification.

Options:
  --ip=IP_ADDRESS        The IP address to block. (Required)
  --notify-email=EMAIL   Email address to send notification to (Optional).
                         Requires Moodle mail system to be configured.
  -h, --help             Show this help message.

Example:
  sudo -u www-data php block_ip.php --ip=192.168.1.100 --notify-email=admin@example.com
EOT;
    echo $help;
    exit(0);
}

$ip_to_block = trim($options['ip']);
$notify_email = trim($options['notify_email']);

if (!filter_var($ip_to_block, FILTER_VALIDATE_IP)) {
    cli_error("Invalid IP address format provided: '{$ip_to_block}'");
    exit(1);
}
if (!empty($notify_email) && !filter_var($notify_email, FILTER_VALIDATE_EMAIL)) {
     cli_writeln("WARNING: Invalid format for --notify-email: '{$notify_email}'. Notification will not be sent.");
     $notify_email = '';
}


cli_heading('Moodle IP Blocker CLI (Core Setting: blockedip)');
cli_writeln("Attempting to block IP: " . $ip_to_block . " in CORE config ('blockedip')");

// Read the 'blockedip' setting
$blockedips_string = get_config(null, 'blockedip');
$ip_list = preg_split('/[\s,]+/', $blockedips_string ?? '', -1, PREG_SPLIT_NO_EMPTY);
$ip_list = array_map('trim', $ip_list);
$ip_list = array_filter($ip_list);

if (in_array($ip_to_block, $ip_list)) {
    cli_writeln("IP address {$ip_to_block} is already in the CORE 'blockedip' list. No changes made.");
    exit(0);
}

// Add the new IP
$ip_list[] = $ip_to_block;
$ip_list = array_unique($ip_list);
$new_list_string = implode("\n", $ip_list);

// Save the updated list
if (set_config('blockedip', $new_list_string)) {
    cli_writeln("Successfully added {$ip_to_block} to the CORE Moodle 'blockedip' list.");
    cli_writeln("Updating config value to:\n---\n{$new_list_string}\n---");

    // Attempt to purge cache
    try {
        $cache = cache::make('core', 'config');
        $cache->purge();
        cli_writeln("Purged core config cache.");
    } catch (Exception $e) {
        cli_writeln("WARNING: Could not purge Moodle cache automatically: " . $e->getMessage());
    }

    // Send Email Notification
    if (!empty($notify_email)) {
        cli_writeln("Attempting to send notification email to {$notify_email}...");

        if (empty($CFG->noreplyaddress)) {
             cli_writeln("WARNING: Moodle 'noreplyaddress' is not configured. Cannot send email.");
        } else {
            try {
                $sitename = format_string($SITE->fullname, true, ['context' => context_system::instance()]);
                $subject = $sitename . ' :: Banned IP notification';
                $body_text = "The following IP address has been automatically added to the Moodle block list due to excessive failed login attempts:\n\n";
                $body_text .= "IP Address: {$ip_to_block}\n\n";
                $body_text .= "Timestamp: " . date('Y-m-d H:i:s T') . "\n\n";
                $body_text .= "This block was added by the Moodle Auto IP Blocker script.\n";
                $body_text .= "You can manage blocked IPs via Site administration > Server > IP blocker.\n";

                // Use Moodle's send_mail function
                $mail_sent = send_email(
                    $notify_email,
                    $CFG->noreplyaddress,
                    $subject,
                    $body_text
                );

                if ($mail_sent) {
                    cli_writeln("Successfully sent notification email to {$notify_email}.");
                } else {
                    cli_error("Failed to send notification email to {$notify_email}. Check Moodle mail configuration and logs.");
                }
            } catch (Exception $e) {
                 cli_error("Error during email sending process: " . $e->getMessage());
            }
        }
    } else {
         cli_writeln("Email notification skipped (no --notify-email provided or address invalid).");
    }

    exit(0);

} else {
    cli_error("Failed to update the CORE Moodle 'blockedip' list configuration for {$ip_to_block}. Check database permissions or Moodle logs.");
    exit(1);
}