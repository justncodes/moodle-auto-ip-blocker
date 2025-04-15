<?php
// This script is designed to be run from the command line.

define('CLI_SCRIPT', true);

// --- Setup ---
$scriptpath = dirname(__FILE__);
$moodleroot = dirname(dirname(dirname($scriptpath)));
$configfile = $moodleroot . '/config.php';

if (!file_exists($configfile)) { $configfile = '/var/www/html/moodle/config.php'; }
if (!file_exists($configfile)) { fwrite(STDERR, "ERROR: Moodle config not found.\n"); exit(1); }
if (!is_readable($configfile)) { fwrite(STDERR, "ERROR: Moodle config not readable.\n"); exit(1); }

require_once($configfile);

if (!isset($CFG) || !is_object($CFG) || !isset($CFG->libdir)) { fwrite(STDERR, "ERROR: \$CFG object not loaded.\n"); exit(1); }

require_once($CFG->libdir.'/clilib.php');
require_once($CFG->libdir.'/adminlib.php');
require_once($CFG->libdir.'/messagelib.php');

// --- Parse CLI options ---
$cli_options_definition = [ 'ip' => '', 'notify-email' => '', 'help' => false ];
$cli_short_options = ['h' => 'help'];
list($options, $unrecognised) = cli_get_params($cli_options_definition, $cli_short_options);

if ($unrecognised) { cli_error(get_string('cliunknowoption', 'admin', implode("\n  ", $unrecognised))); }

if ($options['help'] || empty($options['ip'])) {
    $help = <<<EOT
Add IP to Moodle 'blockedip' list and optionally send notification.

Options:
  --ip=IP_ADDRESS        The IP address to block. (Required)
  --notify-email=EMAIL   Email address to send notification to (Optional).
  -h, --help             Show this help message.
EOT;
    echo $help;
    exit(0);
}

$ip_to_block = trim($options['ip']);
$notify_email = trim($options['notify_email']);

if (!filter_var($ip_to_block, FILTER_VALIDATE_IP)) { cli_error("Invalid IP address format: '{$ip_to_block}'"); exit(1); }
if (!empty($notify_email) && !filter_var($notify_email, FILTER_VALIDATE_EMAIL)) {
     cli_writeln("WARNING: Invalid --notify-email format: '{$notify_email}'.");
     $notify_email = '';
}

// --- Main Logic ---
cli_heading("Moodle IP Blocker CLI ('blockedip')");
cli_writeln("Processing IP: " . $ip_to_block);

$blockedips_string = get_config(null, 'blockedip');
$ip_list = preg_split('/[\s,]+/', $blockedips_string ?? '', -1, PREG_SPLIT_NO_EMPTY);
$ip_list = array_map('trim', $ip_list);
$ip_list = array_filter($ip_list);

if (in_array($ip_to_block, $ip_list)) {
    cli_writeln("IP {$ip_to_block} already in 'blockedip' list.");
    exit(0);
}

$ip_list[] = $ip_to_block;
$ip_list = array_unique($ip_list);
$new_list_string = implode("\n", $ip_list);

if (set_config('blockedip', $new_list_string)) {
    cli_writeln("Successfully added {$ip_to_block} to 'blockedip' list.");
    cli_writeln("New list value:\n---\n{$new_list_string}\n---");

    // Purge cache
    try {
        cache::make('core', 'config')->purge();
        cli_writeln("Purged core config cache.");
    } catch (Exception $e) {
        cli_writeln("WARNING: Cache purge failed: " . $e->getMessage());
    }

    // Send Email
    if (!empty($notify_email)) {
        cli_writeln("Attempting notification to {$notify_email}...");
        if (empty($CFG->noreplyaddress)) {
             cli_writeln("WARNING: Moodle 'noreplyaddress' not configured. Cannot send.");
        } else {
            try {
                $sitename = get_config('moodle', 'sitename') ?: 'Moodle Site';
                $subject = $sitename . ' :: Banned IP notification';
                $body_text = "IP address automatically added to Moodle block list:\n\n"
                           . "IP Address: {$ip_to_block}\n\n"
                           . "Timestamp: " . date('Y-m-d H:i:s T') . "\n\n"
                           . "Manage via Site administration > Server > IP blocker.\n";

                $mail_sent = send_email($notify_email, $CFG->noreplyaddress, $subject, $body_text);

                if ($mail_sent) { cli_writeln("Successfully sent notification email."); }
                else { cli_error("Failed sending notification email. Check Moodle mail config/logs."); }
            } catch (Exception $e) {
                 cli_error("Error during email sending: " . $e->getMessage());
            }
        }
    } else { cli_writeln("Email notification skipped."); }

    exit(0);

} else {
    cli_error("Failed updating 'blockedip' list configuration for {$ip_to_block}.");
    exit(1);
}