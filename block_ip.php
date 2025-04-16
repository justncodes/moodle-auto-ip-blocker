<?php
// This script is designed to be run from the command line.

define('CLI_SCRIPT', true);
error_reporting(E_ALL & ~E_DEPRECATED); // Suppressing deprecation notices
// ini_set('display_errors', 'stderr'); // Disables direct error display if needed

// --- Setup ---
$scriptpath = dirname(__FILE__);
$moodleroot = dirname(dirname(dirname($scriptpath)));
$configfile = $moodleroot . '/config.php';

if (!file_exists($configfile)) { $configfile = '/var/www/html/moodle/config.php'; }
if (!file_exists($configfile)) { fwrite(STDERR, "ERROR: Moodle config not found.\n"); exit(1); }
if (!is_readable($configfile)) { fwrite(STDERR, "ERROR: Moodle config not readable.\n"); exit(1); }

require_once($configfile);

if (!isset($CFG) || !is_object($CFG) || !isset($CFG->libdir) || !isset($CFG->dirroot) || !isset($CFG->wwwroot)) {
    fwrite(STDERR, "ERROR: \$CFG object not loaded correctly from config or missing wwwroot.\n");
    exit(1);
}

require_once($CFG->libdir.'/clilib.php');
require_once($CFG->libdir.'/adminlib.php');

$phpmailer_base = $CFG->dirroot . '/lib/phpmailer/src/';
$phpmailer_path = $phpmailer_base . 'PHPMailer.php';
$phpmailer_smtp_path = $phpmailer_base . 'SMTP.php';
$phpmailer_exception_path = $phpmailer_base . 'Exception.php';

if (!file_exists($phpmailer_path) || !file_exists($phpmailer_smtp_path) || !file_exists($phpmailer_exception_path)) {
     fwrite(STDERR, "ERROR: Could not find required PHPMailer files in {$phpmailer_base}\n");
     exit(1);
}
require($phpmailer_path);
require($phpmailer_smtp_path);
require($phpmailer_exception_path);

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception as PHPMailerException;


// --- Parse CLI options ---
$cli_options_definition = [
    'ip'           => false,
    'notify-email' => false,
    'help'         => true,
];
$cli_short_options = ['h' => 'help'];

list($options, $unrecognised) = cli_get_params($cli_options_definition, $cli_short_options);

if ($unrecognised) {
    $unrecognised_str = implode("\n  ", $unrecognised);
    $errormsg = function_exists('get_string') ? get_string('cliunknowoption', 'admin', $unrecognised_str) : "Unrecognised options:\n  " . $unrecognised_str;
    cli_error($errormsg);
}

$help_requested = false;
global $argv;
if (is_array($argv)) {
    foreach ($argv as $arg) {
        if ($arg === '-h' || $arg === '--help') {
            $help_requested = true;
            break;
        }
    }
}

if ($help_requested || !isset($options['ip']) || $options['ip'] === '' || $options['ip'] === false) {
    $help = <<<EOT
Add IP to Moodle 'blockedip' list and optionally send notification.

Options:
  --ip=IP_ADDRESS        The IP address to block. (Required)
  --notify-email=EMAIL   Email address to send notification to.
  -h, --help             Show this help message.
EOT;
    echo $help;
    exit(0);
}

$ip_to_block = trim($options['ip']);
$notify_email = isset($options['notify-email']) ? trim($options['notify-email']) : '';


if (!filter_var($ip_to_block, FILTER_VALIDATE_IP)) { cli_error("Invalid IP address format: '{$ip_to_block}'"); exit(1); }
if (!empty($notify_email) && !filter_var($notify_email, FILTER_VALIDATE_EMAIL)) {
     cli_writeln("WARNING: Invalid --notify-email format: '{$notify_email}'. Notification will be skipped.");
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

$set_config_result = set_config('blockedip', $new_list_string);

if ($set_config_result === true) {
    cli_writeln("Successfully added {$ip_to_block} to 'blockedip' list.");

    try {
        if (class_exists('cache', false)) {
             cache::make('core', 'config')->purge();
             cli_writeln("Purged core config cache.");
        } else {
             cli_writeln("WARNING: Cache API potentially unavailable, skipping purge.");
        }
    } catch (Throwable $e) {
        cli_writeln("WARNING: Cache purge failed: " . $e->getMessage());
    }

    if (!empty($notify_email)) {
        cli_writeln("Attempting notification to {$notify_email} via PHPMailer...");

        if (empty($CFG->noreplyaddress)) {
             cli_writeln("WARNING: Moodle 'noreplyaddress' not set. Using default 'noreply@hostname'.");
             $hostname = php_uname('n');
             $fromaddress = 'noreply@' . ($hostname ?: 'localhost');
        } else {
            $fromaddress = $CFG->noreplyaddress;
        }

        $mail = new PHPMailer(true);

        try {
            // Server settings
            if (empty($CFG->smtphosts)) {
                 $mail->isMail();
            } else {
                 $mail->isSMTP();
                 $mail->Host = $CFG->smtphosts;
                if (!empty($CFG->smtpuser)) {
                    $mail->SMTPAuth = true;
                    $mail->Username = $CFG->smtpuser;
                    $mail->Password = isset($CFG->smtppass) ? $CFG->smtppass : '';
                    if (empty($mail->Password) && $mail->SMTPAuth) {
                         cli_writeln("WARNING: smtpuser set but smtppass is empty or not found in \$CFG.");
                    }
                } else {
                    $mail->SMTPAuth = false;
                }
                if (!empty($CFG->smtpsecure)) { $mail->SMTPSecure = strtolower($CFG->smtpsecure); }
                else { $mail->SMTPSecure = ''; }
                if (!empty($CFG->smtpport)) { $mail->Port = (int)$CFG->smtpport; }

                 $mail->SMTPOptions = [
                     'ssl' => [
                         'verify_peer' => false,
                         'verify_peer_name' => false,
                         'allow_self_signed' => true
                     ]
                 ];
            }

            // Recipients
            $fromname = get_config('moodle', 'sitename') ?: 'Moodle System';
            $mail->setFrom($fromaddress, $fromname);
            $mail->addAddress($notify_email);

            // Content
            $mail->isHTML(false); // Send as plain text
            $sitename = get_config('moodle', 'sitename') ?: 'Moodle Site';
            $mail->Subject = $sitename . ' :: Banned IP notification';

            $ipblocker_url = rtrim($CFG->wwwroot, '/') . '/admin/settings.php?section=ipblocker';
            $mail->Body    = "IP address automatically added to Moodle block list:\n\n"
                           . "IP Address: {$ip_to_block}\n\n"
                           . "Timestamp: " . date('Y-m-d H:i:s T') . "\n\n"
                           . "Manage via Site administration > General > Security > IP blocker\n"
                           . "Direct Link: {$ipblocker_url}\n";
            $mail->CharSet = 'UTF-8';

            $mail->send();
            cli_writeln("Successfully sent notification email via PHPMailer.");

        } catch (PHPMailerException $e) {
            cli_error("PHPMailer failed to send email: {$mail->ErrorInfo}");
        } catch (\Throwable $e) {
            cli_error("PHP Error/Exception during email sending process: " . $e->getMessage());
            cli_error("File: " . $e->getFile() . " Line: " . $e->getLine());
        }
    } else { cli_writeln("Email notification skipped."); }

    exit(0);

} else {
    cli_error("Failed updating 'blockedip' list configuration for {$ip_to_block} (set_config returned false).");
    exit(1);
}