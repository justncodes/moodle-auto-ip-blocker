<?php
// This script is designed to be run from the command line.

define('CLI_SCRIPT', true);
error_reporting(E_ALL & ~E_DEPRECATED);
// ini_set('display_errors', 'stderr');

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
    'ips'          => false,
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

// --- Check for --ips instead of --ip ---
if ($help_requested || !isset($options['ips']) || $options['ips'] === '' || $options['ips'] === false) {
    $help = <<<EOT
Adds a list of IPs to Moodle 'blockedip' list and optionally sends notification.

Options:
  --ips=IP1,IP2,...    Comma-separated list of IP addresses to block. (Required)
  --notify-email=EMAILS Comma-separated list of email addresses to notify.
  -h, --help            Show this help message.
EOT;
    echo $help;
    exit(0);
}

// --- Process list of IPs ---
$ips_string_to_block = trim($options['ips']);
$ips_to_block = [];
if (!empty($ips_string_to_block)) {
    $ip_candidates = explode(',', $ips_string_to_block);
    foreach ($ip_candidates as $ip_candidate) {
        $trimmed_ip = trim($ip_candidate);
        if (filter_var($trimmed_ip, FILTER_VALIDATE_IP)) {
            $ips_to_block[] = $trimmed_ip;
        } else if (!empty($trimmed_ip)) {
            cli_writeln("WARNING: Invalid IP address format in list: '{$trimmed_ip}'. Skipping this IP.");
        }
    }
}

if (empty($ips_to_block)) {
     cli_error("ERROR: No valid IP addresses provided in the --ips list.");
     exit(1);
}

$notify_email_string = isset($options['notify-email']) ? trim($options['notify-email']) : '';

// Split and validate notification emails
$valid_recipient_emails = [];
if (!empty($notify_email_string)) {
    $email_candidates = explode(',', $notify_email_string);
    foreach ($email_candidates as $email_candidate) {
        $trimmed_email = trim($email_candidate);
        if (filter_var($trimmed_email, FILTER_VALIDATE_EMAIL)) {
            $valid_recipient_emails[] = $trimmed_email;
        } else if (!empty($trimmed_email)) {
            cli_writeln("WARNING: Invalid email format in list: '{$trimmed_email}'. Skipping this recipient.");
        }
    }
}
if (empty($valid_recipient_emails) && !empty($notify_email_string)) {
     cli_writeln("WARNING: No valid email addresses found in --notify-email list. Notification will be skipped.");
}


// --- Main Logic ---
cli_heading("Moodle IP Blocker CLI ('blockedip') - Bulk Mode");
cli_writeln("Processing " . count($ips_to_block) . " IP(s): " . implode(', ', $ips_to_block));

// Get current list once
$blockedips_string = get_config(null, 'blockedip');
$current_ip_list = preg_split('/[\s,]+/', $blockedips_string ?? '', -1, PREG_SPLIT_NO_EMPTY);
$current_ip_list = array_map('trim', $current_ip_list);
$current_ip_list = array_filter($current_ip_list);
$current_ip_set = array_flip($current_ip_list);

$ips_actually_added = [];
$needs_update = false;

// Loop through IPs to block
foreach ($ips_to_block as $ip_to_add) {
    if (!isset($current_ip_set[$ip_to_add])) {
        $current_ip_list[] = $ip_to_add;
        $ips_actually_added[] = $ip_to_add;
        $needs_update = true;
        cli_writeln("Marked IP {$ip_to_add} for blocking.");
    } else {
        cli_writeln("IP {$ip_to_add} already in 'blockedip' list. Skipping.");
    }
}

if (!$needs_update) {
     cli_writeln("No new IPs needed blocking from the provided list.");
     exit(0);
}

// Save the potentially updated list
$current_ip_list = array_unique($current_ip_list);
$new_list_string = implode("\n", $current_ip_list);
$set_config_result = set_config('blockedip', $new_list_string);

if ($set_config_result === true) {
    cli_writeln("Successfully updated 'blockedip' list in database config.");

    // Attempt cache purge
    try {
        if (class_exists('cache', false)) {
             cache::make('core', 'config')->purge();
             cli_writeln("Purged core config cache.");
        } else { cli_writeln("WARNING: Cache API potentially unavailable, skipping purge."); }
    } catch (Throwable $e) { cli_writeln("WARNING: Cache purge failed: " . $e->getMessage()); }

    // Send summary email if needed
    if (!empty($valid_recipient_emails) && !empty($ips_actually_added)) {
        cli_writeln("Attempting summary notification to " . count($valid_recipient_emails) . " recipient(s) via PHPMailer...");
        cli_writeln("Recipients: " . implode(', ', $valid_recipient_emails));
        cli_writeln("IPs added this run: " . implode(', ', $ips_actually_added));


        if (empty($CFG->noreplyaddress)) {
             cli_writeln("WARNING: Moodle 'noreplyaddress' not set. Using default 'noreply@hostname'.");
             $hostname = php_uname('n'); $fromaddress = 'noreply@' . ($hostname ?: 'localhost');
        } else { $fromaddress = $CFG->noreplyaddress; }

        $mail = new PHPMailer(true);

        try {
            // Server settings
            if (empty($CFG->smtphosts)) { $mail->isMail(); }
            else {
                 $mail->isSMTP(); $mail->Host = $CFG->smtphosts;
                if (!empty($CFG->smtpuser)) {
                    $mail->SMTPAuth = true; $mail->Username = $CFG->smtpuser;
                    $mail->Password = isset($CFG->smtppass) ? $CFG->smtppass : '';
                    if (empty($mail->Password) && $mail->SMTPAuth) { cli_writeln("WARNING: smtpuser set but smtppass is empty/not found."); }
                } else { $mail->SMTPAuth = false; }
                if (!empty($CFG->smtpsecure)) { $mail->SMTPSecure = strtolower($CFG->smtpsecure); }
                else { $mail->SMTPSecure = ''; }
                if (!empty($CFG->smtpport)) { $mail->Port = (int)$CFG->smtpport; }
                $mail->SMTPOptions = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true]];
            }

            // Recipients
            $fromname = get_config('moodle', 'sitename') ?: 'Moodle System';
            $mail->setFrom($fromaddress, $fromname);
            foreach ($valid_recipient_emails as $recipient_email) { $mail->addAddress($recipient_email); }

            // Content
            $mail->isHTML(false);
            $sitename = get_config('moodle', 'sitename') ?: 'Moodle Site';
            $mail->Subject = $sitename . ' :: IP Blocker Summary Notification';
            $ipblocker_url = rtrim($CFG->wwwroot, '/') . '/admin/settings.php?section=ipblocker';
            $mail->Body    = count($ips_actually_added) . " IP address(es) were automatically added to the Moodle block list:\n\n"
                           . implode("\n", $ips_actually_added) . "\n\n"
                           . "Timestamp: " . date('Y-m-d H:i:s T') . "\n\n"
                           . "Manage via Site administration > General > Security > IP blocker\n"
                           . "Direct Link: {$ipblocker_url}\n";
            $mail->CharSet = 'UTF-8';

            $mail->send();
            cli_writeln("Successfully sent summary notification email via PHPMailer.");

        } catch (PHPMailerException $e) {
            cli_error("PHPMailer failed to send summary email: {$mail->ErrorInfo}");
        } catch (\Throwable $e) {
            cli_error("PHP Error/Exception during summary email sending: " . $e->getMessage());
            cli_error("File: " . $e->getFile() . " Line: " . $e->getLine());
        }
    } else if (empty($ips_actually_added)) {
         cli_writeln("No new IPs were added in this run, notification skipped.");
    } else { cli_writeln("Email notification skipped (no valid recipients specified)."); }

    exit(0); // Overall Success

} else {
    cli_error("Failed updating 'blockedip' list configuration (set_config returned false).");
    exit(1); // Failure
}