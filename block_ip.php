<?php
// This script is designed to be run from the command line.

define('CLI_SCRIPT', true);

// Adjust the path to your Moodle config.php
require(__DIR__.'/../../../../config.php'); // Go up 4 levels from local/customscripts/cli/ to moodle root
require_once($CFG->libdir.'/clilib.php');
require_once($CFG->libdir.'/adminlib.php'); // Need this for set_config

// --- Parse command line options ---
list($options, $unrecognised) = cli_get_params(
    ['ip' => '', 'help' => false],
    ['h' => 'help']
);

if ($unrecognised) {
    $unrecognised = implode("\n  ", $unrecognised);
    cli_error(get_string('cliunknowoption', 'admin', $unrecognised));
}

if ($options['help'] || empty($options['ip'])) {
    $help = <<<EOS
Add an IP address to Moodle's built-in IP blocker list.

Options:
--ip=<ip_address>   The IP address (v4 or v6) or CIDR range to block. (Required)
-h, --help          Print this help.

Example:
\$ sudo -u www-data /usr/bin/php local/customscripts/cli/block_ip.php --ip=192.168.1.100
EOS;
    echo $help;
    exit(0);
}

$ip_to_block = trim($options['ip']);

// Basic validation
if (empty($ip_to_block)) {
     cli_error("IP address cannot be empty.");
}

cli_heading('Moodle IP Blocker CLI');
cli_writeln("Attempting to block IP: " . $ip_to_block);

// --- Core Logic ---
// Get the current list
$blockedips = get_config('tool_ipblocker', 'blockedips');
$ip_list = preg_split('/[\s,]+/', $blockedips ?? '', -1, PREG_SPLIT_NO_EMPTY); // Split by space, comma, newline etc.

// Check if already blocked
if (in_array($ip_to_block, $ip_list)) {
    cli_writeln("IP address {$ip_to_block} is already in the block list.");
    exit(0);
}

// Add the new IP
$ip_list[] = $ip_to_block;

// Join back into a string
$new_list_string = implode("\n", $ip_list);

// Save the updated list
if (set_config('blockedips', $new_list_string, 'tool_ipblocker')) {
    cli_writeln("Successfully added {$ip_to_block} to the Moodle IP block list.");
    // Purge caches related to config just in case
    \core\cache\config::purge_all();
    exit(0);
} else {
    cli_error("Failed to update the Moodle IP block list configuration for {$ip_to_block}.");
    exit(1);
}