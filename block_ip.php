<?php
// This script is designed to be run from the command line.

define('CLI_SCRIPT', true);
$configfile = '/var/www/html/moodle/config.php';
if (!file_exists($configfile)) { exit(1); }
require_once($configfile);
require_once($CFG->libdir.'/clilib.php');
require_once($CFG->libdir.'/adminlib.php');

// --- Parse command line options ---
list($options, $unrecognised) = cli_get_params(['ip' => '', 'help' => false], ['h' => 'help']);
if ($unrecognised) { cli_error(get_string('cliunknowoption', 'admin', implode("\n  ", $unrecognised))); }
if ($options['help'] || empty($options['ip'])) { /* Print help */ echo "Add IP to Moodle CORE 'blockedip' list.\nOptions: --ip=IP_ADDRESS\n"; exit(0); }

$ip_to_block = trim($options['ip']);
if (empty($ip_to_block)) { cli_error("IP address cannot be empty."); }

cli_heading('Moodle IP Blocker CLI (Core Setting: blockedip)');
cli_writeln("Attempting to block IP: " . $ip_to_block . " in CORE config ('blockedip')");

// Read the 'blockedip' setting
$blockedips_string = get_config(null, 'blockedip');

// Split the existing list (handle if it's null/empty)
$ip_list = preg_split('/[\s,]+/', $blockedips_string ?? '', -1, PREG_SPLIT_NO_EMPTY);

if (in_array($ip_to_block, $ip_list)) {
    cli_writeln("IP address {$ip_to_block} is already in the CORE 'blockedip' list.");
    exit(0);
}

// Add the new IP to the list
$ip_list[] = $ip_to_block;
$new_list_string = implode("\n", $ip_list);

// Save the updated list back to the 'blockedip' setting
if (set_config('blockedip', $new_list_string)) { 
    cli_writeln("Successfully added {$ip_to_block} to the CORE Moodle 'blockedip' list.");
    try {
        $cache = cache::make('core', 'config');
        $cache->purge();
        cli_writeln("Purged core config cache.");
    } catch (Exception $e) {
        cli_writeln("Could not purge core config cache automatically: " . $e->getMessage());
    }
    exit(0);
} else {
    cli_error("Failed to update the CORE Moodle 'blockedip' list configuration for {$ip_to_block}.");
    exit(1);
}