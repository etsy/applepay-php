#!/usr/bin/env php
<?php

// Set defaults
$merch_privkey = __DIR__ . '/priv.p12';
$merch_privkey_pass = '';
$merch_pubkey = __DIR__ . '/pub.pem';
$merch_cert = __DIR__ . '/merch.cer';
$int_cert = __DIR__ . '/int.cer';
$root_cert = __DIR__ . '/root.cer';
$token_json = __DIR__ . '/token.json';
$txn_time = $_SERVER['REQUEST_TIME'];
$max_time_diff = 60;

// Get params
$opt = getopt('ha:c:d:i:k:p:t:r:u:');
if (isset($opt['h'])) {
    echo "Usage: php {$_SERVER['PHP_SELF']} [options]\n\n" .
        "Options:\n" .
        "    -h         Show help\n" .
        "    -a <path>  Apple cert (default: $merch_cert)\n" .
        "    -c <path>  Payment token (default: $token_json)\n" .
        "    -k <path>  Private key (default: $merch_privkey)\n" .
        "    -p <pass>  Private key password\n" .
        "    -u <path>  Public key (default: $merch_pubkey)\n" .
        "    -r <path>  Apple root cert (default: $root_cert)\n" .
        "    -i <path>  Apple intermediate cert (default: $int_cert)\n" .
        "    -t <unix>  Transaction time (default: $txn_time)\n" .
        "    -d <secs>  Max time difference in seconds (default: $max_time_diff)\n";
    die();
} else {
    $merch_privkey = isset($opt['k']) ? $opt['k'] : $merch_privkey;
    $merch_privkey_pass = isset($opt['p']) ? $opt['p'] : $merch_privkey_pass;
    $merch_pubkey = isset($opt['u']) ? $opt['u'] : $merch_pubkey;
    $merch_cert = isset($opt['a']) ? $opt['a'] : $merch_cert;
    $int_cert = isset($opt['i']) ? $opt['i'] : $int_cert;
    $root_cert = isset($opt['r']) ? $opt['r'] : $root_cert;
    $token_json = isset($opt['c']) ? $opt['c'] : $token_json;
    $txn_time = isset($opt['t']) ? $opt['t'] : $txn_time;
    $max_time_diff = isset($opt['d']) ? $opt['d'] : $max_time_diff;
}

// Try to load extension if not already available
if (!extension_loaded('applepay')) {
    dl('applepay.' . PHP_SHLIB_SUFFIX);
}

// Parse cryptogram
$cryptogram = trim(file_get_contents($token_json));
$cryptogram = json_decode($cryptogram, true);

// Read privkey
$merch_privkey_str = base64_encode(file_get_contents($merch_privkey));

// Verify and decrypt
$res = applepay_verify_and_decrypt($cryptogram, $merch_pubkey, $merch_privkey_str, $merch_privkey_pass, $merch_cert, $int_cert, $root_cert, $max_time_diff, $txn_time);
if ($res === false) {
    $consts = get_defined_constants(true)['applepay'];
    $out = [
        'last_error_code' => applepay_last_error(),
        'last_error_str' => array_search(applepay_last_error(), $consts),
    ];
} else {
    $out = json_decode($res, true);
}
echo json_encode($out, JSON_PRETTY_PRINT) . PHP_EOL;
exit($res === false ? 1 : 0);
