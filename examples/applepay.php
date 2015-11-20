#!/usr/bin/env php
<?php

// Get params
$opt = getopt('c:d:hp:t:');
if (isset($opt['h'])
    || !isset($opt['p'])
    || !isset($opt['c'])
    || !file_exists($opt['c'])
) {
    echo "Usage: php {$_SERVER['PHP_SELF']} [options]\n\n" .
        "Options:\n" .
        "    -c <path>  Path to file containing payment token\n" .
        "    -d <secs>  Max time difference in seconds (default: 60)\n" .
        "    -h         Show help\n" .
        "    -p <pass>  Specify private key password\n" .
        "    -t <unix>  Transaction time (default: now)\n";
    die();
}

// Try to load extension if not already available
if (!extension_loaded('applepay')) {
    dl('applepay.' . PHP_SHLIB_SUFFIX);
}

// Parse cryptogram
$cryptogram = trim(file_get_contents($opt['c']));
$cryptogram = str_replace(' ', '', $cryptogram);
$cryptogram = pack("H*", $cryptogram);
$cryptogram = json_decode($cryptogram, true);

// Set args
$merch_privkey = base64_encode(file_get_contents(__DIR__ . '/priv.p12'));
$merch_privkey_pass = $opt['p'];
$merch_pubkey = __DIR__ . '/pub.pem';
$merch_cert = __DIR__ . '/merch.cer';
$int_cert = __DIR__ . '/int.cer';
$root_cert = __DIR__ . '/root.cer';
$txn_time = isset($opt['t']) ? (int)$opt['t'] : time();
$max_time_diff = isset($opt['d']) ? (int)$opt['d'] : 60;

$res = applepay_verify_and_decrypt($cryptogram, $merch_pubkey, $merch_privkey, $merch_privkey_pass, $merch_cert, $int_cert, $root_cert, $max_time_diff, $txn_time);
if ($res === false) {
    $consts = get_defined_constants(true)['applepay'];
    var_dump(applepay_last_error());
    var_dump(array_search(applepay_last_error(), $consts));
} else {
    var_dump($res);
    printf("res=%s\n\njson_decoded=%s\n", $res, print_r(json_decode($res, true), true));
}
