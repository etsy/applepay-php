--TEST--
Check for applepay presence
--SKIPIF--
<?php if (!extension_loaded("applepay")) print "skip"; ?>
--FILE--
<?php 
echo "applepay extension is available";
--EXPECT--
applepay extension is available
