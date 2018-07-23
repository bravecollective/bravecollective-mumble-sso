<?php
define('GUEST', 23);

if (PHP_SAPI != 'cli') {
    die("nope!");
}

include_once('../webroot/config.php');
include_once('../webroot/helper.php');

if (!isset($argv[1])) {
    echo 'No character id given';
    exit(1);
}

$characterIdentifier = (int)$argv[1];

$result = update_character($characterIdentifier);

if (!$result) {
    echo 'Something went wrong';
    exit(1);
}

echo 'Update OK';
exit(0);

