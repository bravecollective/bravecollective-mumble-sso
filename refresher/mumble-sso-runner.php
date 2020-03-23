<?php
define('GUEST', 23);

if (PHP_SAPI != 'cli') {
    die("nope!");
}

include_once '../webroot/config.php';
include_once '../webroot/helper.php';

while (true) {
    echo date('Y-m-d H:i:s') . " Refreshing characters....\n";
    character_refresh();
    fetchTicker(50);
    echo date('Y-m-d H:i:s') . " done. sleeping.\n";
    sleep(600);
}
?>
