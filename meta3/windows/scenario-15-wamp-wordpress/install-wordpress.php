<?php
// Bootstraps WordPress 4.7.1's own installer to populate the full schema
// (wp_options / wp_posts / wp_postmeta / etc.) and create the 'admin' user
// with the password 'admin'. Intended to be run once during docker build,
// after MariaDB is up and the empty 'wordpress' database + 'wpuser' grant
// have been seeded by init-wordpress.sql.
//
// Usage:  php.exe C:\install-wordpress.php

define('ABSPATH', 'C:/wamp/www/wordpress/');
define('WPINC', 'wp-includes');
define('WP_INSTALLING', true);

$_SERVER['HTTP_HOST']    = 'localhost';
$_SERVER['REQUEST_URI']  = '/';
$_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.0';
$_SERVER['SERVER_NAME']  = 'localhost';

require ABSPATH . 'wp-load.php';
require ABSPATH . 'wp-admin/includes/upgrade.php';

if ( is_blog_installed() ) {
    echo "already installed\n";
    exit(0);
}

$result = wp_install(
    'Meta3 WordPress',          // blog_title
    'admin',                    // user_name
    'admin@example.com',        // user_email
    true,                       // public
    '',                         // deprecated
    'admin'                     // user_password
);

echo "installed user_id=" . $result['user_id'] . "\n";
