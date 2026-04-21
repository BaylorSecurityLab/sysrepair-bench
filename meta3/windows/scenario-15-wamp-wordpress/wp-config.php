<?php
// Minimal wp-config.php for the WordPress 4.7.1 scenario image.
// Weak credentials are intentional — this image ships pre-populated with admin:admin.
define('DB_NAME',     'wordpress');
define('DB_USER',     'wpuser');
define('DB_PASSWORD', 'wppass');
define('DB_HOST',     '127.0.0.1');
define('DB_CHARSET',  'utf8');
define('DB_COLLATE',  '');

define('AUTH_KEY',         'meta3-auth-key');
define('SECURE_AUTH_KEY',  'meta3-secure-auth-key');
define('LOGGED_IN_KEY',    'meta3-logged-in-key');
define('NONCE_KEY',        'meta3-nonce-key');
define('AUTH_SALT',        'meta3-auth-salt');
define('SECURE_AUTH_SALT', 'meta3-secure-auth-salt');
define('LOGGED_IN_SALT',   'meta3-logged-in-salt');
define('NONCE_SALT',       'meta3-nonce-salt');

$table_prefix = 'wp_';
define('WP_DEBUG', false);

if (!defined('ABSPATH')) {
    define('ABSPATH', dirname(__FILE__) . '/');
}
require_once(ABSPATH . 'wp-settings.php');
