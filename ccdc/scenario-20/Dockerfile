FROM ubuntu:25.10
# Scenario 20: WordPress file editor enabled
# CWE-94: Improper Control of Generation of Code (Code Injection)
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 php libapache2-mod-php php-mysql curl wget && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Download and set up WordPress (simulated with key config files)
RUN mkdir -p /var/www/html/wp-content/themes /var/www/html/wp-content/plugins /var/www/html/wp-admin && \
    echo '<?php echo "WordPress running"; ?>' > /var/www/html/index.php

# Create wp-config.php WITHOUT DISALLOW_FILE_EDIT (vulnerable)
RUN cat > /var/www/html/wp-config.php <<'WPEOF'
<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'wppass');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');

define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');
define('AUTH_SALT',        'put your unique phrase here');
define('SECURE_AUTH_SALT', 'put your unique phrase here');
define('LOGGED_IN_SALT',   'put your unique phrase here');
define('NONCE_SALT',       'put your unique phrase here');

$table_prefix = 'wp_';
define('WP_DEBUG', false);

if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}
WPEOF

RUN chown -R www-data:www-data /var/www/html && chmod 644 /var/www/html/wp-config.php


EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]
