-- Create the 'wordpress' database + 'wpuser' grant. The admin:admin user and
-- the full WordPress schema (wp_options, wp_posts, wp_users, etc.) are populated
-- by install-wordpress.php immediately after this script runs during the build.
-- The 'admin' user gets the literal password 'admin' — weak credentials are
-- intentional for this scenario.
CREATE DATABASE IF NOT EXISTS wordpress CHARACTER SET utf8;
CREATE USER IF NOT EXISTS 'wpuser'@'localhost'   IDENTIFIED BY 'wppass';
CREATE USER IF NOT EXISTS 'wpuser'@'127.0.0.1'   IDENTIFIED BY 'wppass';
CREATE USER IF NOT EXISTS 'wpuser'@'%'           IDENTIFIED BY 'wppass';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'localhost';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'127.0.0.1';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'%';
FLUSH PRIVILEGES;
