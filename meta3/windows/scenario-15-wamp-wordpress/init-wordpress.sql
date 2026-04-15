-- Seed the WordPress 4.7.1 database with weak admin:admin credentials.
-- The password hash below is WordPress's phpass hash for the literal string "admin".
CREATE DATABASE IF NOT EXISTS wordpress CHARACTER SET utf8;
CREATE USER IF NOT EXISTS 'wpuser'@'localhost' IDENTIFIED BY 'wppass';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'localhost';
FLUSH PRIVILEGES;

USE wordpress;

CREATE TABLE IF NOT EXISTS wp_users (
    ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    user_login varchar(60) NOT NULL DEFAULT '',
    user_pass varchar(255) NOT NULL DEFAULT '',
    user_nicename varchar(50) NOT NULL DEFAULT '',
    user_email varchar(100) NOT NULL DEFAULT '',
    user_registered datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
    user_status int(11) NOT NULL DEFAULT 0,
    display_name varchar(250) NOT NULL DEFAULT '',
    PRIMARY KEY (ID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_registered, display_name)
VALUES ('admin', '$P$B7pR5tG5cPz5cGhqg4/8PmMnYsaKp6/', 'admin', 'admin@example.com', NOW(), 'admin');
