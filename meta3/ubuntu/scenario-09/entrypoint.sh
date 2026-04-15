#!/bin/bash
service mysql start || /usr/bin/mysqld_safe &
exec /usr/sbin/apache2ctl -D FOREGROUND
