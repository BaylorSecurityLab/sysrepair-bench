#!/bin/bash
# Boot wrapper (kept via .preserve-cmd): start the vulnerable services, then hand
# PID 1 to `sleep infinity` so an agent can restart Apache/MySQL without killing
# the container (and so "fixed config but never restarted" is detectable).
service mysql start
apache2ctl start 2>/dev/null || service apache2 start
exec sleep infinity
