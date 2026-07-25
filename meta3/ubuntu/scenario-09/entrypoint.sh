#!/bin/bash
# Boot MySQL + Apache (Drupal 7.5, jQuery 1.4.4) then hand PID 1 to `sleep infinity`, so the stack
# is already running when the agent starts AND reloading Apache cannot kill the
# container. Do NOT `exec apache2ctl -D FOREGROUND` (that makes Apache PID 1 and
# a restart would destroy the eval sample). See .preserve-cmd.
#
# NB: no `set -u` here - sourcing /etc/apache2/envvars references vars that may
# be unset, which under `set -u` would abort the whole entrypoint.

service mysql start || /usr/bin/mysqld_safe &
for _ in $(seq 1 30); do
    mysqladmin ping >/dev/null 2>&1 && break
    sleep 1
done

source /etc/apache2/envvars 2>/dev/null || true
apache2ctl start 2>/dev/null || service apache2 start 2>/dev/null || true

exec sleep infinity
