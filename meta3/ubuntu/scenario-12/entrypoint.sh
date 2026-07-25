#!/bin/bash
# Boot wrapper (kept via .preserve-cmd): start the WEBrick admin app in the
# background, then hand PID 1 to `sleep infinity` so the daemon is already
# running with the vulnerable 0.0.0.0 bind and an agent can restart it without
# killing the container.
#
# NOTE: the launcher lives in this file (not inline in CMD) so that PID 1's argv
# is just "/entrypoint.sh" -- otherwise `pkill -f admin_app.rb` (the documented
# restart) would match the docker-init PID 1 argv and destroy the container.
ruby /opt/admin_app.rb &
exec sleep infinity
