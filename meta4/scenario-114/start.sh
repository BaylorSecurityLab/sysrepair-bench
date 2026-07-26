#!/bin/bash
# Boot wrapper (paired with .preserve-cmd): start the Apache (Cacti sim) backend
# on 0.0.0.0:8080, then exec `sleep infinity` so PID 1 is the sleep and the
# vulnerable remote_agent.php surface is already reachable when the agent starts.
# NOT a bare foreground process (the old `exec "$@"` with an empty CMD made PID 1
# exit and killed the container).
set -u
service apache2 start || apache2ctl start || true
exec sleep infinity
