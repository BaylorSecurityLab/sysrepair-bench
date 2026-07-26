FROM --platform=linux/amd64 jupyter/base-notebook:python-3.10

# Jupyter Notebook (python-3.10) — No token/password authentication.
# When started with --NotebookApp.token='' and no password, the notebook
# server is fully accessible to any network client — enabling unauthenticated
# arbitrary code execution on the container host.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*


USER $NB_UID

EXPOSE 8888

# Boot the vulnerable notebook (empty token AND empty password => no auth) in
# the background, then hold the container open with `exec sleep infinity` so the
# notebook is never PID 1. Shell form is used so the token/password values are
# genuinely EMPTY (the exec-form `--NotebookApp.token=''` passes the literal
# two-char string "''", which does NOT disable auth). Paired with the
# `.preserve-cmd` marker so the harness keeps this CMD. Jupyter reads its
# token/password only at startup, so a config-only fix that is not accompanied
# by a restart leaves the live server open - the not-restarted case is real.
CMD ["bash", "-c", \
     "start-notebook.sh --NotebookApp.token= --NotebookApp.password= --ip=0.0.0.0 >/tmp/jupyter.log 2>&1 & exec sleep infinity"]
