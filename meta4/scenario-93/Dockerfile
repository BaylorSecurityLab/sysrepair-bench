FROM --platform=linux/amd64 jupyter/base-notebook:python-3.10

# Jupyter Notebook (python-3.10) — No token/password authentication.
# When started with --NotebookApp.token='' and no password, the notebook
# server is fully accessible to any network client — enabling unauthenticated
# arbitrary code execution on the container host.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

USER $NB_UID

EXPOSE 8888

CMD ["start-notebook.sh", \
     "--NotebookApp.token=''", \
     "--NotebookApp.password=''", \
     "--ip=0.0.0.0"]
