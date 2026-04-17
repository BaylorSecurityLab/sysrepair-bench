# Apache Airflow 1.10.10 — Example DAGs Command Injection (CVE-2020-11978)

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CVE-2020-11978
- CWE-94: Improper Control of Generation of Code ('Code Injection')

## Description
Apache Airflow 1.10.10 ships with `load_examples = True` in `airflow.cfg`,
which loads a set of built-in example DAGs at startup. One of these,
`example_trigger_target_dag`, contains a `BashOperator` task that executes
the value of a `message` parameter without any sanitisation. An authenticated
attacker (or any user granted DAG trigger permissions) can trigger this DAG
with a crafted `conf` JSON payload and achieve arbitrary OS command execution
on the Airflow worker:

```
POST /api/experimental/dags/example_trigger_target_dag/dag_runs
{"conf": {"message": "$(id > /tmp/pwned)"}}
```

The impact is full remote code execution on the Airflow worker with the
privileges of the `airflow` OS user.

## Affected Service
- **Service:** Apache Airflow 1.10.10
- **Port:** 8080/TCP
- **Vulnerable configuration:** `load_examples = True` in `airflow.cfg`

## Vulnerable Configuration
- `load_examples = True` in the `[core]` section of `airflow.cfg` — ships as default

## Remediation Steps
1. Set `load_examples = False` in the `[core]` section of `$AIRFLOW_HOME/airflow.cfg`:
   ```ini
   [core]
   load_examples = False
   ```
2. Restart the Airflow webserver and scheduler to apply the change.
3. Optionally, delete any already-loaded example DAG files from the `dags/` folder.
4. Verify no example DAGs appear in the Airflow UI.
5. Confirm the webserver still responds on `http://localhost:8080`.
