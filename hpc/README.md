# Serving a model on NCSA Delta for SysRepair-Bench

The harness builds a Docker image per scenario. Delta provides Apptainer, not
Docker, so **the harness cannot run on Delta**. The split is fixed:

```
  your machine                          Delta
  ┌────────────────────────┐            ┌──────────────────────────┐
  │ Inspect + Docker       │            │ dt-login01               │
  │ scenario sandboxes     │            │   (ssh -L terminates)    │
  │                        │  tunnel    │        │                 │
  │ OPENAI_BASE_URL ───────┼───────────►│        ▼                 │
  │ localhost:8001/v1      │            │ gpuh200-NN               │
  └────────────────────────┘            │   vLLM, 4x H200, API key │
                                        └──────────────────────────┘
```

Only JSON inference traffic crosses the tunnel, so bandwidth is not a concern.

## Prerequisites

| | |
|---|---|
| Account | `accounts` on a login node → use the **Project** value as `--account` |
| Partition | `gpuH200x8` — 8 nodes system-wide, 48 hr cap, charge factor 3.0 |
| vLLM | `module avail vllm`, or `module help llmflux` (LLMFlux wraps vLLM) |
| Cache | Never `/u` — 100 GB quota. The script pins `HF_HOME` to `$SCRATCH`. |

## 1. Submit

```bash
sbatch --account=<your-project> hpc/vllm_serve.slurm
```

Start with the default small model. It proves the tunnel, the API key and the
Inspect wiring in a few minutes. A 397B checkpoint cannot finish loading inside
the 30-minute allocation on a cold cache — prove the path first, then raise
`--time` and switch models.

For Qwen3.5 once the path is proven:

```bash
VLLM_MODEL=Qwen/Qwen3.5-397B-A17B-FP8 \
VLLM_SERVED_NAME=qwen3.5-397b \
VLLM_EXTRA_ARGS="--language-model-only --reasoning-parser qwen3" \
  sbatch --account=<acct> --export=ALL --time=04:00:00 hpc/vllm_serve.slurm
```

`--language-model-only` skips the vision tower. SysRepair-Bench is text-only,
and on 4 GPUs that reclaimed memory is the difference between a usable KV cache
and none.

### Why `-dp 4 --enable-expert-parallel`, not `-tp 4`

vLLM [issue #34893](https://github.com/vllm-project/vllm/issues/34893) reports
`Qwen3.5-397B-A17B-FP8` failing on **exactly** 4× H200 with `-tp 4` — fused
linear layer sharding incompatibility — and `--enable-expert-parallel` alone did
not fix it. The upstream recipe only certifies `-tp 8`. Data-parallel attention
with expert-parallel MoE avoids the fused-linear TP path, so that is the
default here. `VLLM_PARALLEL_MODE=tp` switches back for models that shard cleanly.

## 2. Watch it

```bash
./hpc/status.sh          # or: watch -n 600 ./hpc/status.sh
```

Do not wait on job exit. vLLM can wedge during weight loading or after an OOM
while the allocation stays alive, so the health probe is the real signal.
`status.sh` exits 0 serving / 2 starting / 3 unhealthy / 4 gone.

## 3. Tunnel from your machine

`status.sh` prints the exact command. From PowerShell:

```powershell
.\hpc\tunnel.ps1 -Node gpuh200-03 -Port 21847 -User aorojo
```

Duo prompts once; leave the window open. Port forwarding works in the Windows
OpenSSH client — only `ControlMaster` multiplexing does not, and this does not
need it.

**Keep the bind on `127.0.0.1`.** Delta policy forbids sharing access via your
login connection; a `0.0.0.0` bind would expose the endpoint to your whole LAN.

## 4. Point Inspect at it

The API key is generated per job and lives in `~/.vllm_delta/conn_<jobid>.env`
on Delta (mode 0600). Copy it into `inspect_eval/.env`:

```
OPENAI_BASE_URL=http://localhost:8001/v1
OPENAI_API_KEY=<VLLM_API_KEY from the conn file>
INSPECT_EVAL_MAX_CONNECTIONS=<from step 5>
```

Smoke test before spending a GPU-hour on an eval:

```bash
curl -s http://localhost:8001/v1/models -H "Authorization: Bearer $KEY"
```

An unauthenticated request to that URL must return 401. If it returns the model
list, `--api-key` did not take effect — stop and fix it.

## 5. Tune concurrency

`INSPECT_EVAL_MAX_CONNECTIONS=4` leaves four H200s idle. Measure instead of guess:

```bash
python hpc/bench_concurrency.py \
  --base-url http://localhost:8001/v1 \
  --api-key "$KEY" --model qwen3.5-397b \
  --json hpc/concurrency.json
```

It sweeps concurrency with a sysrepair-shaped workload (~6k prompt tokens, ~300
completion tokens) and reports the knee — the smallest level reaching 95% of
peak throughput. Past the knee you buy queueing delay, not speed, which pushes
samples toward the per-sample `time_limit` for no gain.

## Security notes

- The API key is a fresh 24-byte random token per job; it never leaves the
  conn file, which is written `0600` under a `0700` directory.
- vLLM binds `0.0.0.0` because the tunnel terminates on the login node and must
  reach the compute node over the cluster network. Compute nodes are not
  publicly routable; the key is the control on top of that.
- The port is derived from the job ID into the 20000–40000 range, so concurrent
  jobs never collide and the endpoint is not sitting on a guessable 8000.
- NCSA runs port scanners. A vLLM server on an internal interface is ordinary,
  but do not widen the bind or forward the port onward to anyone else.
