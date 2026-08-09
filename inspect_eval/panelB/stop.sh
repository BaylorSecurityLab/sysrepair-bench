#!/bin/bash
docker rm -f pbvllm >/dev/null 2>&1 && echo "[stop] pbvllm removed" || echo "[stop] no pbvllm"
