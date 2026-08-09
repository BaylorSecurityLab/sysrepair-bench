<#
.SYNOPSIS
    Open an SSH tunnel from this machine to a vLLM server running on a Delta
    compute node, via a Delta login node.

.DESCRIPTION
    Delta compute nodes accept no inbound connections from outside the cluster,
    so the only route to the vLLM port is a local forward that terminates on a
    login node. This script builds that forward and leaves it in the foreground.

    Port forwarding (-L) works fine in the Windows OpenSSH client. Only
    connection multiplexing (ControlMaster) is unsupported there, and this
    script does not need it -- you authenticate once, interactively, right here.

.PARAMETER Node
    Compute node hostname from the job output, e.g. gpuh200-01.

.PARAMETER Port
    Remote port vLLM is listening on, printed by vllm_serve.slurm.

.PARAMETER LocalPort
    Local port to bind. Defaults to 8001, matching inspect_eval/.env.

.PARAMETER User
    Delta username. Defaults to $env:DELTA_USER, else the current Windows user.

.EXAMPLE
    .\hpc\tunnel.ps1 -Node gpuh200-03 -Port 21847

.EXAMPLE
    # Then, in another terminal:
    #   curl.exe -s http://localhost:8001/v1/models -H "Authorization: Bearer <key>"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Node,
    [Parameter(Mandatory = $true)][int]$Port,
    [int]$LocalPort = 8001,
    [string]$User = $(if ($env:DELTA_USER) { $env:DELTA_USER } else { $env:USERNAME }),
    [string]$LoginNode = "dt-login01.delta.ncsa.illinois.edu"
)

$ErrorActionPreference = "Stop"

# Bind explicitly to loopback. Delta policy forbids sharing your login
# connection with others; a 0.0.0.0 bind would expose the model endpoint to
# anything that can reach this machine on the network.
$forward = "127.0.0.1:${LocalPort}:${Node}:${Port}"

Write-Host ""
Write-Host "  local  http://127.0.0.1:$LocalPort/v1" -ForegroundColor Cyan
Write-Host "  ->     $Node`:$Port  (via $LoginNode)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Duo will prompt below. Leave this window open for the run." -ForegroundColor Yellow
Write-Host "  Ctrl-C closes the tunnel." -ForegroundColor Yellow
Write-Host ""

# Pin the login node rather than the round-robin alias: the forward must
# survive for the life of the eval, and round-robin can land you elsewhere on
# reconnect. ServerAliveInterval keeps an idle tunnel from being dropped.
# PubkeyAuthentication=no is not optional. Delta disables key auth for general
# users, so any local keys get offered and rejected first; the server counts
# each rejection against MaxAuthTries and disconnects with "Too many
# authentication failures" before the password prompt is ever shown.
& ssh -N `
    -L $forward `
    -o PubkeyAuthentication=no `
    -o IdentitiesOnly=yes `
    -o PreferredAuthentications=keyboard-interactive,password `
    -o NumberOfPasswordPrompts=1 `
    -o ServerAliveInterval=60 `
    -o ServerAliveCountMax=3 `
    -o ExitOnForwardFailure=yes `
    "$User@$LoginNode"
