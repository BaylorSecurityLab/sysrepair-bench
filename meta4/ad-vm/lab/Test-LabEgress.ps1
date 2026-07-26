function Test-LabEgress {
    <#
    .SYNOPSIS
    Asserts the AD segment has no route to the internet.

    .DESCRIPTION
    Measured from inside attacker01, not inferred from the switch type. An ICS
    bridge, a second adapter or a stray host route can all silently provide
    egress that a claim about "Internal switch" would miss.

    FAILS CLOSED. The first draft of this function returned $true whenever ssh
    itself was broken: a non-three-digit result skipped the throw, and the DNS
    check then captured ssh's own error text via 2>&1 and found it non-empty.
    "Isolated" would be reported when the probe had never run. Every step below
    therefore gates on an explicit RC= marker emitted by the remote shell.
    #>
    [CmdletBinding()]
    param(
        [string] $AttackerHost = '10.20.30.10',
        [string] $AttackerUser = 'vagrant',
        [string] $KeyPath      = (Join-Path $HOME '.ssh\srb_attacker')
    )

    $script = @'
if ! command -v curl >/dev/null 2>&1; then echo "PROBE=nocurl"; exit 0; fi
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 https://example.com 2>/dev/null || echo "000")
echo "EGRESS=${code}"
if getent hosts corp-dc01.corp.local >/dev/null 2>&1; then echo "DNS=ok"; else echo "DNS=fail"; fi
echo "PROBE=complete"
'@

    $raw = ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=yes `
        -i $KeyPath "$AttackerUser@$AttackerHost" $script 2>&1 | Out-String
    $sshRc = $LASTEXITCODE

    if ($sshRc -ne 0) {
        throw "Test-LabEgress: ssh to $AttackerHost failed (rc=$sshRc). The isolation claim is UNVERIFIED, not confirmed.`n$raw"
    }

    if ($raw -notmatch 'PROBE=complete') {
        if ($raw -match 'PROBE=nocurl') {
            throw 'Test-LabEgress: curl is absent on attacker01, so egress could not be measured. Install curl; an unmeasurable probe is not a pass.'
        }
        throw "Test-LabEgress: probe did not run to completion. UNVERIFIED.`n$raw"
    }

    if ($raw -notmatch 'EGRESS=(\d{3})') {
        throw "Test-LabEgress: no EGRESS marker in probe output. UNVERIFIED.`n$raw"
    }
    $code = $Matches[1]

    if ($code -ne '000') {
        throw "Test-LabEgress: attacker01 reached the internet (HTTP $code). The AD segment is NOT isolated -- check for an ICS bridge, a second adapter, or a host route."
    }

    if ($raw -notmatch 'DNS=ok') {
        throw 'Test-LabEgress: corp-dc01.corp.local does not resolve from attacker01. The segment is isolated but non-functional.'
    }

    Write-Host '[egress] isolated: no internet egress, corp.local resolves'
    return $true
}
