function Get-ScenarioToolPaths {
    <#
    .SYNOPSIS
    Extracts every external tool a verify-poc.sh invokes.

    .DESCRIPTION
    Two forms are recognised: absolute paths under /usr/bin, /usr/local/bin or
    /opt, and bare commands guarded by `command -v`. The shebang is skipped --
    it is an interpreter, not a scenario dependency.

    This exists because provision/attacker-baseline.sh symlinked tools into
    /usr/local/bin while every verify-poc.sh calls /usr/bin, and certipy-ad was
    never symlinked at all because the guard tested for a console-script name
    pip does not create. The result was scenarios 07-10 grading a PASS on an
    unmodified vulnerable box. This function makes that class of defect
    mechanically detectable.

    .EXAMPLE
    Get-ScenarioToolPaths -ScenarioRoot ./meta4/ad-vm | Sort-Object Path -Unique
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ScenarioRoot
    )

    $absolute = [regex] '(?<![\w/])(/(?:usr/local/bin|usr/bin|opt)/[A-Za-z0-9._-]+)'
    $commandV = [regex] 'command\s+-v\s+([A-Za-z0-9._-]+)'
    $results  = New-Object System.Collections.Generic.List[object]

    Get-ChildItem -Path $ScenarioRoot -Filter 'verify-poc.sh' -Recurse -File | ForEach-Object {
        $scenario = Split-Path (Split-Path $_.FullName -Parent) -Leaf
        $seen     = New-Object System.Collections.Generic.HashSet[string]
        $lineNo   = 0

        foreach ($line in (Get-Content -LiteralPath $_.FullName)) {
            $lineNo++
            if ($lineNo -eq 1 -and $line.StartsWith('#!')) { continue }

            foreach ($m in $absolute.Matches($line)) {
                if ($seen.Add($m.Groups[1].Value)) {
                    $results.Add([pscustomobject]@{
                        Scenario = $scenario
                        Path     = $m.Groups[1].Value
                        Line     = $lineNo
                    })
                }
            }
            foreach ($m in $commandV.Matches($line)) {
                if ($seen.Add($m.Groups[1].Value)) {
                    $results.Add([pscustomobject]@{
                        Scenario = $scenario
                        Path     = $m.Groups[1].Value
                        Line     = $lineNo
                    })
                }
            }
        }
    }

    return $results.ToArray()
}
