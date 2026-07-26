function Test-ImageChecksums {
    <#
    .SYNOPSIS
    Verifies every image listed in IMAGES.md against its recorded SHA256.

    .DESCRIPTION
    Parses markdown table rows of the form:  | <filename> | SHA256 | <hash> |
    Throws on any mismatch or missing file. Reviewers run this to confirm they
    hold the same artifacts the benchmark was built against.

    .EXAMPLE
    Test-ImageChecksums -ManifestPath .\lab\IMAGES.md -ImageDir 'C:\LabSources\ISOs'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ManifestPath,
        [Parameter(Mandatory)] [string] $ImageDir
    )

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "Test-ImageChecksums: manifest '$ManifestPath' not found"
    }

    $row     = [regex] '^\|\s*([^\s|]+)\s*\|\s*SHA256\s*\|\s*([0-9a-fA-F]{64})\s*\|'
    $checked = 0

    foreach ($line in (Get-Content -LiteralPath $ManifestPath)) {
        $m = $row.Match($line)
        if (-not $m.Success) { continue }

        $name     = $m.Groups[1].Value
        $expected = $m.Groups[2].Value.ToUpperInvariant()
        $path     = Join-Path $ImageDir $name

        if (-not (Test-Path -LiteralPath $path)) {
            throw "Test-ImageChecksums: '$name' is listed in the manifest but not present in $ImageDir"
        }

        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actual -ne $expected) {
            throw "Test-ImageChecksums: '$name' hash mismatch`n  expected $expected`n  actual   $actual"
        }
        $checked++
    }

    if ($checked -eq 0) {
        throw "Test-ImageChecksums: no SHA256 rows found in $ManifestPath. Placeholder rows (<fill in>) do not count -- record the real hashes."
    }

    Write-Host "[images] verified $checked artifact(s)"
    return $true
}
