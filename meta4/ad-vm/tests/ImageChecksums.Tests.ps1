BeforeAll { . "$PSScriptRoot/../lab/Test-ImageChecksums.ps1" }

Describe 'Test-ImageChecksums' {
    It 'returns true when the file matches its recorded hash' {
        $f = Join-Path $TestDrive 'a.iso'
        Set-Content -LiteralPath $f -Value 'hello' -NoNewline
        $h = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
        $m = Join-Path $TestDrive 'IMAGES.md'
        Set-Content -LiteralPath $m -Value "| a.iso | SHA256 | $h |"
        Test-ImageChecksums -ManifestPath $m -ImageDir $TestDrive | Should -BeTrue
    }

    It 'throws when the file does not match' {
        $f = Join-Path $TestDrive 'b.iso'
        Set-Content -LiteralPath $f -Value 'hello' -NoNewline
        $m = Join-Path $TestDrive 'IMAGES.md'
        Set-Content -LiteralPath $m -Value "| b.iso | SHA256 | 0000000000000000000000000000000000000000000000000000000000000000 |"
        { Test-ImageChecksums -ManifestPath $m -ImageDir $TestDrive } | Should -Throw
    }

    It 'throws when a manifest entry has no corresponding file' {
        $m = Join-Path $TestDrive 'IMAGES.md'
        Set-Content -LiteralPath $m -Value "| missing.iso | SHA256 | 0000000000000000000000000000000000000000000000000000000000000000 |"
        { Test-ImageChecksums -ManifestPath $m -ImageDir $TestDrive } | Should -Throw
    }

    It 'throws when the manifest still holds placeholders rather than real hashes' {
        $m = Join-Path $TestDrive 'IMAGES.md'
        Set-Content -LiteralPath $m -Value "| some.iso | SHA256 | <fill in> |"
        { Test-ImageChecksums -ManifestPath $m -ImageDir $TestDrive } | Should -Throw
    }

    It 'ignores non-table prose in the manifest' {
        $f = Join-Path $TestDrive 'c.iso'
        Set-Content -LiteralPath $f -Value 'x' -NoNewline
        $h = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
        $m = Join-Path $TestDrive 'IMAGES.md'
        Set-Content -LiteralPath $m -Value @"
# Image provenance

Some explanatory prose that is not a table row.

| File | Alg | Hash |
|---|---|---|
| c.iso | SHA256 | $h |
"@
        Test-ImageChecksums -ManifestPath $m -ImageDir $TestDrive | Should -BeTrue
    }
}
