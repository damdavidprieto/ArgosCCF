BeforeAll {
    $root = Join-Path $PSScriptRoot '../..'
    $manifest = Import-PowerShellDataFile -Path (Join-Path $root 'ArgosCCF.psd1')
    $reference = Get-Content -Path (Join-Path $root 'Docs/API-Reference.md') -Raw -Encoding UTF8
}

Describe 'Docs/API-Reference.md' {
    It 'documents every function and alias (regenerate with Docs/New-ApiReference.ps1)' {
        $names = @($manifest.FunctionsToExport + $manifest.AliasesToExport)
        @($names | Where-Object { $reference -notmatch [regex]::Escape("``$_``") }) -join ', ' | Should -BeNullOrEmpty
    }
}
