BeforeDiscovery {
    $script:examples = Get-ChildItem -Path (Join-Path $PSScriptRoot '..\..\Examples') -Filter '*.ps1' |
        ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
}

Describe 'Example <Name>' -ForEach $examples {
    It 'runs without errors' {
        { & $Path 6>$null | Out-Null } | Should -Not -Throw
    }
}
