BeforeDiscovery {
    $script:examples = Get-ChildItem -Path (Join-Path $PSScriptRoot '..\..\Examples') -Filter '*.ps1' |
        ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
}

Describe 'Example <Name>' -ForEach $examples {
    BeforeAll {
        $configs = Join-Path $PSScriptRoot '..\..\Configs'
        $plugins = Join-Path $PSScriptRoot '..\..\Plugins'
        $before = @(Get-ChildItem $configs, $plugins -Recurse -File | ForEach-Object FullName)
    }

    It 'runs without errors' {
        { & $Path 6>$null | Out-Null } | Should -Not -Throw
    }

    It 'leaves no files behind in Configs or Plugins' {
        $after = @(Get-ChildItem $configs, $plugins -Recurse -File | ForEach-Object FullName)
        $after | Where-Object { $_ -notin $before } | Should -BeNullOrEmpty
    }
}
