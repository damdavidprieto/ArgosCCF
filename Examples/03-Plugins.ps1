# Plugins: discovery, lifecycle hooks and the restricted (hardened) runspace.
# The example creates a plugin under Plugins and removes it at the end.
# Run from the repository: .\Examples\03-Plugins.ps1

Import-Module (Join-Path $PSScriptRoot '..\ArgosCCF.psd1') -Force

# The module ships two example plugins in Plugins/Examples.
Get-CCFPlugin | Format-Table Name, Version, Signed, Path -AutoSize | Out-Host

$hello = Get-CCFPlugin | Where-Object Name -EQ 'HelloWorld'
Invoke-CCFPlugin -Plugin $hello -Arguments @{ Name = 'ArgosCCF' } | Format-List | Out-Host

$pluginDir = Join-Path (Get-CCFPath -Target Plugins) 'ExampleTemp'
try {
    New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
    @{ Name = 'Totals'; Version = '1.0.0'; Author = 'Example'; Description = 'Adds numbers' } |
        ConvertTo-Json | Set-Content -Path (Join-Path $pluginDir 'ccf_plugin.json') -Encoding UTF8

    # Before-Execute and After-Execute are optional hooks. This plugin only uses language
    # features, so it also runs in the restricted runspace of -HardenedMode, where cmdlets
    # (including the ArgosCCF logging commands) are not available.
    @'
param($Arguments)

function Before-Execute { param($Arguments) $null = $Arguments.Numbers.Count }
function After-Execute { param($Result) $null = $Result }

$sum = 0
foreach ($n in $Arguments.Numbers) { $sum += $n }
@{ Count = $Arguments.Numbers.Count; Sum = $sum }
'@ | Set-Content -Path (Join-Path $pluginDir 'Totals.ps1') -Encoding UTF8

    $totals = Get-CCFPlugin | Where-Object Name -EQ 'Totals'
    $normal = Invoke-CCFPlugin -Plugin $totals -Arguments @{ Numbers = 1, 2, 3 }
    $hardened = Invoke-CCFPlugin -Plugin $totals -Arguments @{ Numbers = 4, 5, 6 } -HardenedMode
    Write-CCFLogInfo "Normal run: sum $($normal.Sum); hardened run: sum $($hardened.Sum)"

    # A plugin outside the Plugins folder is refused.
    $outside = [pscustomobject]@{ Name = 'Outside'; Path = (Join-Path ([IO.Path]::GetTempPath()) 'outside.ps1') }
    $null = Invoke-CCFPlugin -Plugin $outside
}
finally {
    Remove-Item -Path $pluginDir -Recurse -Force -ErrorAction SilentlyContinue
}
