# Layered configuration: factory defaults, presets and user overrides, plus schema validation.
# The example creates its files under Configs and removes them at the end.
# Run from the repository: .\Examples\02-Configuration.ps1

Import-Module (Join-Path $PSScriptRoot '..\ArgosCCF.psd1') -Force

$name = 'example_app'
$configs = Get-CCFPath -Target Configs
$files = @{
    Factory = Join-Path $configs "Factory/$name.json"
    Preset  = Join-Path $configs 'Presets/example_production.json'
    User    = Join-Path $configs "User/$name.json"
}

try {
    foreach ($folder in 'Factory', 'Presets', 'User') {
        New-Item -ItemType Directory -Path (Join-Path $configs $folder) -Force | Out-Null
    }

    # 1. Factory defaults, shipped with the application.
    @{ Database = @{ Host = 'localhost'; Port = 5432; SSL = $false }; Features = @{ Cache = $true } } |
        ConvertTo-Json -Depth 5 | Set-Content -Path $files.Factory -Encoding UTF8

    # 2. A preset holds one section per configuration name.
    @{ $name = @{ Database = @{ Host = 'db.prod.example.com'; SSL = $true } } } |
        ConvertTo-Json -Depth 5 | Set-Content -Path $files.Preset -Encoding UTF8

    $factory = Get-CCFConfig -ConfigName $name -ForceRefresh
    Write-CCFLogInfo "Factory:    $($factory.Database.Host):$($factory.Database.Port) SSL=$($factory.Database.SSL)"

    $production = Get-CCFConfig -ConfigName $name -ActivePresets 'example_production' -ForceRefresh
    Write-CCFLogInfo "Production: $($production.Database.Host):$($production.Database.Port) SSL=$($production.Database.SSL)"

    # 3. User overrides, saved with Set-CCFUserConfig (the cache is cleared for this name).
    Set-CCFUserConfig -ConfigName $name -ConfigObject ([pscustomobject]@{ Database = @{ Port = 6543 } })
    $user = Get-CCFConfig -ConfigName $name -ActivePresets 'example_production'
    Write-CCFLogInfo "With user:  $($user.Database.Host):$($user.Database.Port) SSL=$($user.Database.SSL)"

    # Schema validation fills in defaults and reports problems.
    $settings = [pscustomobject]@{ Port = 8080 }
    $valid = Test-CCFConfigSchema -Config $settings -Schema @{
        Port = @{ Mandatory = $true; Type = [int] }
        Mode = @{ AllowedValues = 'Audit', 'Enforce'; Default = 'Audit' }
    }
    Write-CCFLogInfo "Schema valid: $valid, Mode = $($settings.Mode)"

    # Names that look like paths are refused.
    $null = Get-CCFConfig -ConfigName '..\..\secrets'
}
finally {
    $files.Values | Where-Object { Test-Path $_ } | Remove-Item -Force
    Remove-CCFConfigCache
}
