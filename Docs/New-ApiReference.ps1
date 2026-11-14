<#
.SYNOPSIS
    Regenerates Docs/API-Reference.md from the comment-based help of the exported commands.

.DESCRIPTION
    The help in the source files is the single source of truth. Run this script after changing
    a command's help; tests/QA checks that the reference lists every exported command.

.EXAMPLE
    ./Docs/New-ApiReference.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$module = Import-Module (Join-Path $root 'ArgosCCF.psd1') -Force -PassThru
$common = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters

$sb = [System.Text.StringBuilder]::new()
$null = $sb.AppendLine('# ArgosCCF API reference')
$null = $sb.AppendLine()
$null = $sb.AppendLine('Generated from the comment-based help by `Docs/New-ApiReference.ps1`. In PowerShell, `Get-Help <command> -Full` shows the same information.')
$null = $sb.AppendLine()

$null = $sb.AppendLine('| Command | Synopsis |')
$null = $sb.AppendLine('|---|---|')
$commands = $module.ExportedFunctions.Values | Sort-Object Name
foreach ($command in $commands) {
    $synopsis = (Get-Help $command.Name).Synopsis.Trim() -replace '\|', '\|'
    $null = $sb.AppendLine("| [``$($command.Name)``](#$($command.Name.ToLowerInvariant())) | $synopsis |")
}
$null = $sb.AppendLine()

$null = $sb.AppendLine('## Aliases')
$null = $sb.AppendLine()
$null = $sb.AppendLine('Names from earlier versions, kept so existing scripts keep working.')
$null = $sb.AppendLine()
$null = $sb.AppendLine('| Alias | Command |')
$null = $sb.AppendLine('|---|---|')
foreach ($alias in $module.ExportedAliases.Values | Sort-Object Name) {
    $null = $sb.AppendLine("| ``$($alias.Name)`` | ``$($alias.Definition)`` |")
}
$null = $sb.AppendLine()

foreach ($command in $commands) {
    $help = Get-Help $command.Name -Full
    $null = $sb.AppendLine("## $($command.Name)")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine($help.Synopsis.Trim())
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('```powershell')
    $null = $sb.AppendLine((Get-Command $command.Name -Syntax).Trim())
    $null = $sb.AppendLine('```')
    $null = $sb.AppendLine()
    $description = (($help.Description | ForEach-Object Text) -join "`n").Trim()
    $null = $sb.AppendLine(($description -split "`n" | ForEach-Object { $_.Trim() }) -join "`n")
    $null = $sb.AppendLine()

    $parameters = @($help.Parameters.Parameter | Where-Object { $_.Name -notin $common })
    if ($parameters) {
        $null = $sb.AppendLine('| Parameter | Description |')
        $null = $sb.AppendLine('|---|---|')
        foreach ($parameter in $parameters) {
            $text = ((($parameter.Description | ForEach-Object Text) -join ' ') -replace '\s+', ' ' -replace '\|', '\|').Trim()
            $null = $sb.AppendLine("| ``-$($parameter.Name)`` | $text |")
        }
        $null = $sb.AppendLine()
    }

    $i = 0
    foreach ($example in @($help.Examples.Example)) {
        $i++
        $null = $sb.AppendLine("**Example $i**")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('```powershell')
        $null = $sb.AppendLine($example.Code.Trim())
        $null = $sb.AppendLine('```')
        $null = $sb.AppendLine()
        $remarks = (($example.Remarks | ForEach-Object Text) -join ' ').Trim()
        if ($remarks) { $null = $sb.AppendLine($remarks); $null = $sb.AppendLine() }
    }
}

$path = Join-Path $PSScriptRoot 'API-Reference.md'
$text = ($sb.ToString().TrimEnd() + "`n") -replace "`r`n", "`n" -replace "`n", "`r`n"
[System.IO.File]::WriteAllText($path, $text, [System.Text.UTF8Encoding]::new($false))
Write-Output "Wrote $path"
