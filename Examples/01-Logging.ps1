# Logging: levels, structured data, secret redaction, security and audit records.
# Run from the repository: .\Examples\01-Logging.ps1

Import-Module (Join-Path $PSScriptRoot '..\ArgosCCF.psd1') -Force

Initialize-CCFLogger -FileName 'Example.log'
Write-CCFLogHeader '=== Logging example ==='

Write-CCFLogInfo 'Job started'
Write-CCFLogSuccess 'Configuration loaded'
Write-CCFLogWarn 'Disk space below 15%' @{ Drive = 'C:'; FreePercent = 14 }
Write-CCFLogDebug 'Only shown after Set-CCFLogLevel -Level DEBUG'

# Secrets are redacted before anything is written.
Write-CCFLog -Message 'Connecting with password=Sup3rSecret! as svc-backup' -Level INFO
Protect-CCFSensitiveData -InputData @{ User = 'svc-backup'; ApiKey = 'k-123'; Region = 'eu-west' }

# Line breaks cannot forge entries: they are written as \n on a single line.
Write-CCFLog -Message "User input: abc`n[2026-01-01T00:00:00.000Z] [INFO] [System] fake entry" -Level WARN

# Security and audit records go to CCF_Security.log and CCF_Audit.log.
Write-CCFSecurityRecord -Type 'PathTraversal' -Source 'UserInput' -Payload '../../etc/passwd'
Write-CCFAuditRecord -Action 'ConfigChange' -User ([Environment]::UserName) -Resource 'ccf_core'

try {
    Get-Item -Path (Join-Path ([IO.Path]::GetTempPath()) 'argosccf-missing-file') -ErrorAction Stop
}
catch {
    Write-CCFErrorRecord -ErrorRecord $_ -Context 'Example'
}

$health = Test-CCFHealth
Write-CCFLogInfo "Health: $($health.Status)"
Write-CCFLogInfo "Log files are in $(Get-CCFPath -Target Logs)"
