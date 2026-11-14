@{
    RootModule           = 'ArgosCCF.psm1'
    ModuleVersion        = '1.4.0'
    CompatiblePSEditions = @('Desktop', 'Core')
    GUID                 = 'a4ce1d7d-c89a-46eb-9a85-5edccd5dab32'
    Author               = 'David Prieto'
    CompanyName          = 'David Prieto'
    Copyright            = '(c) 2026 David Prieto. Licensed under the MIT License.'
    Description          = 'Building blocks for PowerShell automation scripts: logging with secret redaction, security and audit records and log rotation; layered JSON configuration; plugins with signature checks and an optional restricted runspace; and parallel execution with retries. Windows PowerShell 5.1 and PowerShell 7+.'
    PowerShellVersion    = '5.1'

    # Keep in sync with Export-ModuleMember in ArgosCCF.psm1 (tests/QA checks it).
    FunctionsToExport    = @(
        'Get-CCFPath'
        'Initialize-CCFEnvironment'

        # Logging
        'Set-CCFLogLevel'
        'Register-CCFLogProvider'
        'Register-CCFSIEMProvider'
        'Initialize-CCFLogger'
        'Write-CCFLog'
        'Write-CCFLogInfo'
        'Write-CCFLogSuccess'
        'Write-CCFLogWarn'
        'Write-CCFLogError'
        'Write-CCFLogCritical'
        'Write-CCFLogDebug'
        'Write-CCFLogHeader'
        'Write-CCFSecurityRecord'
        'Write-CCFAuditRecord'
        'Write-CCFErrorRecord'
        'Remove-CCFOldLog'
        'Protect-CCFSensitiveData'
        'Test-CCFEntropyContent'
        'Test-CCFHealth'
        'Submit-CCFHeartbeat'

        # Configuration
        'Get-CCFConfig'
        'Set-CCFUserConfig'
        'Merge-CCFConfig'
        'Remove-CCFConfigCache'
        'Test-CCFConfigSchema'

        # Plugins
        'Get-CCFPlugin'
        'Invoke-CCFPlugin'
        'Confirm-CCFPluginSignature'

        # Execution
        'Invoke-CCFParallel'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    # Names from earlier versions, kept so existing scripts keep working.
    AliasesToExport      = @(
        'Log-Info', 'Log-Success', 'Log-Warn', 'Log-Error', 'Log-Critical', 'Log-Debug', 'Log-Header',
        'Log-Attack', 'Log-Audit', 'Init-CCFLogger', 'Catch-CCFError', 'Redact-CCFSensitiveData',
        'Test-CCFHighEntropy', 'Remove-OldCCFLogs', 'Clear-CCFConfigCache', 'Test-CCFPluginSignature',
        'Get-CCFPlugins'
    )

    PrivateData          = @{
        PSData = @{
            Tags         = @('Logging', 'Configuration', 'Plugins', 'Parallel', 'Runspace', 'Security', 'Audit', 'Redaction', 'Automation', 'Windows', 'Linux', 'MacOS', 'PSEdition_Desktop', 'PSEdition_Core')
            LicenseUri   = 'https://github.com/damdavidprieto/ArgosCCF/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/damdavidprieto/ArgosCCF'
            ReleaseNotes = 'See https://github.com/damdavidprieto/ArgosCCF/blob/main/CHANGELOG.md'
        }
    }
}
