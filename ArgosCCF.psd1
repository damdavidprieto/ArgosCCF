@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'ArgosCCF.psm1'

    # Version number of this module.
    ModuleVersion     = '1.4.0'

    # ID used to uniquely identify this module
    GUID              = 'a4ce1d7d-c89a-46eb-9a85-5edccd5dab32'

    # Author of this module
    Author            = 'David Prieto'

    # Company or vendor of this module
    CompanyName       = 'Open Source'

    # Copyright statement for this module
    Copyright         = '(c) 2026 David Prieto. Licensed under the MIT License.'

    # Description of the functionality provided by this module
    Description       = 'ArgosCCF (formerly CCF) is a professional PowerShell framework for secure configuration, logging, plugin management, and parallel execution. Designed for high-integrity automation and security hardening.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # Functions to export from this module, for best performance, do not use wildcards
    FunctionsToExport = @(
        'Get-CCFPath',
        'Initialize-CCFEnvironment',
        'Set-CCFLogLevel',
        'Register-CCFLogProvider',
        'Register-CCFSIEMProvider',
        'Initialize-CCFLogger',
        'Write-CCFLog',
        'Write-CCFLogInfo',
        'Write-CCFLogSuccess',
        'Write-CCFLogWarn',
        'Write-CCFLogError',
        'Write-CCFLogCritical',
        'Write-CCFLogDebug',
        'Write-CCFLogHeader',
        'Write-CCFSecurityRecord',
        'Write-CCFAuditRecord',
        'Write-CCFErrorRecord',
        'Remove-CCFOldLog',
        'Protect-CCFSensitiveData',
        'Test-CCFEntropyContent',
        'Test-CCFHealth',
        'Submit-CCFHeartbeat',
        'Get-CCFConfig',
        'Set-CCFUserConfig',
        'Merge-CCFConfig',
        'Remove-CCFConfigCache',
        'Test-CCFConfigSchema',
        'Get-CCFPlugins',
        'Invoke-CCFPlugin',
        'Confirm-CCFPluginSignature',
        'Invoke-CCFParallel'
    )

    # Cmdlets to export from this module
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport   = @(
        'Log-Info', 'Log-Success', 'Log-Warn', 'Log-Error', 'Log-Critical', 'Log-Debug', 'Log-Header',
        'Log-Attack', 'Log-Audit', 'Init-CCFLogger', 'Catch-CCFError', 'Redact-CCFSensitiveData',
        'Test-CCFHighEntropy', 'Remove-OldCCFLogs', 'Clear-CCFConfigCache', 'Test-CCFPluginSignature'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData       = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @('Security', 'Configuration', 'Logging', 'Plugins', 'Parallel', 'Framework', 'Hardening', 'ArgosCCF')

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/damdavidprieto/ArgosCCF/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/damdavidprieto/ArgosCCF'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = @'
## 1.3.0
- Rebranding to ArgosCCF
- Security Hardening (L5)
- Plugin Signature Verification
- Parallel Execution Engine
- Enhanced Logging & Forensics
'@
        }
    }
}
