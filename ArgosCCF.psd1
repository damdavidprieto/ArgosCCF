@{
    RootModule           = 'ArgosCCF.psm1'
    ModuleVersion        = '2.0.0'
    CompatiblePSEditions = @('Desktop', 'Core')
    GUID                 = 'a4ce1d7d-c89a-46eb-9a85-5edccd5dab32'
    Author               = 'David Prieto'
    CompanyName          = 'David Prieto'
    Copyright            = '(c) 2026 David Prieto. Licensed under the MIT License.'
    Description          = 'Secure logging for PowerShell scripts. Passwords, tokens and keys are redacted before anything is written: key/value pairs and JSON, connection strings, credentials in URLs, Authorization headers, private keys, GitHub, AWS, Slack, Stripe, Google and npm tokens, values you register with Register-CCFSecret, your own patterns, and random-looking strings. Every rule has a time limit and fails closed. Entries cannot be forged, security and audit records go to their own files, chained logs show any line changed or deleted (also across rotation), and logs are kept per user, outside the module folder. The redaction also works on its own: put Protect-CCFSensitiveData in front of any other logger, or clean transcripts with Protect-CCFLogFile. Windows PowerShell 5.1 and PowerShell 7+, no dependencies.'
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
        'Test-CCFLogChain'
        'Get-CCFLogChainHead'
        'Register-CCFChainAnchor'
        'Get-CCFChainAnchor'
        'Write-CCFErrorRecord'
        'Remove-CCFOldLog'
        'Get-CCFLogWriter'
        'Wait-CCFLogWriter'
        'Stop-CCFLogWriter'
        'Protect-CCFSensitiveData'
        'Test-CCFEntropyContent'
        'Test-CCFHealth'

        # Redaction
        'Register-CCFSecret'
        'Unregister-CCFSecret'
        'Register-CCFRedactionPattern'
        'Unregister-CCFRedactionPattern'
        'Get-CCFRedactionPattern'
        'Protect-CCFLogFile'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Logging', 'Redaction', 'Secrets', 'Masking', 'Sanitize', 'Security', 'Audit', 'Transcript', 'SIEM', 'Compliance', 'DevSecOps', 'Windows', 'Linux', 'MacOS', 'PSEdition_Desktop', 'PSEdition_Core')
            LicenseUri   = 'https://github.com/damdavidprieto/ArgosCCF/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/damdavidprieto/ArgosCCF'
            ReleaseNotes = 'See https://github.com/damdavidprieto/ArgosCCF/blob/main/CHANGELOG.md'
        }
    }
}
