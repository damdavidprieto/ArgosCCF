# Redaction: what is removed before anything is written, your own secrets and patterns, and
# redacting text for other loggers and files that were already written.
# Run from the repository: .\Examples\05-Redaction.ps1
# All the secrets below are made-up examples.

Import-Module (Join-Path $PSScriptRoot '..\ArgosCCF.psd1') -Force

# Known formats are recognized in any message.
@(
    'Server=db01;User Id=sa;Password=P@ss w0rd;Encrypt=True'
    '{"user":"bob","password":"hunter2x"}'
    'GET https://admin:S3cretPw@files.example.com/share'
    'Authorization: Basic dXNlcjpwYXNz'
    'Using AKIAIOSFODNN7EXAMPLE and ghp_aBcD1234eFgH5678iJkL9012mNoP3456qRsT'
    'Run 3f2504e0-4f89-11d3-9a0c-0305e82c3301 finished'            # GUIDs are kept
) | Protect-CCFSensitiveData

# Your own secrets are redacted wherever they appear, in any format.
$cred = [pscredential]::new('svc-deploy', (ConvertTo-SecureString 'Verano2026!' -AsPlainText -Force))
Register-CCFSecret -Credential $cred
Write-CCFLogError 'The remote server said: invalid password Verano2026! for svc-deploy'

# Formats specific to your organization.
Register-CCFRedactionPattern -Name 'ContosoKey' -Pattern '\bCTS-[0-9A-F]{24}\b'
Write-CCFLogInfo 'Using key CTS-0123456789ABCDEF01234567'

# Data objects: keys that name a secret, credentials and arrays.
Protect-CCFSensitiveData -InputData @{ User = 'bob'; ApiKey = 'k-123'; Login = $cred; Items = @('token=abc123', 'ok') }

# The rules, in the order they are applied.
Get-CCFRedactionPattern | Format-Table Name, Source, Description -AutoSize | Out-String -Width 160

# A transcript or a log written by another tool: write a redacted copy.
$folder = Join-Path ([IO.Path]::GetTempPath()) ('argosccf-example-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $folder | Out-Null
try {
    $transcript = Join-Path $folder 'transcript.txt'
    Set-Content -Path $transcript -Value @('Deploying', 'Connecting with password=hunter2x', 'Done')
    $result = Protect-CCFLogFile -Path $transcript
    "$($result.Redactions) redaction(s) written to $($result.Destination)"
    Get-Content -Path $result.Destination
}
finally {
    Remove-Item -LiteralPath $folder -Recurse -Force
    Unregister-CCFRedactionPattern -Name 'ContosoKey'
    Unregister-CCFSecret -All
}
