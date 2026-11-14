# Security

What ArgosCCF does to protect the scripts that use it, what it does not do, and how to use it safely.
To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Secret redaction

Every message and data object passed to `Write-CCFLog` (and the level shortcuts) goes through
`Protect-CCFSensitiveData` before it reaches the console, a provider or a file.

- **Key-value pairs in text.** `password=...`, `token: ...`, `apikey=...` and similar become
  `password=[REDACTED]`. Keywords: password, passwd, pwd, token, api_key, apikey, secret,
  authorization, auth_token.
- **Hashtables and objects.** Values whose key contains one of those keywords become `[REDACTED]`.
  Nested values are processed up to five levels; deeper values become `[DEPTH-LIMIT]` instead of
  being written unchecked.
- **Values that look like secrets.** Words of 20 or more characters that mix upper case, lower case,
  digits and `- _ + =` (see `Test-CCFEntropyContent`) become `[REDACTED-ENTROPY]`.

```powershell
Protect-CCFSensitiveData -InputData 'login user=admin password=Secr3t!'
# login user=admin password=[REDACTED]

Protect-CCFSensitiveData -InputData 'key AKIA-872H-J92K-LL92-MM102-PP01'
# key [REDACTED-ENTROPY]
```

Redaction is a safety net, not a guarantee: a secret without a keyword and with low variety (for
example a long lower-case passphrase) is not detected. Do not log secrets on purpose.

## Log integrity

- **One entry, one line.** Line breaks in messages are written as the text `\n`, and other control
  characters are removed, so a message cannot add fake entries to a log file.
- **No terminal escape sequences.** ANSI escape sequences are removed, so a message cannot recolor
  or hide console output.
- **Log files stay in the Logs folder.** `-Category` and `Initialize-CCFLogger -FileName` accept only
  letters, digits, `.`, `-` and `_`. The `Logging.DefaultPath` override in `ccf_core` is used only
  when, after resolving `..`, it is inside the module folder or inside `$env:CCF_DATA_PATH`.

Security and audit events have their own commands and files:

```powershell
Write-CCFSecurityRecord -Type 'PathTraversal' -Source 'UserInput' -Payload '../../etc/passwd'   # CCF_Security.log
Write-CCFAuditRecord -Action 'ConfigChange' -User $env:USERNAME -Resource 'ccf_core'           # CCF_Audit.log
try { ... } catch { Write-CCFErrorRecord -ErrorRecord $_ -Context 'Backup' }                   # CCF_Errors.log
```

To review them, read the files in `Get-CCFPath -Target Logs`. With `Initialize-CCFLogger -JsonOutput`
each line is a JSON object:

```powershell
Get-Content (Join-Path (Get-CCFPath -Target Logs) 'CCF_Security.log')
```

## Configuration files

Configuration and preset names become file names, so `Get-CCFConfig`, `Set-CCFUserConfig` and
`-ActivePresets` accept only plain names (letters, digits, `.`, `-`, `_`). Anything else is refused
and logged as a security block. Files are read and written as UTF-8.

Do not store secrets in configuration files. Read them at run time instead, for example from an
environment variable or with the SecretManagement module (`Get-Secret`).

## Plugins

A plugin is PowerShell code that runs with the permissions of the script that calls
`Invoke-CCFPlugin`. Treat installing a plugin like installing any other script.

1. **Location.** Only `.ps1` files inside the module's `Plugins` folder run. The path is resolved
   first, so `Plugins\..\other.ps1` and sibling folders such as `PluginsX` are refused.
2. **Signatures.** With `Security.RequireSignedPlugins` set to `true`, a plugin runs only if it has a
   valid Authenticode signature from a trusted certificate. The signature is checked on the same bytes
   that are then run, so the file cannot be replaced between the check and the execution. On Linux and
   macOS, where Authenticode is not available, every plugin counts as unsigned (fail closed).

   ```powershell
   Set-CCFUserConfig -ConfigName ccf_core -ConfigObject ([pscustomobject]@{ Security = @{ RequireSignedPlugins = $true } })
   ```

   To sign a plugin:

   ```powershell
   $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
   Set-AuthenticodeSignature -FilePath .\Plugins\MyPlugin\MyPlugin.ps1 -Certificate $cert
   ```

3. **Hardened mode.** With `-HardenedMode`, the plugin and its `Before-Execute`/`After-Execute` hooks
   run in a new restricted runspace in Constrained Language Mode: no cmdlets or providers are loaded
   and calls to non-core .NET methods, `Add-Type` and COM are blocked. Hooks cannot call ArgosCCF in
   this mode.

> **Limits.** Microsoft does not treat Constrained Language Mode as a security boundary on its own; it
> is enforced as one only together with WDAC or AppLocker. Hardened mode reduces what a plugin can do,
> but it does not make untrusted code safe. For plugins you did not write, require signatures and keep
> the `Plugins` folder writable only by administrators.

## Parallel execution

`Invoke-CCFParallel` runs the script block you pass, with your permissions, in separate runspaces.
Build it from your own code, never from untrusted input.

## Checklist

- [ ] Enable `RequireSignedPlugins` where plugins come from other people.
- [ ] Keep the module folder, and especially `Plugins` and `Configs`, writable only by administrators.
- [ ] Keep secrets out of configuration files and out of log messages.
- [ ] Use `Write-CCFSecurityRecord` and `Write-CCFAuditRecord` for events that must be traceable, and
      review `CCF_Security.log` and `CCF_Audit.log`.
- [ ] Keep ArgosCCF up to date: `Update-Module ArgosCCF`.
