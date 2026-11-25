# Security

What ArgosCCF does to protect the scripts that use it, what it does not do, and how to use it safely.
To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Secret redaction

Every message and data object passed to `Write-CCFLog` (and the level shortcuts, and the security,
audit and error records) goes through `Protect-CCFSensitiveData` before it reaches the console, a
provider, the SIEM provider or a file. Text is checked in this order
(`Get-CCFRedactionPattern` lists the rules):

| Step | What is redacted | Example result |
|---|---|---|
| 1. Registered values | Every occurrence of a value passed to `Register-CCFSecret` (and its URL-encoded form) | `login failed for [REDACTED]` |
| 2. Private keys | PEM blocks from `-----BEGIN ... PRIVATE KEY-----` to the END line | `[REDACTED-PRIVATE-KEY]` |
| 3. URLs | The password in `scheme://user:password@host` | `https://admin:[REDACTED]@host` |
| 4. Authorization | `Authorization` and `Proxy-Authorization` headers; the scheme is kept | `Authorization: Basic [REDACTED]` |
| 5. Bearer tokens | `Bearer <token>` anywhere | `Bearer [REDACTED]` |
| 6. Connection strings | `Password`, `Pwd`, `AccountKey` and shared access keys, up to the next `;` (spaces included) | `User Id=sa;Password=[REDACTED];` |
| 7. Known token formats | JSON web tokens; GitHub (`ghp_`, `github_pat_`...), AWS access key IDs (`AKIA`...), Slack (`xoxb-`...), Stripe (`sk_live_`...), Google (`AIza`...), npm (`npm_`) and `sk-` keys | `token [REDACTED]` |
| 7b. XML and command lines | Elements such as `<password>`; `-Password x`, `--token x`, `/pass:x` in any program; the password options of `net`, `rasdial`, `schtasks` and other Windows tools, PsTools, `sqlcmd`, `mysql`, `curl -u`, container logins, `sshpass`, 7-Zip, RAR, `zip`, `openssl`, `certutil` and `netsh`; literals of `ConvertTo-SecureString` | `net user bob [REDACTED] /add` |
| 7c. Encoded commands | PowerShell `-EncodedCommand`: 32 bits of its SHA-256 and its length. The same command gives the same fingerprint; someone who already suspects the exact content could check the guess | `-EncodedCommand [ENCODED 1a2b3c4d 120 chars]` |
| 8. Your patterns | Regular expressions added with `Register-CCFRedactionPattern` | `[REDACTED]` |
| 9. Key/value pairs | `key=value`, `key: value`, `"key": "value"` and quoted values with spaces, when the key names a secret: password, passwd, passphrase, contrasena (with or without the tilde), secret, token, api key, access key, private key, account key, shared key, credential, cookie, session id, signature, connection string (also inside longer keys such as `db_password` or `ClientSecret`), and the exact keys pwd, pass, pw, pin, sig, sas, pat, clave | `{"password":"[REDACTED]"}` |
| 10. Random-looking words | 20 or more characters mixing upper case, lower case and digits (see `Test-CCFEntropyContent`). GUIDs, SIDs, hashes, paths, URLs and host names are left alone | `key [REDACTED-ENTROPY]` |

Hashtables, objects and arrays are copied and checked recursively: values whose key names a secret
become `[REDACTED]` (true/false values are kept), `SecureString` values become `[REDACTED]`, and
`PSCredential` and `NetworkCredential` objects keep only the user name. Other objects are replaced by
their text form, redacted, so a password stored in one of their properties is never serialized.
Values nested more than five levels deep become `[DEPTH-LIMIT]` instead of being written unchecked.

**Fail closed.** Every rule, built-in or yours, has a time limit of 500 ms per text. If a rule runs out
of time or fails, the whole text is replaced by `[REDACTED: the text could not be checked for secrets]`:
an entry can lose its content, but never leak a secret because a rule broke.

```powershell
Protect-CCFSensitiveData -InputData 'Server=db01;User Id=sa;Password=P@ss w0rd;Encrypt=True'
# Server=db01;User Id=sa;Password=[REDACTED];Encrypt=True

Protect-CCFSensitiveData -InputData 'Authorization: Basic dXNlcjpwYXNz'
# Authorization: Basic [REDACTED]

Protect-CCFSensitiveData -InputData 'key Xk9fQ2mLp7RtZ4vNw8Bc'
# key [REDACTED-ENTROPY]
```

### Register the secrets your script uses

Rules recognize formats; they cannot know that `Verano2026` is your password. Register the values your
script reads, and they are redacted wherever they appear, even inside an error message from another
module:

```powershell
$cred = Get-Credential
Register-CCFSecret -Credential $cred                      # its password
Register-CCFSecret -Value $env:DEPLOY_TOKEN               # any string of 4 or more characters
Register-CCFRedactionPattern -Name 'ContosoKey' -Pattern '\bCTS-[0-9A-F]{24}\b'   # your own format
```

Registered values and patterns are kept in memory, for the current session only.

### Use it with other loggers and with files

The redaction does not depend on ArgosCCF's own logger:

```powershell
Write-PSFMessage -Message (Protect-CCFSensitiveData "Calling $uri with $body")   # PSFramework
Write-Verbose (Protect-CCFSensitiveData $response)
Protect-CCFLogFile -Path .\transcript.txt          # writes transcript.redacted.txt
```

Redaction is a safety net, not a guarantee. A secret that no rule knows, that was not registered and
that does not look random (for example a long lower-case passphrase after an unrelated word) is not
detected. Do not log secrets on purpose, and register the ones your script handles.

## Log integrity

- **Tamper-evident logs.** `Initialize-CCFLogger -Chain` hashes every line with the one before it.
  `Register-CCFChainAnchor` passes each new head to your code, to keep it out of the writer's reach, and
  `Test-CCFLogChain` checks the chain, also across rotated copies: when rotation deletes the oldest copy, the next
  file records where it ended, so retention is not mistaken for tampering. `-Strict` makes an entry that cannot be
  written throw an error.
- **One entry, one line.** Line breaks in messages are written as the text `\n`, and other control
  characters are removed, so a message cannot add fake entries to a log file.
- **No terminal escape sequences.** ANSI escape sequences are removed, so a message cannot recolor
  or hide console output.
- **No lost entries.** Each write locks the file with a named mutex, so runspaces and processes of the
  same user session that log to the same file at the same time neither lose nor interleave entries.
  Files are rotated by size before every write, so a long session cannot fill the disk with one file.
- **Background writing keeps what matters synchronous.** With `Initialize-CCFLogger -Background`,
  `Write-CCFLog` returns before the entry is on disk. ERROR and CRITICAL entries, Security and Audit
  records and entries logged with `-NoBuffer` still wait until they are written, together with every
  entry queued before them. A full queue makes the caller wait rather than drop entries, and the queue
  is written out when PowerShell exits normally or the module is removed. Entries still queued when
  the process is killed or crashes are lost, so leave it off where every entry must survive a crash,
  and check `Get-CCFLogWriter` (or `Test-CCFHealth`) for writes that failed.
- **Log files stay in the Logs folder.** `-Category` and `Initialize-CCFLogger -FileName` accept only
  letters, digits, `.`, `-` and `_`. The `Logging.DefaultPath` override in `ccf_core` is used only
  when, after resolving `..`, it is inside the data folder, so a configuration file cannot send logs
  anywhere else. Only the script itself can choose another folder, with `Initialize-CCFLogger -Path`.
- **Logs and settings are kept per user, outside the module.** ArgosCCF never writes into the folder it
  is installed in. Logs and user settings go to the data folder: `$env:CCF_DATA_PATH`, or `ArgosCCF`
  under `%LOCALAPPDATA%` (`$XDG_DATA_HOME` or `~/.local/share` on Linux and macOS). Updating or
  removing the module keeps them, and an all-users install works without administrator rights.

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

## Plugins (deprecated)

Plugins will be removed in 2.0.0, which keeps only logging and redaction. A plugin is PowerShell code that runs with the permissions of the script that calls
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

## Parallel execution (deprecated)

`Invoke-CCFParallel` will be removed in 2.0.0; use `ForEach-Object -Parallel` or ThreadJob. It runs the script block you pass, with your permissions, in separate runspaces.
Build it from your own code, never from untrusted input.

## Checklist

- [ ] Enable `RequireSignedPlugins` where plugins come from other people.
- [ ] Keep the module folder, and especially `Plugins` and `Configs`, writable only by administrators.
- [ ] Register the secrets your script reads with `Register-CCFSecret` (or `-Credential`), right after
      reading them.
- [ ] Add `Register-CCFRedactionPattern` rules for secret formats specific to your organization.
- [ ] Run `Protect-CCFLogFile` on transcripts and on logs written by other tools before sharing them.
- [ ] Keep secrets out of configuration files and out of log messages.
- [ ] Use `Write-CCFSecurityRecord` and `Write-CCFAuditRecord` for events that must be traceable, and
      review `CCF_Security.log` and `CCF_Audit.log`.
- [ ] Keep ArgosCCF up to date: `Update-Module ArgosCCF`.
