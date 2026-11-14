# Plugin development

A plugin is a PowerShell script in the module's `Plugins` folder (or a subfolder of it) that
`Invoke-CCFPlugin` runs with a hashtable of arguments and whose return value it passes back.
`Examples/03-Plugins.ps1` creates, runs and removes a plugin end to end.

## A minimal plugin

```powershell
# Plugins/Greeter/Greeter.ps1
param($Arguments)

$name = if ($Arguments.Name) { $Arguments.Name } else { 'World' }
Write-CCFLogInfo "Greeting $name"
@{ Greeting = "Hello, $name!" }
```

`param($Arguments)` must be the first statement of the script. Return data instead of writing it to
the console, so the caller can use it.

## Metadata

`Get-CCFPlugin` reads the name, version, author and description from a `ccf_plugin.json` file in the
plugin's folder:

```json
{
    "Name": "Greeter",
    "Version": "1.0.0",
    "Author": "Your Name",
    "Description": "Says hello"
}
```

Without a manifest it looks for comment keywords in the script (`.NAME`, `.DESCRIPTION`, `.VERSION`,
`.AUTHOR`, or `CCF_PLUGIN_NAME:` and similar) and falls back to the file name.

## Lifecycle hooks

A plugin can define `Before-Execute` and `After-Execute`. They are read from the script without
running it, then called around the main code: `Before-Execute` receives `-Arguments`, `After-Execute`
receives `-Result` (what the script returned). `-SkipHooks` skips them.

```powershell
param($Arguments)

function Before-Execute {
    param($Arguments)
    Write-CCFLogInfo "Preparing $($Arguments.Target)"
}

function After-Execute {
    param($Result)
    Write-CCFLogInfo "Finished with status $($Result.Status)"
}

# Main code
@{ Status = 'Success'; Target = $Arguments.Target }
```

## Running a plugin

```powershell
$plugin = Get-CCFPlugin | Where-Object Name -EQ 'Greeter'
$result = Invoke-CCFPlugin -Plugin $plugin -Arguments @{ Name = 'Ana' }
```

`Invoke-CCFPlugin` refuses any script outside the `Plugins` folder, logs errors with
`Write-CCFErrorRecord` and returns `$null` when the plugin fails.

## Hardened mode

```powershell
$result = Invoke-CCFPlugin -Plugin $plugin -Arguments @{ Name = 'Ana' } -HardenedMode
```

With `-HardenedMode` the plugin and its hooks run in a new runspace in Constrained Language Mode with
no cmdlets or providers loaded. Only the language itself is available: variables, loops, hashtables,
arithmetic and string operations, and methods of core types. ArgosCCF commands (`Write-CCFLogInfo`),
other cmdlets, `Add-Type` and most .NET calls fail. Write plugins meant for this mode so that they only
compute and return data, and do the logging in the caller.

Hardened mode reduces what a plugin can do but is not a security boundary on its own; see
[Security](Security.md#plugins).

## Signatures

When `Security.RequireSignedPlugins` is `true` in the `ccf_core` configuration, only plugins with a
valid Authenticode signature run. Sign a plugin after every change:

```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath .\Plugins\Greeter\Greeter.ps1 -Certificate $cert
```

Enable the check for this installation with a user setting:

```powershell
Set-CCFUserConfig -ConfigName ccf_core -ConfigObject ([pscustomobject]@{ Security = @{ RequireSignedPlugins = $true } })
```

`Get-CCFPlugin` shows whether each plugin is signed in its `Signed` property.

## Checklist

- `param($Arguments)` first; return data, do not print it.
- A `ccf_plugin.json` with name and version.
- Errors: let them throw, or catch them and return a result that says what failed.
- If it may run with `-HardenedMode`, use only language features.
- Sign it when the installation requires signed plugins.
