# Module Structure

How ArgosCCF is laid out as a PowerShell module, and the steps to turn a collection of
scripts into a module built the same way. Use it as a reference when contributing to
ArgosCCF or when structuring your own module.

## Layout

```
ArgosCCF/
├── ArgosCCF.psd1        # Manifest: version, exported functions and aliases, Gallery metadata
├── ArgosCCF.psm1        # Root module: environment initialisation, imports Core/*
├── Core/                # Internal modules
│   ├── Configuration.psm1   # Layered config (Factory / Preset / User), deep merge, cache
│   ├── Execution.psm1       # Runspace-pool parallel execution
│   ├── Logging.psm1         # Structured logging, rotation, secret redaction
│   └── Plugins.psm1         # Plugin discovery, signature check, sandboxing
├── Configs/             # Factory defaults and user overrides
├── Plugins/             # Plugin scripts
├── Tests/               # Pester: Unit/, Integration/, E2E/
├── Docs/                # This documentation
├── Examples/
├── CHANGELOG.md
└── LICENSE
```

The general rule: one manifest, one thin root module, and the real logic split into
`Core/*.psm1` files by responsibility.

## 1. The manifest (`.psd1`)

Create it once with `New-ModuleManifest`, then edit it by hand:

```powershell
New-ModuleManifest -Path .\MyModule.psd1 `
    -RootModule 'MyModule.psm1' `
    -ModuleVersion '1.0.0' `
    -Author 'Your Name' `
    -Description 'What the module does' `
    -PowerShellVersion '5.1'
```

Fields that matter:

```powershell
@{
    RootModule        = 'MyModule.psm1'
    ModuleVersion     = '1.0.0'                 # SemVer: MAJOR.MINOR.PATCH
    GUID              = '...'                   # [guid]::NewGuid(), never change it afterwards
    PowerShellVersion = '5.1'

    # List exports explicitly. Wildcards ('*') slow down auto-loading
    # and leak internal helpers.
    FunctionsToExport = @('Get-Something', 'Set-Something')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @('gs')

    PrivateData = @{
        PSData = @{
            Tags       = @('Automation', 'Logging')
            LicenseUri = 'https://github.com/<user>/<repo>/blob/main/LICENSE'
            ProjectUri = 'https://github.com/<user>/<repo>'
        }
    }
}
```

ArgosCCF exports 28 functions and 15 aliases this way. The aliases keep older names
working (`Log-Info` → `Write-CCFLogInfo`, `Init-CCFLogger` → `Initialize-CCFLogger`)
while the functions themselves use approved verbs.

Validate the manifest after every change:

```powershell
Test-ModuleManifest -Path .\MyModule.psd1
```

## 2. The root module (`.psm1`)

Keep it small: initialise state, import the internal modules, and let the manifest decide
what is exported.

```powershell
$script:ModuleRoot = $PSScriptRoot

foreach ($name in 'Configuration', 'Logging', 'Execution', 'Plugins') {
    $path = Join-Path $script:ModuleRoot "Core\$name.psm1"
    if (Test-Path $path) { Import-Module $path -Force }
}
```

ArgosCCF's root module also resolves its own root folder, so the module works whether it is
loaded from a clone or from `PSModulePath`. It tries the folder the module was loaded from
first, then the `ARGOS_CCF_ROOT` environment variable. It then creates `Configs`, `Logs` and
`Plugins` if they are missing, and checks that `Logs` is writable:

```powershell
$script:ArgosCCFRoot = (Get-Item $PSScriptRoot).FullName

if (-not (Test-Path (Join-Path $script:ArgosCCFRoot 'Core')) -and
    $env:ARGOS_CCF_ROOT -and (Test-Path $env:ARGOS_CCF_ROOT)) {
    $script:ArgosCCFRoot = $env:ARGOS_CCF_ROOT
}
```

Avoid hard-coded development paths (`C:\dev\...`) in the module itself; use
`$PSScriptRoot` or an environment variable.

## 3. Versioning

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: breaking changes (removed or renamed functions, changed parameters).
- **MINOR**: new functionality that stays compatible.
- **PATCH**: bug fixes.
- Pre-releases: `1.4.0-beta1` in `PrivateData.PSData.Prerelease`.

For each release, update `ModuleVersion` in the manifest, add an entry to `CHANGELOG.md`
and tag the commit:

```powershell
git tag -a v1.3.0 -m "v1.3.0"
git push origin v1.3.0
```

## 4. Loading the module

- **From the Gallery:** `Install-Module ArgosCCF -Scope CurrentUser`.
- **From a clone:** `Import-Module .\ArgosCCF\ArgosCCF.psd1`.
- **While developing:** add the parent folder of the clone to `PSModulePath` for the
  session, so `Import-Module ArgosCCF` picks up your working copy:

  ```powershell
  $env:PSModulePath = "$(Resolve-Path ..);$env:PSModulePath"
  ```

## 5. Keeping old names working

When renaming functions to approved verbs, existing callers break. Two options:

- **Aliases in the manifest** (what ArgosCCF does): cheap, and visible to
  `Get-Command`.
- **A wrapper function** when the old signature differs from the new one:

  ```powershell
  function Init-Logger {
      param([Parameter(Mandatory)][string]$Path)
      Initialize-CCFLogger -FileName (Split-Path $Path -Leaf) -MaxMB 50
  }
  ```

Mark both as deprecated in the changelog and remove them in the next major version.

## 6. Tests

Tests use [Pester 5](https://pester.dev/) and are split by scope:

| Folder | What it covers |
|---|---|
| `Tests/Unit` | Each `Core` module (configuration, execution, logging, plugins) |
| `Tests/Integration` | Several modules together: hardening, forensics, performance |
| `Tests/E2E` | Full scenarios, such as signed and unsigned plugins |

A minimal test file:

```powershell
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\..\ArgosCCF.psd1') -Force
}

Describe 'Module loading' {
    It 'exports the logger' {
        Get-Command -Module ArgosCCF -Name Initialize-CCFLogger | Should -Not -BeNullOrEmpty
    }
}
```

Run them with:

```powershell
Invoke-Pester -Path .\Tests -Output Detailed
```

## 7. Continuous integration and publishing

- `.github/workflows/ci.yml` runs on Windows, Linux and macOS for every push and pull
  request: PSScriptAnalyzer (errors fail the build), `Test-ModuleManifest`, an import check
  that the module exports its functions, and the E2E security tests.
- `.github/workflows/publish.yml` publishes to the PowerShell Gallery. The API key lives
  in the `NUGET_API_KEY` repository secret and reaches `Publish-Module` as an environment
  variable.

Never write a Gallery API key in a script or commit it. If one is ever exposed, revoke it
on powershellgallery.com and create a new one.

Before publishing by hand:

```powershell
Test-ModuleManifest -Path .\ArgosCCF.psd1
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error, Warning
Invoke-Pester -Path .\Tests
```

## Checklist

- [ ] Manifest with explicit `FunctionsToExport` and `AliasesToExport`
- [ ] Thin root module; logic in `Core/*.psm1`
- [ ] No hard-coded machine paths; use `$PSScriptRoot` or environment variables
- [ ] Approved verbs (`Get-Verb`); old names kept as aliases
- [ ] SemVer, `CHANGELOG.md` entry and Git tag per release
- [ ] Pester tests and PSScriptAnalyzer in CI
- [ ] Gallery API key only in a CI secret

## References

- [How to write a module manifest](https://learn.microsoft.com/powershell/scripting/developer/module/how-to-write-a-powershell-module-manifest)
- [Approved verbs](https://learn.microsoft.com/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands)
- [Pester](https://pester.dev/) and [PSScriptAnalyzer](https://learn.microsoft.com/powershell/utility-modules/psscriptanalyzer/overview)
