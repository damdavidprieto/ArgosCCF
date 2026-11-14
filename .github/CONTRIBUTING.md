# Contributing

Thanks for helping improve ArgosCCF. Issues and pull requests are welcome. For security problems,
use the private channel in [SECURITY.md](../SECURITY.md) instead of an issue.

## Setting up

```powershell
git clone https://github.com/damdavidprieto/ArgosCCF.git
cd ArgosCCF
.\build.ps1 -InstallDependencies   # Pester 5 and PSScriptAnalyzer, first time only
.\build.ps1                        # analysis, tests and package
```

`build.ps1` must pass on both Windows PowerShell 5.1 and PowerShell 7 before a pull request is merged;
CI checks both, and PowerShell 7 on Linux and macOS too.

## Making a change

- **New command:** add it to the right file in `Core/`, then to `FunctionsToExport` in `ArgosCCF.psd1`
  and to `Export-ModuleMember` in `ArgosCCF.psm1`. The QA tests fail if the lists differ. Use an
  approved verb (`Get-Verb`) and a singular noun; keep an alias when renaming.
- **Help:** every exported command needs comment-based help with a synopsis, a description, an
  example and a description for each parameter (`Tests/QA/Module.Tests.ps1` checks it). Then run
  `./Docs/New-ApiReference.ps1` to update the API reference.
- **Analyzer:** the code must have no findings with `PSScriptAnalyzerSettings.psd1`. If a rule does not
  apply, suppress it on that function with `SuppressMessageAttribute` and a justification.
- **Paths and names:** anything that becomes a file name (log categories, configuration names) must be
  validated, and paths compared after `[IO.Path]::GetFullPath`.
- **Encoding:** read and write files with `-Encoding UTF8`, and save source files that contain
  non-ASCII characters as UTF-8 with BOM, or Windows PowerShell 5.1 will misread them.
- **Tests:** add or update tests in `Tests/Unit` or `Tests/Integration`. Examples in `Examples/` run
  as tests and must clean up any file they create.
- **Changelog:** describe the change under `## [Unreleased]` in `CHANGELOG.md`.

## Releasing

The `Publish` workflow runs in the `psgallery` environment, which only accepts `v*` tags and holds
three secrets:

| Secret | Contents |
|---|---|
| `PSGALLERY_API_KEY` | A PowerShell Gallery API key scoped to this package only |
| `CODE_SIGNING_PFX_BASE64` | The code signing certificate (.pfx), base64-encoded: `[Convert]::ToBase64String([IO.File]::ReadAllBytes('cert.pfx'))` |
| `CODE_SIGNING_PFX_PASSWORD` | The password of that .pfx |

1. Move the `Unreleased` entries in `CHANGELOG.md` under the new version and update `ModuleVersion`
   in the manifest.
2. Push a tag `v<version>`. The workflow checks that the tag matches the manifest, runs the build,
   signs every `.ps1`, `.psm1` and `.psd1` (and fails unless every signature is valid), publishes
   `output/ArgosCCF` to the PowerShell Gallery and creates the GitHub release.
