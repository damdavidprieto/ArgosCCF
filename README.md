# ArgosCCF

![ArgosCCF Badge](https://img.shields.io/badge/ArgosCCF-v1.3.0-blueviolet) ![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green)

**ArgosCCF** (formerly CCF) is a professional, open-source PowerShell framework designed for high-integrity automation, secure configuration management, and parallel execution. It provides a robust foundation for building enterprise-grade PowerShell applications with built-in security hardening.

![Architecture Diagram](https://github.com/damdavidprieto/ArgosCCF/raw/main/Docs/architecture_diagram.png)

## 🚀 Features

- **🛡️ Security First**: Built-in L5 hardening, anti-path traversal, and plugin signature verification.
- **⚙️ Layered Configuration**: Deep merging of Factory, Preset, and User configurations with caching.
- **📝 Centralized Logging**: Structured JSON logging with automatic rotation, entropy-based secret redaction, and forensic hooks.
- **🔌 Plugin System**: Modular architecture supporting signed plugins and constrained language mode sandboxing.
- **⚡ Parallel Execution**: Optimized runspace pools for high-performance concurrent tasks.

## 📦 Installation

Not yet published to the PowerShell Gallery. Once published, installation will be:

```powershell
Install-Module -Name ArgosCCF -Scope CurrentUser
```

Or clone and import locally:

```powershell
git clone https://github.com/damdavidprieto/ArgosCCF.git
Import-Module ./ArgosCCF/ArgosCCF.psd1
```

## 📖 Quick Start

### Logging
```powershell
Init-CCFLogger -FileName "MyApp.log" -MaxMB 50
Log-Info "Application started successfully"
Log-Warn "Low disk space detected"
```

### Configuration
```powershell
$config = Get-CCFConfig -ConfigName "app_settings"
Write-Host "Database Host: $($config.Database.Host)"
```

### Parallel Execution
```powershell
$servers = @('Server01', 'Server02', 'Server03')
$results = Invoke-CCFParallel -InputObjects $servers -ScriptBlock {
    param($srv)
    Test-Connection -ComputerName $srv -Count 1 -Quiet
}
```

## 🤝 Contributing

We welcome contributions! Please check out our [Contribution Guidelines](CONTRIBUTING.md) for details on how to submit pull requests, report issues, and follow our coding standards.

## 🔒 Security

Security is a top priority for ArgosCCF. See our [Security Policy](SECURITY.md) for supported versions and how to report vulnerabilities securely.

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---
*Built with ❤️ by [David Prieto](https://github.com/damdavidprieto)*
