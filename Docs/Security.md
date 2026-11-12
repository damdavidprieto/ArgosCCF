# Security Features

## Overview

ArgosCCF is built with security as a core principle. This document outlines the security features and best practices.

## Security Features

### 1. L5 Hardening

ArgosCCF implements Level 5 (L5) security hardening across all core modules:

- **Input Validation**: Strict type checking and boundary validation
- **Path Traversal Protection**: All file paths are validated against allowed base paths
- **Injection Prevention**: Sanitization of user inputs
- **Least Privilege**: Minimal permissions required for operations

### 2. Secret Redaction

Automatic detection and redaction of sensitive data in logs:

#### Blacklist-Based Redaction

```powershell
$message = "My password is SuperSecret123!"
$redacted = Redact-CCFSensitiveData -InputData $message
# Output: "My [REDACTED] is [REDACTED]!"
```

Blacklisted keywords:
- password, passwd, pwd
- secret, apikey, token
- credential, auth

#### Entropy-Based Redaction

Detects high-entropy strings (likely secrets):

```powershell
$message = "API Key: AKIA-872H-J92K-LL92-MM102-PP01"
$redacted = Redact-CCFSensitiveData -InputData $message
# Output: "API Key: [REDACTED-ENTROPY]"
```

### 3. Plugin Signature Verification

Require cryptographically signed plugins:

**Enable in `Configs/Factory/ccf_core.json`:**
```json
{
    "Security": {
        "RequireSignedPlugins": true
    }
}
```

**Sign a plugin:**
```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath "MyPlugin.ps1" -Certificate $cert
```

### 4. Plugin Sandboxing

Execute untrusted plugins in Constrained Language Mode:

```powershell
# Normal execution (Full Language Mode)
$result = Invoke-CCFPlugin -Plugin $plugin

# Sandboxed execution (Constrained Language Mode)
$result = Invoke-CCFPlugin -Plugin $plugin -HardenedMode
```

**Constrained Language Mode** restricts:
- Access to .NET types
- COM objects
- WMI calls
- File system access (limited)
- Network operations

### 5. Path Traversal Protection

All file operations validate paths:

```powershell
# Attempt to access Windows directory
$path = Get-CCFPath -Target "Logs" -Override "C:\Windows\System32"

# ArgosCCF blocks this and returns the safe default
# Result: <repo>\ArgosCCF\Logs
```

### 6. Forensic Logging

All security-relevant events are logged:

```powershell
# Log security attack
Log-Attack -Type "PathTraversal" -Source "User Input" -Payload "../../../etc/passwd"

# Automatic error logging with context
try {
    # Risky operation
}
catch {
    Catch-CCFError -ErrorRecord $_ -Context "PluginExecution"
}
```

## Security Best Practices

### 1. Principle of Least Privilege

Run ArgosCCF with minimal required permissions:

```powershell
# Don't run as Administrator unless necessary
# Use specific service accounts for automation
```

### 2. Secure Configuration Storage

Never store secrets in configuration files:

```powershell
# ❌ BAD: Hardcoded password
$config = @{
    Database = @{
        Password = "MyPassword123"
    }
}

# ✅ GOOD: Use environment variables
$config = @{
    Database = @{
        Password = $env:DB_PASSWORD
    }
}

# ✅ BETTER: Use secret management
$config = @{
    Database = @{
        Password = (Get-Secret -Name "DbPassword" -AsPlainText)
    }
}
```

### 3. Plugin Verification

Always verify plugin sources:

```powershell
# Check plugin signature before execution
$plugin = Get-CCFPlugins | Where-Object { $_.Name -eq "MyPlugin" }

if ($plugin.Signed) {
    Log-Info "Plugin is signed and verified"
    $result = Invoke-CCFPlugin -Plugin $plugin
}
else {
    Log-Warn "Plugin is not signed - executing in hardened mode"
    $result = Invoke-CCFPlugin -Plugin $plugin -HardenedMode
}
```

### 4. Log Review

Regularly review logs for security events:

```powershell
# Search for attack attempts
$logs = Get-Content (Get-CCFPath -Target "Logs") -Raw | ConvertFrom-Json
$attacks = $logs | Where-Object { $_.Category -eq "Attack" }
```

### 5. Update Regularly

Keep ArgosCCF updated:

```powershell
Update-Module -Name ArgosCCF
```

## Reporting Security Vulnerabilities

If you discover a security vulnerability:

1. **DO NOT** create a public GitHub issue
2. Private report: [Report a vulnerability](https://github.com/damdavidprieto/ArgosCCF/security/advisories/new)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours.

## Security Checklist

- [ ] Enable `RequireSignedPlugins` in production
- [ ] Use Constrained Language Mode for untrusted plugins
- [ ] Store secrets in environment variables or secret managers
- [ ] Review logs regularly for security events
- [ ] Keep ArgosCCF updated
- [ ] Run with least privilege
- [ ] Validate all user inputs
- [ ] Use HTTPS for remote operations
- [ ] Enable audit logging
- [ ] Implement proper access controls

## Compliance

ArgosCCF supports security compliance requirements:

- **Audit Trails**: All operations are logged with timestamps
- **Data Sanitization**: Automatic secret redaction
- **Access Control**: Plugin signature verification
- **Isolation**: Sandboxed execution environments
