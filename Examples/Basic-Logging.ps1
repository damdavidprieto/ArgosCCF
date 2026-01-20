# Basic Logging Example

<#
.SYNOPSIS
Demonstrates basic logging capabilities of ArgosCCF

.DESCRIPTION
This example shows how to initialize the logger and use different log levels.
#>

# Import ArgosCCF
Import-Module "$PSScriptRoot\..\ArgosCCF.psd1" -Force

# Initialize logger with custom settings
Init-CCFLogger -FileName "BasicLogging_Example.log" -MaxMB 10 -MaxRolling 3

# Log different message types
Log-Header "=== ArgosCCF Logging Demo ==="

Log-Info "This is an informational message"
Log-Success "Operation completed successfully"
Log-Warn "This is a warning message"
Log-Error "This is an error message"
Log-Critical "This is a critical error message"
Log-Debug "This is a debug message (only visible if debug logging is enabled)"

# Logging with structured data
$userData = @{
    Username  = "john.doe"
    Action    = "Login"
    Timestamp = Get-Date
}

Write-CCFLog -Message "User action logged" -Level "INFO" -Category "Audit" -Data $userData

# Logging security events
Log-Attack -Type "PathTraversal" -Source "UserInput" -Payload "../../../etc/passwd"

# Error handling with logging
try {
    # Simulate an error
    throw "Simulated error for demonstration"
}
catch {
    Catch-CCFError -ErrorRecord $_ -Context "DemoScript"
}

Log-Header "=== Logging Demo Complete ==="

# View the log file location
$logPath = Get-CCFPath -Target "Logs"
Write-Host "`nLog file created at: $logPath\BasicLogging_Example.log" -ForegroundColor Cyan
