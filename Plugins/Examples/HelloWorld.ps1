<#
.NAME
HelloWorld

.DESCRIPTION
A simple Hello World plugin for ArgosCCF

.VERSION
1.0.0

.AUTHOR
ArgosCCF Team
#>

param($Arguments)

# Get the name from arguments or use default
$name = if ($Arguments.Name) { $Arguments.Name } else { "World" }

# Log the greeting
Log-Success "Hello, $name! Welcome to ArgosCCF plugins!"

# Return a result
return @{
    Greeting      = "Hello, $name!"
    Timestamp     = Get-Date
    PluginVersion = "1.0.0"
}
