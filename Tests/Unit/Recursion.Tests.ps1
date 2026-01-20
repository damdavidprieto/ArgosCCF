# Test-Recursion.ps1
Import-Module "C:\test\ArgosCCF\Core\Logging.psm1" -Force

# Simular un objeto circular o muy complejo
$obj = [PSCustomObject]@{ Name = "Test" }
$obj | Add-Member -NotePropertyName "Self" -NotePropertyValue $obj

Write-Host "--- TEST 1: Sanitizacion de objeto circular ---"
try {
    $redacted = Redact-CCFSensitiveData -InputData $obj
    Write-Host "Exito: $($redacted.Name)"
}
catch {
    Write-Host "Fallo esperado o error: $($_.Exception.Message)"
}

Write-Host "--- TEST 2: Log de objeto complejo (JSON) ---"
$script:JsonOutput = $true
$complex = [PSCustomObject]@{ 
    Prop1 = "Val1"
    Prop2 = [PSCustomObject]@{ Sub = "SubVal" }
}
# Añadir algo que rompa ConvertTo-Json si es posible
# (Ej: un objeto con profundidad > 10)
$current = $complex
for ($i = 0; $i -lt 15; $i++) {
    $current.Prop2 = [PSCustomObject]@{ Sub = "Level $i"; Next = $null }
    $current = $current.Prop2
}

try {
    Write-CCFLog -Message "Prueba complejo" -Data $complex
    Write-Host "Exito log JSON"
}
catch {
    Write-Host "Error en log: $($_.Exception.Message)"
}
