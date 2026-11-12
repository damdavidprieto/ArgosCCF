try {
    Write-Host "Cargando módulo..."
    $RepoRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $RepoRoot "Core/Logging.psm1") -Force -ErrorAction Stop
    Write-Host "Módulo cargado correctamente."

    $testString = "A1b2C3d4_E5f6G7h8-I9j0"
    Write-Host "Probando Test-CCFHighEntropy con: $testString"
    $res = Test-CCFHighEntropy -String $testString
    Write-Host "Resultado: $res"

    $redactInput = "password=SuperSecret123!"
    Write-Host "Probando Redact-CCFSensitiveData con: $redactInput"
    $redacted = Redact-CCFSensitiveData -InputData $redactInput
    Write-Host "Resultado: $redacted"
}
catch {
    Write-Error "Fallo en el diagnóstico: $($_.Exception.Message)"
    Write-Host "StackTrace: $($_.ScriptStackTrace)"
}
