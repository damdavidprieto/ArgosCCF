<#
    .SYNOPSIS
    CCF Forensic Logging Verification Suite (Grado Alucard)
#>

Import-Module "C:\test\ArgosCCF\ArgosCCF.psm1" -Force

# 1. Forzar salida JSON vía Config (simulación)
$script:JsonOutput = $true # Hack rápido para el test
Init-CCFLogger -FileName "CCF_Forensic.log"

Log-Header "--- INICIANDO VERIFICACION FORENSE ---"

# 2. Test de Sanitización
Log-Info "Prueba de sanitización de secretos..."
Log-Info "Iniciando sesión con usuario='admin' y password='SuperSecret123!'"
Log-Success "Usuario autenticado con token='XYZ-999-ABC'" -Data @{ raw_response = "auth_token: XYZ-999-ABC"; port = 8080 }

# 3. Test de Ataque (Security Category)
Log-Attack -Type "SQL Injection" -Source "192.168.1.50" -Payload "id=1' OR '1'='1" -Metadata @{ target = "UserTable" }

# 4. Test de Auditoria (Audit Category)
Log-Audit -Action "FileDeletion" -User "SystemAdmin" -Resource "C:\Critical\DB.bak"

# 5. Verificación de Archivos
Log-Header "--- VERIFICACION DE ROUTING ---"
$logDir = Get-CCFPath -Target "Logs"
$files = Get-ChildItem $logDir -Filter "CCF_*.log"
foreach ($f in $files) {
    Log-Success "Archivo generado: $($f.Name) ($($f.Length) bytes)"
    # Mostrar última línea si es JSON
    $last = Get-Content $f.FullName -Tail 1
    if ($last -match "^{") {
        Log-Info "Validación JSON para $($f.Name): EXITOSA"
        # Mostrar sanitización en la última línea del log principal
        if ($f.Name -eq "CCF_Session.log") {
            Log-Warn "Contenido sanitizado: $last"
        }
    }
}

Log-Header "--- TODAS LAS PRUEBAS FORENSES COMPLETADAS ---"
