Describe 'ArgosCCF 2.0' {
    BeforeAll { $module = Import-Module (Join-Path $PSScriptRoot '../../ArgosCCF.psd1') -Force -PassThru }

    It 'no longer has the configuration, plugin and parallel commands, nor the old aliases' {
        # Only what this copy exports: Get-Command would load an older ArgosCCF installed on the computer.
        $exported = @($module.ExportedCommands.Keys)
        foreach ($name in 'Get-CCFConfig', 'Set-CCFUserConfig', 'Invoke-CCFPlugin', 'Invoke-CCFParallel', 'Submit-CCFHeartbeat', 'Log-Info', 'Init-CCFLogger', 'Redact-CCFSensitiveData') {
            $exported | Should -Not -Contain $name
        }
        $module.ExportedAliases.Count | Should -Be 0
        (Test-CCFHealth).Status | Should -Be 'OK'
    }
}
