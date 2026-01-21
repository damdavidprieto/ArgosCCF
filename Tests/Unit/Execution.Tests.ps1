Describe "ArgosCCF: Motor de Ejecución" {
    BeforeAll {
        Import-Module "C:\test\ArgosCCF\ArgosCCF.psd1" -Force
    }

    Context "Paralelismo y Resiliencia" {
        It "Debe ejecutar tareas en paralelo y recolectar resultados" {
            $inputs = 1..5
            $res = Invoke-CCFParallel -InputObjects $inputs -ScriptBlock { param($n) $n * 10 }
            $res.Output | Should -Contain 50
            $res.Output.Count | Should -Be 5
        }

        It "Debe capturar excepciones en hilos individuales sin detener el pool" {
            $res = Invoke-CCFParallel -InputObjects @(1, 2) -ScriptBlock { if ($args[0] -eq 1) { throw "Fail" } else { "Success" } }
            $res[0].Status | Should -Be "Failed"
            $res[1].Output | Should -Be "Success"
        }
    }
}
