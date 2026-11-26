# Redaction rules, registered secrets, custom patterns and Protect-CCFLogFile.
# All the secrets below are made-up test values.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../ArgosCCF.psd1') -Force
    $script:jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
}

AfterAll {
    Unregister-CCFSecret -All
}

Describe 'Known formats' {
    It 'redacts <Case>' -TestCases @(
        @{ Case = 'key=value'; Text = 'password=Secr3t!'; Secret = 'Secr3t!'; Expected = 'password=[REDACTED]' }
        @{ Case = 'key: value'; Text = 'Password: hunter2x'; Secret = 'hunter2x'; Expected = 'Password: [REDACTED]' }
        @{ Case = 'JSON'; Text = '{"user":"bob","password":"hunter2x"}'; Secret = 'hunter2x'; Expected = '{"user":"bob","password":"[REDACTED]"}' }
        @{ Case = 'a quoted value with spaces'; Text = "password='my pass phrase' next"; Secret = 'pass phrase'; Expected = "password='[REDACTED]' next" }
        @{ Case = 'a longer key name'; Text = 'db_password=abc12 ClientSecret: xyz98'; Secret = 'xyz98'; Expected = 'db_password=[REDACTED] ClientSecret: [REDACTED]' }
        @{ Case = 'Authorization Basic'; Text = 'Authorization: Basic dXNlcjpwYXNz'; Secret = 'dXNlcjpwYXNz'; Expected = 'Authorization: Basic [REDACTED]' }
        @{ Case = 'a bearer token'; Text = 'sent Bearer abcdefgh12345678'; Secret = 'abcdefgh1234'; Expected = 'sent Bearer [REDACTED]' }
        @{ Case = 'credentials in a URL'; Text = 'https://admin:S3cretPw@files.example.com/share'; Secret = 'S3cretPw'; Expected = 'https://admin:[REDACTED]@files.example.com/share' }
        @{ Case = 'a connection string with spaces'; Text = 'Server=db01;User Id=sa;Password=P@ss w0rd;Encrypt=True'; Secret = 'w0rd'; Expected = 'Server=db01;User Id=sa;Password=[REDACTED];Encrypt=True' }
        @{ Case = 'an Azure account key'; Text = 'AccountName=x;AccountKey=bm90LWEtcmVhbC1rZXk=;'; Secret = 'bm90LWEt'; Expected = 'AccountName=x;AccountKey=[REDACTED];' }
        @{ Case = 'a query string'; Text = 'GET /api?api_key=abc123def&page=2'; Secret = 'abc123def'; Expected = 'GET /api?api_key=[REDACTED]&page=2' }
        @{ Case = 'an AWS access key ID'; Text = 'Using AKIAIOSFODNN7EXAMPLE now'; Secret = 'AKIAIOSFODNN7EXAMPLE'; Expected = 'Using [REDACTED] now' }
        @{ Case = 'a GitHub token'; Text = 'token ghp_aBcD1234eFgH5678iJkL9012mNoP3456qRsT'; Secret = 'ghp_aBcD'; Expected = 'token [REDACTED]' }
        @{ Case = 'a Slack token'; Text = 'xoxb-123456789012-abcdefghij'; Secret = 'xoxb-1234'; Expected = '[REDACTED]' }
        @{ Case = 'a Stripe key'; Text = 'key sk_live_abcdefghijklmnop1234'; Secret = 'sk_live_'; Expected = 'key [REDACTED]' }
        @{ Case = 'a private key block'; Text = "x`n-----BEGIN RSA PRIVATE KEY-----`nMIIEowIBAAKCAQEA7bq`n-----END RSA PRIVATE KEY-----`ny"; Secret = 'MIIEow'; Expected = "x`n[REDACTED-PRIVATE-KEY]`ny" }
    ) {
        $result = Protect-CCFSensitiveData -InputData $Text
        $result | Should -Not -BeLike "*$Secret*"
        $result | Should -BeExactly $Expected
    }

    It 'redacts a JSON web token after Authorization: Bearer' {
        Protect-CCFSensitiveData "Authorization: Bearer $jwt" | Should -BeExactly 'Authorization: Bearer [REDACTED]'
        Protect-CCFSensitiveData "id_token $jwt" | Should -BeExactly 'id_token [REDACTED]'
    }

    It 'redacts random-looking words and keeps the punctuation around them' {
        Protect-CCFSensitiveData 'key (Xk9fQ2mLp7RtZ4vNw8Bc).' | Should -BeExactly 'key ([REDACTED-ENTROPY]).'
    }

    It 'checks long text too' {
        $long = ('x' * 3000) + ' password=hunter2x Xk9fQ2mLp7RtZ4vNw8Bc'
        $result = Protect-CCFSensitiveData $long
        $result | Should -Not -Match 'hunter2x|Xk9fQ2'
    }
}

Describe 'Command lines' {
    It 'redacts <Text>' -TestCases @(
        @{ Text = 'net user juan Zanahoria9 /add'; Expected = 'net user juan [REDACTED] /add' }
        @{ Text = 'C:\Windows\System32\net.exe user "juan perez" "Zanahoria9 x" /add'; Expected = 'C:\Windows\System32\net.exe user "juan perez" [REDACTED] /add' }
        @{ Text = 'net user a Zanahoria9 & net user b Zanahoria9'; Expected = 'net user a [REDACTED] & net user b [REDACTED]' }
        @{ Text = 'net use Z: \\nas\d /user:juan Zanahoria9'; Expected = 'net use Z: \\nas\d /user:juan [REDACTED]' }
        @{ Text = 'net use \\nas\d Zanahoria9 /user:juan'; Expected = 'net use \\nas\d [REDACTED] /user:juan' }
        @{ Text = 'rasdial "Mi VPN" juan Zanahoria9'; Expected = 'rasdial "Mi VPN" juan [REDACTED]' }
        @{ Text = 'schtasks /create /tn x /ru juan /rp Zanahoria9 /f'; Expected = 'schtasks /create /tn x /ru juan /rp [REDACTED] /f' }
        @{ Text = '"C:\Windows\system32\schtasks.exe" /s pc /u juan /p Zanahoria9'; Expected = '"C:\Windows\system32\schtasks.exe" /s pc /u juan /p [REDACTED]' }
        @{ Text = 'cmdkey /add:nas /user:juan /pass:Zanahoria9;x'; Expected = 'cmdkey /add:nas /user:juan /pass:[REDACTED]' }
        @{ Text = 'PsExec64.exe \\pc -u juan -p Zanahoria9 cmd'; Expected = 'PsExec64.exe \\pc -u juan -p [REDACTED] cmd' }
        @{ Text = 'x.exe -Password Zanahoria9 -v'; Expected = 'x.exe -Password [REDACTED] -v' }
        @{ Text = 'x -AdminPassword "Zanahoria9 y" z'; Expected = 'x -AdminPassword [REDACTED] z' }
        @{ Text = 'x --client-secret Zanahoria9'; Expected = 'x --client-secret [REDACTED]' }
        @{ Text = 'x --token=Zanahoria9,y z'; Expected = 'x --token=[REDACTED] z' }
        @{ Text = 'plink -pw Zanahoria9 host'; Expected = 'plink -pw [REDACTED] host' }
        @{ Text = 'x -Password "Zanahoria9 sin cerrar'; Expected = 'x -Password [REDACTED]' }
        @{ Text = 'sqlcmd -S s -U sa -P Zanahoria9 -Q q'; Expected = 'sqlcmd -S s -U sa -P [REDACTED] -Q q' }
        @{ Text = 'sqlcmd -S s -PZanahoria9'; Expected = 'sqlcmd -S s -P[REDACTED]' }
        @{ Text = 'mysql -u root -pZanahoria9 db'; Expected = 'mysql -u root -p[REDACTED] db' }
        @{ Text = 'mysqldump -u root -p"Zanahoria9 z" db'; Expected = 'mysqldump -u root -p[REDACTED] db' }
        @{ Text = 'curl -u juan:Zanahoria9 https://h.example?a=1'; Expected = 'curl -u juan:[REDACTED] https://h.example?a=1' }
        @{ Text = 'curl https://h.example?a=1&b=2 -su juan:Zanahoria9'; Expected = 'curl https://h.example?a=1&b=2 -su juan:[REDACTED]' }
        @{ Text = 'docker login -u juan -p Zanahoria9 reg.example'; Expected = 'docker login -u juan -p [REDACTED] reg.example' }
        @{ Text = 'sshpass -p Zanahoria9 ssh h'; Expected = 'sshpass -p [REDACTED] ssh h' }
        @{ Text = '7z a -pZanahoria9 f.7z d'; Expected = '7z a -p[REDACTED] f.7z d' }
        @{ Text = 'openssl rsa -passin pass:Zanahoria9 -in k'; Expected = 'openssl rsa -passin pass:[REDACTED] -in k' }
        @{ Text = 'netsh wlan set hostednetwork key=Zanahoria9 x'; Expected = 'netsh wlan set hostednetwork key=[REDACTED] x' }
        @{ Text = "ConvertTo-SecureString 'Zanahoria9' -AsPlainText -Force"; Expected = 'ConvertTo-SecureString [REDACTED] -AsPlainText -Force' }
        @{ Text = 'ConvertTo-SecureString -AsPlainText -Force -String Zanahoria9'; Expected = 'ConvertTo-SecureString -AsPlainText -Force -String [REDACTED]' }
        @{ Text = "'Zanahoria9' | ConvertTo-SecureString -AsPlainText"; Expected = '[REDACTED] | ConvertTo-SecureString -AsPlainText' }
    ) {
        $result = Protect-CCFSensitiveData -InputData $Text
        $result | Should -Not -Match 'Zanahoria9'
        $result | Should -BeExactly $Expected
    }

    It 'redacts a quoted curl user' {
        Protect-CCFSensitiveData 'curl -u "juan:Zanahoria9 z" https://h.example' | Should -Not -Match 'Zanahoria9'
        Protect-CCFSensitiveData "curl --user='juan:Zanahoria9' https://h.example" | Should -Not -Match 'Zanahoria9'
    }

    It 'keeps <Text>' -TestCases @(
        @{ Text = 'net user juan /active:yes' }
        @{ Text = 'net user juan * /add' }
        @{ Text = 'net use Z: \\nas\d /persistent:yes' }
        @{ Text = 'net use Z: /delete' }
        @{ Text = 'mysql -u root -p db' }
        @{ Text = 'ssh -p 2222 host' }
        @{ Text = 'mkdir -p /tmp/a' }
        @{ Text = 'docker run -p 8080:80 -u 1000:1000 img' }
        @{ Text = 'sqlcmd -S s -p 1' }
        @{ Text = 'git push -u origin main' }
        @{ Text = 'Set-LocalUser juan -PasswordNeverExpires 1' }
        @{ Text = 'x --token-file /run/t --password-stdin' }
        @{ Text = 'x -Password -Force' }
        @{ Text = 'ConvertTo-SecureString $texto -AsPlainText' }
        @{ Text = 'schtasks /query /tn x' }
        @{ Text = 'grep -e abcdefgh file' }
        @{ Text = 'powershell -ExecutionPolicy Bypass -File C:\x.ps1' }
        @{ Text = 'C:\Windows\System32\consent.exe 10356 1194 00000214461F8550' }
    ) {
        Protect-CCFSensitiveData -InputData $Text | Should -BeExactly $Text
    }

    It 'replaces an encoded command by the same fingerprint every time' {
        $a = Protect-CCFSensitiveData '"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -EncodedCommand dwBoAG8AYQBtAGkAIAAvAGEAbABsAA=='
        $b = Protect-CCFSensitiveData 'powershell.exe -enc dwBoAG8AYQBtAGkAIAAvAGEAbABsAA=='
        $a | Should -Match '-EncodedCommand \[ENCODED [0-9a-f]{8} 32 chars\]$'
        $a | Should -Not -Match 'dwBoAG8'
        [regex]::Match($a, '\[ENCODED.*').Value | Should -Be ([regex]::Match($b, '\[ENCODED.*').Value)
        Protect-CCFSensitiveData 'pwsh -e dwBoAG8AYQBtAGkAIAAvAGMA' | Should -Not -Match ([regex]::Match($a, '[0-9a-f]{8}').Value)
    }

    It 'stays fast on a long line' {
        $text = 'schtasks ' + ('C:\Windows\System32\cmd.exe /c algo -p -u /p --x ' * 60)
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        Protect-CCFSensitiveData $text | Should -Not -Match 'could not be checked'
        $watch.ElapsedMilliseconds | Should -BeLessThan 2000
    }
}

Describe 'XML and Spanish keys' {
    It 'redacts <Text>' -TestCases @(
        @{ Text = '<password>Zanahoria9</password>'; Expected = '<password>[REDACTED]</password>' }
        @{ Text = '<db:clientSecret id="1">Zanahoria9</db:clientSecret>'; Expected = '<db:clientSecret id="1">[REDACTED]</db:clientSecret>' }
        @{ Text = '<pwd><![CDATA[Zanahoria9<]]></pwd>'; Expected = '<pwd>[REDACTED]</pwd>' }
        @{ Text = 'contrasena: Zanahoria9'; Expected = 'contrasena: [REDACTED]' }
        @{ Text = "contrase$([char]0xF1)a=Zanahoria9"; Expected = "contrase$([char]0xF1)a=[REDACTED]" }
        @{ Text = "CONTRASE$([char]0xD1)A=Zanahoria9"; Expected = "CONTRASE$([char]0xD1)A=[REDACTED]" }
        @{ Text = 'clave: Zanahoria9'; Expected = 'clave: [REDACTED]' }
        @{ Text = "clave='casa grande'"; Expected = "clave='[REDACTED]'" }
    ) {
        Protect-CCFSensitiveData -InputData $Text | Should -BeExactly $Expected
    }

    It 'redacts object keys in Spanish' {
        $r = Protect-CCFSensitiveData @{ "Contrase$([char]0xF1)a" = 'Zanahoria9'; Clave = 'Zanahoria9'; Enclave = 'x' }
        $r["Contrase$([char]0xF1)a"] | Should -Be '[REDACTED]'
        $r.Clave | Should -Be '[REDACTED]'
        $r.Enclave | Should -Be 'x'
    }

    It 'redacts a password in a sentence: <Text>' -TestCases @(
        @{ Text = 'the password is Zanahoria9.'; Expected = 'the password is [REDACTED].' }
        @{ Text = "la contrase$([char]0xF1)a es Zanahoria9, cambiala"; Expected = "la contrase$([char]0xF1)a es [REDACTED], cambiala" }
        @{ Text = 'la clave era "mi casa"'; Expected = 'la clave era [REDACTED]' }
        @{ Text = 'Your PIN is 4821'; Expected = 'Your PIN is [REDACTED]' }
    ) {
        Protect-CCFSensitiveData -InputData $Text | Should -BeExactly $Expected
    }

    It 'keeps <Text>' -TestCases @(@{ Text = 'secretary=Ana' }, @{ Text = 'pass=3 fail=0' }, @{ Text = '<name>Ana</name>' }, @{ Text = 'enclave: x' },
        @{ Text = 'the password is incorrect' }, @{ Text = 'la contrasena es obligatoria' }, @{ Text = 'palabra clave: seguridad' }, @{ Text = 'quien tenga su clave: webs falsas' }) {
        Protect-CCFSensitiveData -InputData $Text | Should -BeExactly $Text
    }

    It 'still redacts pass with a real value' {
        Protect-CCFSensitiveData 'pass=1234' | Should -BeExactly 'pass=[REDACTED]'
    }
}

Describe 'Values that are not secrets' {
    It 'keeps <Case>' -TestCases @(
        @{ Case = 'a GUID'; Text = 'Run 3f2504e0-4f89-11d3-9a0c-0305e82c3301 done' }
        @{ Case = 'a SHA-256 hash'; Text = 'sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d08c15b0a08ea' }
        @{ Case = 'a certificate thumbprint'; Text = 'Thumbprint 3A1F9C0B5D7E2F4A6B8C0D1E2F3A4B5C6D7E8F90' }
        @{ Case = 'a Windows SID'; Text = 'User S-1-5-21-3623811015-3361044348-30300820-1013 signed in' }
        @{ Case = 'a path'; Text = 'C:\Users\bob\Documents\report-2026-final.xlsx' }
        @{ Case = 'a URL without credentials'; Text = 'https://my-storage-account-2026.blob.core.windows.net/container' }
        @{ Case = 'a WMI class name'; Text = 'Get-CimInstance Win32_OperatingSystem' }
        @{ Case = 'an ordinary sentence'; Text = 'Backup passed 3 of 3 checks; tokenizer finished; design=final' }
        @{ Case = 'a timestamp'; Text = 'User bob signed in from 10.0.0.5 at 2026-11-15T10:00:00Z' }
        # Found in the evidence of a hardening tool (2.1.0): settings, code and command lines.
        @{ Case = 'git options with booleans and empty values'; Text = 'git -c log.showSignature=false -c credential.helper= -c core.askPass= status' }
        @{ Case = 'PowerShell assignments'; Text = '$tokens = $errors = $null; $f.AccountsWithoutPassword = $noPwd -join ", "' }
        @{ Case = 'a command as the value'; Text = '$signatures = Read-ChSignatureCache' }
        @{ Case = 'an if as the value'; Text = '$f.AllAccountsHavePassword = if ($users) { 1 }' }
        @{ Case = 'Defender status'; Text = 'AntivirusSignatureVersion        : 1.459.523.0' }
        @{ Case = 'a password policy'; Text = 'MinimumPasswordLength : 7' }
        @{ Case = 'a Windows session number'; Text = 'SessionId                  : 1' }
        @{ Case = 'an empty JSON object'; Text = '"Secretos": {},' }
        @{ Case = 'a long function name'; Text = 'function Get-ChAdminState2a3b4c5d6e7f([datetime]$Start)' }
        @{ Case = 'a Store app package'; Text = '"bundleId":"MSTeams_8wekyb3d8bbwe!MSTeams"' }
        @{ Case = 'words and a commit hash'; Text = 'code-stable-e4c7e7b1d6d060162f4aa7f8225271b67ce1df75.exe' }
    ) {
        Protect-CCFSensitiveData -InputData $Text | Should -BeExactly $Text
    }

    It 'still redacts <Text>' -TestCases @(
        @{ Text = 'password = -Zanahoria9' }
        @{ Text = 'api_key=$ecretValue9' }
        @{ Text = 'password: $Zanahoria9' }
        @{ Text = 'password=-foo' }
        @{ Text = 'x-amz-signature=abcdef123456' }
        @{ Text = 'SessionId=8f3k2j5h6g7f8d9s' }
        @{ Text = '$password = ''Zanahoria9''' }
        @{ Text = 'password=Read-Zanahoria9' }
        @{ Text = 'password=(Zanahoria9' }
        @{ Text = 'token xQ9zRtYpLm3NbVcXzK7-a1b2c3d4' }
    ) {
        Protect-CCFSensitiveData -InputData $Text | Should -Match 'REDACTED'
    }

    It 'keeps the metadata of a secret in data, not the secret' {
        $r = Protect-CCFSensitiveData @{ MinimumPasswordLength = 7; Password = 'Zanahoria9'; SignatureVersion = '1.2'; RequestSignature = 'abc' }
        $r.MinimumPasswordLength | Should -Be 7
        $r.SignatureVersion | Should -Be '1.2'
        $r.Password | Should -Be '[REDACTED]'
        $r.RequestSignature | Should -Be '[REDACTED]'
    }

    It 'fingerprints -EncodedCommand in a command line inside JSON' {
        Protect-CCFSensitiveData 'C:\x\pwsh.exe\" -NoProfile -EncodedCommand ZQBjAGgAbwAgAGgAbwBsAGEA\"' | Should -Match '-EncodedCommand \[ENCODED [0-9a-f]{8} 24 chars\]\\"$'
    }
}

Describe 'Test-CCFEntropyContent' {
    It 'returns <Expected> for <String>' -TestCases @(
        @{ String = 'Xk9fQ2mLp7RtZ4vNw8Bc'; Expected = $true }
        @{ String = 'A1b2C3d4_E5f6G7h8-I9j0'; Expected = $true }
        @{ String = 'a8f3k2m9q7x1z5c4v6b0n2m8k4j6h3g1'; Expected = $true }
        @{ String = '3f2504e0-4f89-11d3-9a0c-0305e82c3301'; Expected = $false }
        @{ String = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d08c15b0a08ea'; Expected = $false }
        @{ String = 'S-1-5-21-3623811015-3361044348-30300820-1013'; Expected = $false }
        @{ String = 'Win32_OperatingSystem'; Expected = $false }
        @{ String = 'my-very-long-storage-container-2026'; Expected = $false }
        @{ String = 'short1A'; Expected = $false }
    ) {
        Test-CCFEntropyContent -String $String | Should -Be $Expected
    }
}

Describe 'Data objects' {
    It 'redacts values whose key names a secret, and keeps true/false values' {
        $result = Protect-CCFSensitiveData @{ User = 'bob'; ApiKey = 'abc'; PasswordExpired = $true; SessionId = 42 }
        $result.User | Should -Be 'bob'
        $result.ApiKey | Should -Be '[REDACTED]'
        $result.PasswordExpired | Should -BeTrue
        $result.SessionId | Should -Be '[REDACTED]'
    }

    It 'keeps arrays as arrays, including one-item and empty arrays, and checks their items' {
        $result = Protect-CCFSensitiveData @{ One = @('token=abc123'); Two = @('a', 'pwd=abcd'); Empty = @() }
        , $result.One | Should -BeOfType [object[]]
        $result.One[0] | Should -Be 'token=[REDACTED]'
        $result.Two[1] | Should -Be 'pwd=[REDACTED]'
        $result.Empty.Count | Should -Be 0
    }

    It 'returns an array for an array input' {
        $result = Protect-CCFSensitiveData -InputData @('x', 'password=abcd')
        $result.Count | Should -Be 2
        $result[1] | Should -Be 'password=[REDACTED]'
    }

    It 'keeps only the user name of credentials and redacts SecureString values' {
        $secure = ConvertTo-SecureString 'Plain!Pw9' -AsPlainText -Force
        $result = Protect-CCFSensitiveData @{ Cred = [pscredential]::new('bob', $secure); Net = [System.Net.NetworkCredential]::new('ann', 'Plain!Pw9'); Secure = $secure }
        $result.Cred.UserName | Should -Be 'bob'
        $result.Cred.Password | Should -Be '[REDACTED]'
        $result.Net.Password | Should -Be '[REDACTED]'
        $result.Secure | Should -Be '[REDACTED]'
        ($result | ConvertTo-Json -Depth 5) | Should -Not -Match 'Plain!Pw9'
    }

    It 'writes other objects as their redacted text instead of serializing their properties' {
        $object = [System.Uri]'https://admin:S3cretPw@host.example.com/'
        Protect-CCFSensitiveData @{ Target = $object } | ForEach-Object { $_.Target } | Should -Be 'https://admin:[REDACTED]@host.example.com/'
    }

    It 'redacts pipeline input item by item' {
        @('pwd=abcd', 'fine') | Protect-CCFSensitiveData | Should -Be @('pwd=[REDACTED]', 'fine')
    }

    It 'redacts the properties of a custom object' {
        $result = Protect-CCFSensitiveData ([pscustomobject]@{ User = 'bob'; Secret = 'A1b2C3d4_E5f6G7h8' })
        $result.User | Should -Be 'bob'
        $result.Secret | Should -Be '[REDACTED]'
    }

    It 'stops at the depth limit' {
        $result = Protect-CCFSensitiveData @{ n = @{ n = @{ n = @{ n = @{ n = @{ n = 'Limit' } } } } } }
        $result.n.n.n.n.n.n | Should -Be '[DEPTH-LIMIT]'
    }

    It 'does not modify the input' {
        $data = @{ Password = 'abcd' }
        $null = Protect-CCFSensitiveData $data
        $data.Password | Should -Be 'abcd'
    }
}

Describe 'Register-CCFSecret' {
    AfterEach { Unregister-CCFSecret -All }

    It 'redacts a registered value in any format, and its URL-encoded form' {
        Register-CCFSecret -Value 'p@ss word/1'
        Protect-CCFSensitiveData 'said p@ss word/1, sent p%40ss%20word%2F1' | Should -BeExactly 'said [REDACTED], sent [REDACTED]'
    }

    It 'registers the password of a credential and of a SecureString' {
        Register-CCFSecret -Credential ([pscredential]::new('bob', (ConvertTo-SecureString 'Verano2026' -AsPlainText -Force)))
        Register-CCFSecret -SecureString (ConvertTo-SecureString 'Invierno2027' -AsPlainText -Force)
        Protect-CCFSensitiveData 'bob used Verano2026 then Invierno2027' | Should -BeExactly 'bob used [REDACTED] then [REDACTED]'
    }

    It 'redacts the longer of two overlapping values whole' {
        Register-CCFSecret -Value 'abcd', 'abcdefgh'
        Protect-CCFSensitiveData 'x abcdefgh y' | Should -BeExactly 'x [REDACTED] y'
    }

    It 'treats regular expression characters literally' {
        Register-CCFSecret -Value 'a.b*c+d'
        Protect-CCFSensitiveData 'aXbbbcd and a.b*c+d' | Should -BeExactly 'aXbbbcd and [REDACTED]'
    }

    It 'refuses values shorter than 4 characters' {
        { Register-CCFSecret -Value 'abc' } | Should -Throw
    }

    It 'stops redacting a value after Unregister-CCFSecret' {
        Register-CCFSecret -Value 'Verano2026'
        Unregister-CCFSecret -Value 'Verano2026'
        Protect-CCFSensitiveData 'Verano2026' | Should -BeExactly 'Verano2026'
    }

    It 'applies to log entries' {
        Mock -ModuleName ArgosCCF Write-Host { }
        Register-CCFSecret -Value 'Verano2026'
        $entries = [System.Collections.Generic.List[object]]::new()
        Register-CCFSIEMProvider -ProviderScript { param($payload) $entries.Add($payload.Entry) }.GetNewClosure()
        Write-CCFLogError 'remote said: bad password Verano2026'
        InModuleScope ArgosCCF { $script:SIEMProvider = $null }
        $entries[-1].Message | Should -BeExactly 'remote said: bad password [REDACTED]'
    }
}

Describe 'Redaction patterns' {
    AfterEach {
        Get-CCFRedactionPattern -Source Custom | Unregister-CCFRedactionPattern
    }

    It 'applies a custom pattern, with named groups in the replacement' {
        Register-CCFRedactionPattern -Name 'ContosoKey' -Pattern '\bCTS-(?<id>[0-9A-F]{4})[0-9A-F]{20}\b' -Replacement 'CTS-${id}-[REDACTED]'
        Protect-CCFSensitiveData 'key CTS-0123456789ABCDEF01234567 used' | Should -BeExactly 'key CTS-0123-[REDACTED] used'
    }

    It 'lists the rules in the order they are applied' {
        Register-CCFRedactionPattern -Name 'Mine' -Pattern 'zzz'
        $names = @(Get-CCFRedactionPattern).Name
        $names[0] | Should -Be 'RegisteredSecret'
        $names.IndexOf('ConnectionString') | Should -BeLessThan $names.IndexOf('Mine')
        $names.IndexOf('Mine') | Should -BeLessThan $names.IndexOf('KeyValue')
        $names[-1] | Should -Be 'Entropy'
    }

    It 'refuses invalid patterns and built-in names' {
        { Register-CCFRedactionPattern -Name 'Bad' -Pattern '(' } | Should -Throw '*not a valid regular expression*'
        { Register-CCFRedactionPattern -Name 'GitHubToken' -Pattern 'x' } | Should -Throw '*built-in*'
        { Register-CCFRedactionPattern -Name 'bad name' -Pattern 'x' } | Should -Throw
        { Unregister-CCFRedactionPattern -Name 'GitHubToken' -ErrorAction Stop } | Should -Throw '*built-in*'
    }

    It 'fails closed when a pattern runs out of time' {
        Register-CCFRedactionPattern -Name 'Slow' -Pattern '^(a+)+$'
        $result = Protect-CCFSensitiveData (('a' * 40) + '! password=hunter2x')
        $result | Should -BeExactly '[REDACTED: the text could not be checked for secrets]'
    }
}

Describe 'Protect-CCFLogFile' {
    BeforeEach {
        $folder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $folder | Out-Null
        $file = Join-Path $folder 'transcript.txt'
        Set-Content -Path $file -Value @(
            'Start'
            'Connecting with password=hunter2x'
            'key: -----BEGIN OPENSSH PRIVATE KEY-----'
            'b3BlbnNzaC1rZXktdjEAAAAABG5vbmU'
            '-----END OPENSSH PRIVATE KEY-----'
            'Done 3f2504e0-4f89-11d3-9a0c-0305e82c3301'
        )
    }

    It 'writes a redacted copy next to the file and reports the redactions' {
        $result = Protect-CCFLogFile -Path $file
        $result.Destination | Should -Be (Join-Path $folder 'transcript.redacted.txt')
        $result.Redactions | Should -Be 2
        Get-Content $result.Destination | Should -Be @('Start', 'Connecting with password=[REDACTED]', 'key: [REDACTED-PRIVATE-KEY]', 'Done 3f2504e0-4f89-11d3-9a0c-0305e82c3301')
        Get-Content $file | Should -Contain 'Connecting with password=hunter2x'
    }

    It 'does not overwrite without -Force, and overwrites the original only when asked' {
        $null = Protect-CCFLogFile -Path $file
        { Protect-CCFLogFile -Path $file -ErrorAction Stop } | Should -Throw '*already exists*'
        $result = Protect-CCFLogFile -Path $file -Destination $file -Force
        $result.InPlace | Should -BeTrue
        Get-Content $file -Raw | Should -Not -Match 'hunter2x'
    }

    It 'writes nothing with -WhatIf' {
        Protect-CCFLogFile -Path $file -WhatIf
        Join-Path $folder 'transcript.redacted.txt' | Should -Not -Exist
    }

    It 'accepts Get-ChildItem output from the pipeline' {
        $results = @(Get-ChildItem -Path $folder -Filter *.txt | Protect-CCFLogFile)
        $results.Count | Should -Be 1
    }

    It 'reports a missing file' {
        { Protect-CCFLogFile -Path (Join-Path $folder 'missing.txt') -ErrorAction Stop } | Should -Throw '*not found*'
    }
}
