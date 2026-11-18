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
        @{ Case = 'a URL password that contains @'; Text = 'https://admin:p@ss@files.example.com/share'; Secret = 'ss@files'; Expected = 'https://admin:[REDACTED]@files.example.com/share' }
        @{ Case = 'an XML element'; Text = '<User>bob</User><Password>hunter2x</Password>'; Secret = 'hunter2x'; Expected = '<User>bob</User><Password>[REDACTED]</Password>' }
        @{ Case = 'an XML element with a prefix and attributes'; Text = '<ns:ClientSecret type="s">hunter2x</ns:ClientSecret>'; Secret = 'hunter2x'; Expected = '<ns:ClientSecret type="s">[REDACTED]</ns:ClientSecret>' }
        @{ Case = 'an XML element with CDATA'; Text = '<pwd><![CDATA[hunter<2x]]></pwd>'; Secret = 'hunter'; Expected = '<pwd>[REDACTED]</pwd>' }
        @{ Case = 'a PowerShell parameter'; Text = 'New-LocalUser -Name bob -Password hunter2x -Enabled'; Secret = 'hunter2x'; Expected = 'New-LocalUser -Name bob -Password [REDACTED] -Enabled' }
        @{ Case = 'a parameter with a colon'; Text = 'Connect -ApiKey:hunter2x'; Secret = 'hunter2x'; Expected = 'Connect -ApiKey:[REDACTED]' }
        @{ Case = 'a double-dash option with a quoted value'; Text = 'tool --token "hunter 2x" --verbose'; Secret = 'hunter'; Expected = 'tool --token [REDACTED] --verbose' }
        @{ Case = 'ConvertTo-SecureString'; Text = "ConvertTo-SecureString 'hunter2x' -AsPlainText -Force"; Secret = 'hunter2x'; Expected = 'ConvertTo-SecureString [REDACTED] -AsPlainText -Force' }
        @{ Case = 'a Spanish key'; Text = "contrase$([char]0xF1)a=hunter2x"; Secret = 'hunter2x'; Expected = "contrase$([char]0xF1)a=[REDACTED]" }
        @{ Case = 'a Spanish key without the tilde'; Text = 'nueva_contrasena: hunter2x'; Secret = 'hunter2x'; Expected = 'nueva_contrasena: [REDACTED]' }
        @{ Case = 'a short Spanish key'; Text = 'clave=hunter2x'; Secret = 'hunter2x'; Expected = 'clave=[REDACTED]' }
        @{ Case = 'a German key'; Text = 'Passwort=hunter2x'; Secret = 'hunter2x'; Expected = 'Passwort=[REDACTED]' }
        @{ Case = 'a French key'; Text = 'mot_de_passe=hunter2x'; Secret = 'hunter2x'; Expected = 'mot_de_passe=[REDACTED]' }
        @{ Case = 'a Portuguese key'; Text = 'senha=hunter2x'; Secret = 'hunter2x'; Expected = 'senha=[REDACTED]' }
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
        @{ Case = 'switches after a secret parameter name'; Text = 'Get-Thing -PassThru -Verbose; Set-Thing -Token -Force' }
        @{ Case = 'a boolean parameter value'; Text = 'Set-ADUser bob -PasswordNeverExpires $true' }
        @{ Case = 'an XML element that is not a secret'; Text = '<User>bob</User><Server>db01</Server>' }
        @{ Case = 'a URL with an @ in the query'; Text = 'https://example.com/invite?email=bob@example.com' }
        @{ Case = 'words that contain a short key'; Text = 'autoclave=on; la clave primaria es id; x - pin it' }
    ) {
        Protect-CCFSensitiveData -InputData $Text | Should -BeExactly $Text
    }
}

Describe 'Control characters' {
    BeforeAll {
        $script:esc = [char]27
    }

    It 'cannot hide a key with <Case>' -TestCases @(
        @{ Case = 'an ANSI sequence'; Inside = "$([char]27)[0m" }
        @{ Case = 'a NUL character'; Inside = [string][char]0 }
        @{ Case = 'a C1 control sequence'; Inside = "$([char]0x9B)0m" }
        @{ Case = 'an operating system command'; Inside = "$([char]27)]0;title$([char]7)" }
    ) {
        $result = Protect-CCFSensitiveData -InputData "pass${Inside}word=Hunter2Secret"
        $result | Should -BeExactly 'password=[REDACTED]'
    }

    It 'removes colors and keeps line breaks and tabs' {
        Protect-CCFSensitiveData "$esc[31mERROR$esc[0m`tpassword=x1y2z3`nnext" | Should -BeExactly "ERROR`tpassword=[REDACTED]`nnext"
    }

    It 'checks hashtable keys without their control characters' {
        $result = Protect-CCFSensitiveData @{ "pass$esc[0mword" = 'Hunter2Secret' }
        $result.Values | Should -Be '[REDACTED]'
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

    It 'removes colors from a transcript without counting them as redactions' {
        $esc = [char]27
        Set-Content -Path $file -Value @("$esc[32mOK$esc[0m step 1", "$esc[31mpass$esc[0mword=hunter2x")
        $result = Protect-CCFLogFile -Path $file
        $result.Redactions | Should -Be 1
        Get-Content $result.Destination | Should -Be @('OK step 1', 'password=[REDACTED]')
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
