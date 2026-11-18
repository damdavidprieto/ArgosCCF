# ArgosCCF redaction engine.
#
# Removes secrets from text, hashtables and objects before they are logged. Write-CCFLog applies
# it to every message and its data; Protect-CCFSensitiveData and Protect-CCFLogFile expose it on
# its own, so it can sit in front of any other logger or clean files that were already written.
#
# Text goes through these steps, in order:
#   0. ANSI escape sequences and control characters other than line breaks and tabs are removed,
#      so they cannot hide a key from the rules;
#   1. values registered with Register-CCFSecret, wherever they appear;
#   2. built-in rules for known formats (private key blocks, credentials in URLs, Authorization
#      headers, bearer tokens, connection strings, XML elements, command-line parameters,
#      ConvertTo-SecureString, and GitHub, AWS, Slack, Stripe, Google, npm and sk- style keys,
#      JSON web tokens);
#   3. patterns added with Register-CCFRedactionPattern;
#   4. key/value pairs whose key names a secret (password=..., "token": "...", api_key: ...);
#   5. words that look like random secrets (Test-CCFEntropyContent).
# Every regular expression has a time limit. If one runs out, or anything else fails, the whole
# text is replaced (fail closed): a log entry can lose its content, never leak a secret.

$script:CCFRegexTimeout = [timespan]::FromMilliseconds(500)
$script:CCFRegexOptions = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
$script:CCFSecretValues = [System.Collections.Generic.List[string]]::new()
$script:CCFSecretRegex = $null
$script:CCFCustomPatterns = [ordered]@{}

# Key names that mark a secret. Long names may appear inside a longer key (db_password,
# ClientSecret, x-api-key); short ones only as the whole key, so "design" or "passed" are not
# matched. Authorization is handled by its own rule in text, which keeps the scheme.
# Both lists also hold the word for password in other languages (Spanish, German, French,
# Portuguese, Dutch); \u00f1 in the pattern is the n with tilde of the Spanish word.
$script:CCFLongSecretKeys = 'password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|account[_-]?key|shared[_-]?key|credential|cookie|session[_-]?id|signature|connection[_-]?string|contrase(?:\u00f1|n)a|passwort|kennwort|mot[_-]?de[_-]?passe|motdepasse|senha|wachtwoord'
$script:CCFShortSecretKeys = 'pwd|pass|pw|pin|sig|sas|pat|clave|mdp'

# --- Private helpers ---

function Get-CCFCompiledRegex {
    <#
    .SYNOPSIS
        Compiles a regular expression with the redaction time limit.
    #>
    [CmdletBinding()]
    [OutputType([regex])]
    param(
        [Parameter(Mandatory = $true)][string]$Pattern,
        [switch]$IgnoreCase
    )

    $options = $script:CCFRegexOptions
    if ($IgnoreCase) { $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    return [regex]::new($Pattern, $options, $script:CCFRegexTimeout)
}

$script:CCFKeyNameRegex = Get-CCFCompiledRegex -IgnoreCase -Pattern ("^(?:[A-Za-z0-9_.-]*(?:$($script:CCFLongSecretKeys)|authorization)[A-Za-z0-9_.-]*|$($script:CCFShortSecretKeys))$")

# Built-in rules. Order matters: specific formats run before the generic key/value rule, so a
# connection string or an Authorization header keeps its structure.
$script:CCFBuiltInRules = @(
    @{
        Name        = 'PrivateKeyBlock'
        Description = 'PEM private key blocks (-----BEGIN ... PRIVATE KEY----- to the END line, or to the end of the text)'
        Regex       = Get-CCFCompiledRegex -Pattern '-----BEGIN (?<t>[A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?(?:-----END \k<t>-----|$)'
        Replacement = '[REDACTED-PRIVATE-KEY]'
    }
    @{
        Name        = 'UrlCredentials'
        Description = 'Passwords in URLs (scheme://user:password@host)'
        # The password runs to the last '@' before the host, so one that contains '@' is redacted whole.
        Regex       = Get-CCFCompiledRegex -IgnoreCase -Pattern '\b(?<pre>[a-z][a-z0-9+.-]*://[^\s:/@]+):(?<pw>[^\s/?#]+)@'
        Replacement = '${pre}:[REDACTED]@'
    }
    @{
        Name        = 'AuthorizationHeader'
        Description = 'Authorization and Proxy-Authorization headers; the scheme (Basic, Bearer...) is kept'
        Regex       = Get-CCFCompiledRegex -IgnoreCase -Pattern '(?<![A-Za-z0-9_-])(?<k>(?:proxy-)?authorization)(?<sep>["'']?\s*[:=]\s*["'']?)(?<scheme>(?:bearer|basic|digest|negotiate|ntlm|token|apikey|sharedkey)\s+)?(?<v>[^\s,;"'']+)'
        Replacement = '${k}${sep}${scheme}[REDACTED]'
    }
    @{
        Name        = 'BearerToken'
        Description = 'Bearer tokens outside an Authorization header'
        Regex       = Get-CCFCompiledRegex -IgnoreCase -Pattern '\b(?<b>bearer)\s+[A-Za-z0-9._~+/-]{8,}=*'
        Replacement = '${b} [REDACTED]'
    }
    @{
        Name        = 'ConnectionString'
        Description = 'Password, Pwd, AccountKey and shared access keys in connection strings (up to the next semicolon, spaces included)'
        Regex       = Get-CCFCompiledRegex -IgnoreCase -Pattern '(?:(?<=;)|^(?=[^;]*;))(?<k>\s*(?:password|pwd|accountkey|sharedaccesskey|sharedaccesssignature|sharedsecretvalue|client[_ ]?secret)\s*=)[^;]*'
        Replacement = '${k}[REDACTED]'
    }
    @{
        Name        = 'XmlElement'
        Description = 'XML elements whose name names a secret (<Password>...</Password>, CDATA included)'
        Regex       = Get-CCFCompiledRegex -IgnoreCase -Pattern ('<(?<k>(?:[A-Za-z0-9_.-]+:)?(?:[A-Za-z0-9_.-]*(?:' + $script:CCFLongSecretKeys + ')[A-Za-z0-9_.-]*|(?:' + $script:CCFShortSecretKeys + ')))(?<a>\s[^<>]*)?>(?:<!\[CDATA\[[\s\S]*?\]\]>|[^<]+)</\k<k>\s*>')
        Replacement = '<${k}${a}>[REDACTED]</${k}>'
    }
    @{
        Name        = 'PlainTextSecureString'
        Description = 'The text passed to ConvertTo-SecureString (a password typed in a command)'
        Regex       = Get-CCFCompiledRegex -IgnoreCase -Pattern '(?<pre>\bConvertTo-SecureString\s+(?:-String\s+)?)(?:"[^"]*"|''[^'']*''|(?!-)[^\s|;)]+)'
        Replacement = '${pre}[REDACTED]'
    }
    @{
        Name        = 'CommandLineArgument'
        Description = 'Command-line parameters whose name names a secret (-Password value, --token value, -ApiKey:value); true, false and null are kept'
        Regex       = Get-CCFCompiledRegex -IgnoreCase -Pattern ('(?<![A-Za-z0-9_-])(?<k>--?(?:[A-Za-z0-9_-]*(?:' + $script:CCFLongSecretKeys + ')[A-Za-z0-9_-]*|(?:' + $script:CCFShortSecretKeys + ')))(?<sep>:\s*|\s+)(?![-/][A-Za-z]|\$?(?:true|false|null)\b|\[REDACTED)(?:"[^"]*"|''[^'']*''|[^\s"'']+)')
        Replacement = '${k}${sep}[REDACTED]'
    }
    @{
        Name        = 'JsonWebToken'
        Description = 'JSON web tokens (eyJ....eyJ....signature)'
        Regex       = Get-CCFCompiledRegex -Pattern '\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*'
        Replacement = '[REDACTED]'
    }
    @{
        Name        = 'GitHubToken'
        Description = 'GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)'
        Regex       = Get-CCFCompiledRegex -Pattern '\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})'
        Replacement = '[REDACTED]'
    }
    @{
        Name        = 'AwsAccessKeyId'
        Description = 'AWS access key IDs (AKIA, ASIA and the other key ID prefixes)'
        Regex       = Get-CCFCompiledRegex -Pattern '\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b'
        Replacement = '[REDACTED]'
    }
    @{
        Name        = 'SlackToken'
        Description = 'Slack tokens (xoxa-, xoxb-, xoxp-, xoxo-, xoxs-, xoxr-)'
        Regex       = Get-CCFCompiledRegex -Pattern '\bxox[abposr]-[A-Za-z0-9-]{10,}'
        Replacement = '[REDACTED]'
    }
    @{
        Name        = 'StripeKey'
        Description = 'Stripe secret, restricted and publishable keys (sk_live_, rk_test_...)'
        Regex       = Get-CCFCompiledRegex -Pattern '\b[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}'
        Replacement = '[REDACTED]'
    }
    @{
        Name        = 'GoogleApiKey'
        Description = 'Google API keys (AIza...)'
        Regex       = Get-CCFCompiledRegex -Pattern '\bAIza[0-9A-Za-z_-]{35}'
        Replacement = '[REDACTED]'
    }
    @{
        Name        = 'NpmToken'
        Description = 'npm access tokens (npm_...)'
        Regex       = Get-CCFCompiledRegex -Pattern '\bnpm_[A-Za-z0-9]{36}'
        Replacement = '[REDACTED]'
    }
    @{
        Name        = 'SkApiKey'
        Description = 'API keys that start with sk- (used by several AI and payment services)'
        Regex       = Get-CCFCompiledRegex -Pattern '\bsk-[A-Za-z0-9_-]{20,}'
        Replacement = '[REDACTED]'
    }
)

$script:CCFKeyValueRegex = Get-CCFCompiledRegex -IgnoreCase -Pattern ("(?<![A-Za-z0-9_.-])(?<q>[""']?)(?<k>[A-Za-z0-9_.-]*(?:$($script:CCFLongSecretKeys))[A-Za-z0-9_.-]*|(?:$($script:CCFShortSecretKeys)))\k<q>(?<sep>\s*[:=]\s*)(?![""']?\[REDACTED)(?:""(?<dq>[^""]*)""|'(?<sq>[^']*)'|(?<v>[^\s,;&""'}\]]+))")

# Candidates for the entropy check: runs of 20 or more letters, digits, '_', '+' and '-' (plus
# base64 padding) that are not part of a path, a URL or a host name.
$script:CCFEntropyCandidateRegex = Get-CCFCompiledRegex -Pattern '(?<![A-Za-z0-9_+/\\.-])[A-Za-z0-9_+-]{20,}={0,2}(?![A-Za-z0-9_+=/\\-])(?!\.[A-Za-z0-9])'

$script:CCFGuidRegex = Get-CCFCompiledRegex -Pattern '^\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?$'
$script:CCFSidRegex = Get-CCFCompiledRegex -Pattern '^S-1-\d+(?:-\d+)+$'
$script:CCFHexRegex = Get-CCFCompiledRegex -Pattern '^[0-9A-Fa-f]+$'

# Terminal escape sequences and control characters. They are removed before any rule runs: a
# sequence inside a key ("pass<ESC>[0mword=...") would otherwise hide it from the rules, and the
# logger, which removes them afterwards, would then write the secret in clear.
# Line breaks and tabs are kept here (the logger escapes them).
$script:CCFOscSequenceRegex = Get-CCFCompiledRegex -Pattern '\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)?'
$script:CCFCsiSequenceRegex = Get-CCFCompiledRegex -Pattern '(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~]'
$script:CCFEscapeRegex = Get-CCFCompiledRegex -Pattern '\x1B[@-_]?'
$script:CCFControlCharRegex = Get-CCFCompiledRegex -Pattern '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]'

function ConvertTo-CCFPrintableText {
    <#
    .SYNOPSIS
        Removes ANSI escape sequences and control characters, except line breaks and tabs.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $clean = $script:CCFOscSequenceRegex.Replace($Text, '')
    $clean = $script:CCFCsiSequenceRegex.Replace($clean, '')
    $clean = $script:CCFEscapeRegex.Replace($clean, '')
    return $script:CCFControlCharRegex.Replace($clean, '')
}

function Sync-CCFSecretRegex {
    <#
    .SYNOPSIS
        Rebuilds the expression that matches the values registered with Register-CCFSecret.
    #>
    [CmdletBinding()]
    param()

    if ($script:CCFSecretValues.Count -eq 0) { $script:CCFSecretRegex = $null; return }
    # Longest first, so a secret that contains another one is replaced whole.
    $escaped = $script:CCFSecretValues | Sort-Object -Property Length -Descending | ForEach-Object { [regex]::Escape($_) }
    $script:CCFSecretRegex = Get-CCFCompiledRegex -Pattern ($escaped -join '|')
}

function Invoke-CCFTextRedaction {
    <#
    .SYNOPSIS
        Applies every redaction rule to one string. Fails closed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    try {
        $out = ConvertTo-CCFPrintableText -Text $Text
        if ($null -ne $script:CCFSecretRegex) { $out = $script:CCFSecretRegex.Replace($out, '[REDACTED]') }

        foreach ($rule in $script:CCFBuiltInRules) { $out = $rule.Regex.Replace($out, $rule.Replacement) }
        foreach ($name in @($script:CCFCustomPatterns.Keys)) {
            $rule = $script:CCFCustomPatterns[$name]
            $out = $rule.Regex.Replace($out, $rule.Replacement)
        }

        $out = $script:CCFKeyValueRegex.Replace($out, [System.Text.RegularExpressions.MatchEvaluator] {
                param($m)
                $value = if ($m.Groups['dq'].Success) { '"[REDACTED]"' } elseif ($m.Groups['sq'].Success) { "'[REDACTED]'" } else { '[REDACTED]' }
                $m.Groups['q'].Value + $m.Groups['k'].Value + $m.Groups['q'].Value + $m.Groups['sep'].Value + $value
            })

        $out = $script:CCFEntropyCandidateRegex.Replace($out, [System.Text.RegularExpressions.MatchEvaluator] {
                param($m)
                if (Test-CCFEntropyContent -String $m.Value) { '[REDACTED-ENTROPY]' } else { $m.Value }
            })
        return $out
    }
    catch {
        # A rule that times out or fails must not let the original text through.
        Write-Verbose "Redaction failed, the text was replaced: $($_.Exception.Message)"
        return '[REDACTED: the text could not be checked for secrets]'
    }
}

function ConvertTo-CCFRedactedValue {
    <#
    .SYNOPSIS
        Recursive worker behind Protect-CCFSensitiveData.
    #>
    [CmdletBinding()]
    [OutputType([string], [hashtable], [System.Collections.Specialized.OrderedDictionary], [pscustomobject], [object[]], [object])]
    param(
        [AllowNull()][AllowEmptyString()][object]$InputData,
        [int]$Depth = 0
    )

    if ($null -eq $InputData) { return $null }
    if ($InputData -is [string]) { return (Invoke-CCFTextRedaction -Text $InputData) }
    if ($InputData -is [System.Security.SecureString]) { return '[REDACTED]' }
    if ($InputData -is [System.Management.Automation.PSCredential]) {
        return [pscustomobject]@{ UserName = (Invoke-CCFTextRedaction -Text $InputData.UserName); Password = '[REDACTED]' }
    }
    if ($InputData -is [System.Net.NetworkCredential]) {
        return [pscustomobject]@{ UserName = (Invoke-CCFTextRedaction -Text $InputData.UserName); Domain = $InputData.Domain; Password = '[REDACTED]' }
    }
    if ($InputData -is [ValueType]) { return $InputData }
    if ($Depth -gt 5) { return '[DEPTH-LIMIT]' }

    $isDictionary = $InputData -is [System.Collections.IDictionary]
    $isCustomObject = $InputData -is [System.Management.Automation.PSCustomObject]
    if ($isDictionary -or $isCustomObject) {
        $newData = [ordered]@{}
        $keys = if ($isDictionary) { @($InputData.Keys) } else { @($InputData.PSObject.Properties.Name) }
        foreach ($key in $keys) {
            # Assigned inside the branches: "$val = if ..." would unroll a one-item array.
            if ($isDictionary) { $val = $InputData[$key] } else { $val = $InputData.$key }

            # The key is checked without control characters, which could otherwise hide its name.
            $isSecret = $script:CCFKeyNameRegex.IsMatch((ConvertTo-CCFPrintableText -Text ([string]$key))) -and -not ($val -is [bool])
            if (-not $isSecret -and $val -is [string] -and (Test-CCFEntropyContent -String $val)) { $isSecret = $true }

            if ($isSecret) { $newData[$key] = '[REDACTED]' }
            elseif ($Depth -ge 5 -and $null -ne $val -and -not ($val -is [ValueType])) { $newData[$key] = '[DEPTH-LIMIT]' }
            else { $newData[$key] = ConvertTo-CCFRedactedValue -InputData $val -Depth ($Depth + 1) }
        }

        if ($isCustomObject) { return [pscustomobject]$newData }
        if ($InputData -is [System.Collections.Specialized.OrderedDictionary]) { return $newData }
        $result = @{}
        foreach ($key in $newData.Keys) { $result[$key] = $newData[$key] }
        return $result
    }

    if ($InputData -is [System.Collections.IEnumerable]) {
        $items = foreach ($item in $InputData) { , (ConvertTo-CCFRedactedValue -InputData $item -Depth ($Depth + 1)) }
        return , @($items)
    }

    # Any other object: its text form, redacted. Its properties are not serialized, so objects
    # that carry a password in a property cannot leak it.
    return (Invoke-CCFTextRedaction -Text ([string]$InputData))
}

# --- Public commands ---

function Test-CCFEntropyContent {
    <#
    .SYNOPSIS
        Tests whether a string looks like a random secret, such as an API key or a token.

    .DESCRIPTION
        Returns $true for strings of 20 or more characters without spaces, '\', '/' or ':' that
        mix upper case letters, lower case letters and digits with no run of more than six lower
        case letters in a row (random strings rarely have one; words and identifiers such as
        Win32_OperatingSystem do), and for strings of 32 or more characters that mix two of
        those kinds with at least one digit in five characters.
        GUIDs, Windows SIDs and hexadecimal strings (hashes, certificate thumbprints) are never
        flagged: they are common in logs and are not secrets.
        Protect-CCFSensitiveData uses it for values that are not labeled as secrets. It is a
        heuristic: it can miss secrets and flag harmless identifiers.

    .PARAMETER String
        The text to test.

    .EXAMPLE
        Test-CCFEntropyContent -String 'Xk9fQ2mLp7RtZ4vNw8Bc'

        Returns $true.

    .EXAMPLE
        Test-CCFEntropyContent -String '3f2504e0-4f89-11d3-9a0c-0305e82c3301'

        Returns $false: GUIDs are not treated as secrets.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$String
    )

    if ([string]::IsNullOrEmpty($String) -or $String.Length -lt 20 -or $String -match '\s') { return $false }
    if ($String -match '[\\/:]') { return $false }
    $core = $String.TrimEnd('=')
    if ($script:CCFGuidRegex.IsMatch($core) -or $script:CCFSidRegex.IsMatch($core) -or $script:CCFHexRegex.IsMatch($core)) { return $false }

    $upper = $String -cmatch '[A-Z]'
    $lower = $String -cmatch '[a-z]'
    $digits = ([regex]::Matches($String, '[0-9]')).Count
    $longestLowerRun = 0
    foreach ($run in [regex]::Matches($String, '[a-z]+')) { if ($run.Length -gt $longestLowerRun) { $longestLowerRun = $run.Length } }

    if ($upper -and $lower -and $digits -gt 0 -and $longestLowerRun -le 6) { return $true }
    $kinds = @($upper, $lower, ($digits -gt 0)) | Where-Object { $_ }
    return ($String.Length -ge 32 -and @($kinds).Count -ge 2 -and $digits * 5 -ge $String.Length)
}

function Protect-CCFSensitiveData {
    <#
    .SYNOPSIS
        Returns a copy of the data with passwords, tokens, keys and other secrets replaced by [REDACTED].

    .DESCRIPTION
        ANSI escape sequences and control characters other than line breaks and tabs are
        removed from strings first, so they cannot hide a key from the rules. Strings are then
        checked, in this order, for values registered with Register-CCFSecret; for private key
        blocks, passwords in URLs, Authorization headers, bearer tokens and connection strings;
        for XML elements (<Password>...</Password>), command-line parameters (-Password value,
        --token value) and the text passed to ConvertTo-SecureString; for GitHub, AWS, Slack,
        Stripe, Google, npm and sk- keys and JSON web tokens; for patterns added with
        Register-CCFRedactionPattern; for key/value pairs whose key names a secret
        ("password=...", "token: ...", JSON "apiKey": "...", also in Spanish, German, French,
        Portuguese and Dutch); and for words that look like random secrets (see
        Test-CCFEntropyContent), which become [REDACTED-ENTROPY]. Get-CCFRedactionPattern lists
        the rules.

        Hashtables and objects are copied: values whose key names a secret (password, token,
        secret, apikey, authorization, cookie, credential...) or that look like secrets become
        [REDACTED] (true/false values are kept), and everything else is checked recursively,
        including arrays. SecureString values become [REDACTED]; PSCredential and
        NetworkCredential objects keep only the user name. Other objects are replaced by their
        text form, redacted, so a password in one of their properties cannot leak. Values
        nested more than five levels deep become [DEPTH-LIMIT].

        Every rule has a time limit. If a rule runs out of time or fails, the whole string is
        replaced instead of being returned unchecked. The input is not modified.
        Write-CCFLog applies this to every message and its data. Use it directly to redact
        text before passing it to another logger, such as Write-PSFMessage or Write-Verbose.
        The alias Redact-CCFSensitiveData is kept for older scripts.

    .PARAMETER InputData
        A string, hashtable, object or array to redact. Accepts pipeline input.

    .PARAMETER Depth
        Current nesting level, used internally for recursion. Leave it at 0.

    .EXAMPLE
        Protect-CCFSensitiveData -InputData 'login user=admin password=Secr3t!'

        Returns "login user=admin password=[REDACTED]".

    .EXAMPLE
        Protect-CCFSensitiveData -InputData 'Server=db01;User Id=sa;Password=P@ss w0rd;Encrypt=True'

        Returns "Server=db01;User Id=sa;Password=[REDACTED];Encrypt=True".

    .EXAMPLE
        Protect-CCFSensitiveData -InputData @{ User = 'admin'; ApiKey = 'abc' }

        Returns a hashtable where ApiKey is "[REDACTED]".

    .EXAMPLE
        Write-PSFMessage -Message (Protect-CCFSensitiveData "Calling $uri with $headers")

        Redacts the message before PSFramework writes it.
    #>
    [CmdletBinding()]
    [OutputType([string], [hashtable], [pscustomobject], [object[]], [object])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [object]$InputData,

        [int]$Depth = 0
    )

    process {
        $result = ConvertTo-CCFRedactedValue -InputData $InputData -Depth $Depth
        if ($result -is [array]) { return , $result }
        return $result
    }
}

function Register-CCFSecret {
    <#
    .SYNOPSIS
        Registers values that must never appear in a log, wherever they show up.

    .DESCRIPTION
        From now on, in this session, every occurrence of each value is replaced by [REDACTED]
        in everything ArgosCCF redacts: log messages and data, Protect-CCFSensitiveData and
        Protect-CCFLogFile. The URL-encoded form of each value is registered too.
        Use it for the passwords, keys and tokens your script reads or receives: they are
        redacted even in formats no rule knows, such as an error message that quotes them.
        Values are kept in memory only, for the current session, and are compared exactly
        (case-sensitive). Values shorter than 4 characters are refused, since they would
        remove ordinary text. Unregister-CCFSecret removes them.

    .PARAMETER Value
        One or more secret values as plain text. Accepts pipeline input.

    .PARAMETER SecureString
        A secret stored as a SecureString.

    .PARAMETER Credential
        A credential whose password is registered (the user name is not a secret and stays).

    .EXAMPLE
        $token = (Get-Secret -Name 'Deploy').GetNetworkCredential().Password; Register-CCFSecret -Value $token

        Redacts the deployment token from every later log entry.

    .EXAMPLE
        Register-CCFSecret -Credential $cred

        Redacts the password of $cred wherever it appears.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Value')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Value', ValueFromPipeline = $true, Position = 0)]
        [ValidateScript({ if ($_.Length -ge 4) { $true } else { throw 'Secret values must have at least 4 characters.' } })]
        [string[]]$Value,

        [Parameter(Mandatory = $true, ParameterSetName = 'SecureString')]
        [System.Security.SecureString]$SecureString,

        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        $plain = switch ($PSCmdlet.ParameterSetName) {
            'Value' { $Value }
            'SecureString' { [System.Net.NetworkCredential]::new('', $SecureString).Password }
            'Credential' { $Credential.GetNetworkCredential().Password }
        }
        foreach ($secret in @($plain)) {
            if ([string]::IsNullOrEmpty($secret) -or $secret.Length -lt 4) {
                Write-Error 'Secret values must have at least 4 characters; the value was not registered.'
                continue
            }
            foreach ($form in @($secret, [uri]::EscapeDataString($secret)) | Select-Object -Unique) {
                if (-not $script:CCFSecretValues.Contains($form)) { $script:CCFSecretValues.Add($form) }
            }
        }
        Sync-CCFSecretRegex
    }
}

function Unregister-CCFSecret {
    <#
    .SYNOPSIS
        Removes values registered with Register-CCFSecret.

    .DESCRIPTION
        Removes the given values (and their URL-encoded forms), or all of them with -All, so
        they are no longer redacted by value. The other rules keep working.

    .PARAMETER Value
        The values to remove.

    .PARAMETER All
        Remove every registered value.

    .EXAMPLE
        Unregister-CCFSecret -All

        Forgets every registered secret.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Value')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Value', ValueFromPipeline = $true, Position = 0)]
        [string[]]$Value,

        [Parameter(Mandatory = $true, ParameterSetName = 'All')]
        [switch]$All
    )

    process {
        if ($All) { $script:CCFSecretValues.Clear() }
        else {
            foreach ($secret in $Value) {
                $null = $script:CCFSecretValues.Remove($secret)
                $null = $script:CCFSecretValues.Remove([uri]::EscapeDataString($secret))
            }
        }
        Sync-CCFSecretRegex
    }
}

function Register-CCFRedactionPattern {
    <#
    .SYNOPSIS
        Adds a regular expression whose matches are redacted, for secret formats specific to your environment.

    .DESCRIPTION
        Matches are replaced by -Replacement (by default [REDACTED]) in everything ArgosCCF
        redacts, after the built-in rules and before the key/value and entropy rules. A pattern
        with the same name replaces the earlier one. The pattern must compile, and it gets the
        same time limit as the built-in rules: if it runs out of time on some text, that whole
        text is replaced, so write patterns that cannot backtrack for long.
        Patterns last for the current session.

    .PARAMETER Name
        Name of the pattern. Letters, digits, '.', '-' and '_'. Must not be a built-in rule name.

    .PARAMETER Pattern
        The regular expression (.NET syntax). Matching is case-sensitive unless the pattern
        starts with (?i).

    .PARAMETER Replacement
        The replacement text. Can refer to named groups, as in '${user}:[REDACTED]'.
        Defaults to [REDACTED].

    .EXAMPLE
        Register-CCFRedactionPattern -Name 'ContosoKey' -Pattern '\bCTS-[0-9A-F]{24}\b'

        Redacts Contoso API keys wherever they appear.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern('^[A-Za-z0-9._-]+$')]
        [string]$Name,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Pattern,

        [string]$Replacement = '[REDACTED]'
    )

    if ($script:CCFBuiltInRules.Name -contains $Name -or $Name -in 'KeyValue', 'Entropy', 'RegisteredSecret') {
        throw "'$Name' is the name of a built-in rule. Choose another name."
    }
    try { $regex = Get-CCFCompiledRegex -Pattern $Pattern }
    catch { throw "The pattern is not a valid regular expression: $($_.Exception.Message)" }

    $script:CCFCustomPatterns[$Name] = @{ Regex = $regex; Replacement = $Replacement }
}

function Unregister-CCFRedactionPattern {
    <#
    .SYNOPSIS
        Removes a pattern added with Register-CCFRedactionPattern.

    .DESCRIPTION
        Removes the named pattern. Built-in rules cannot be removed. Writes an error if no
        pattern has that name.

    .PARAMETER Name
        Name of the pattern to remove. Accepts pipeline input by property name, so the output
        of Get-CCFRedactionPattern -Source Custom can be piped.

    .EXAMPLE
        Unregister-CCFRedactionPattern -Name 'ContosoKey'

        Stops redacting Contoso keys by pattern.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$Name
    )

    process {
        if ($script:CCFCustomPatterns.Contains($Name)) { $script:CCFCustomPatterns.Remove($Name) }
        elseif ($script:CCFBuiltInRules.Name -contains $Name) { Write-Error "'$Name' is a built-in rule and cannot be removed." }
        else { Write-Error "No redaction pattern is named '$Name'." }
    }
}

function Get-CCFRedactionPattern {
    <#
    .SYNOPSIS
        Lists the redaction rules, in the order they are applied.

    .DESCRIPTION
        Returns one object per rule with its Name, Source (BuiltIn, Custom or Registered),
        Description, Pattern and Replacement: registered secret values (count only, never the
        values), the built-in rules, the patterns added with Register-CCFRedactionPattern, and
        the key/value and entropy rules.

    .PARAMETER Source
        Return only BuiltIn, Custom or Registered rules.

    .EXAMPLE
        Get-CCFRedactionPattern | Format-Table Name, Source, Description

        Shows what is redacted and in which order.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('BuiltIn', 'Custom', 'Registered')]
        [string]$Source
    )

    $rules = @(
        [pscustomobject]@{ Name = 'RegisteredSecret'; Source = 'Registered'; Description = "Values registered with Register-CCFSecret ($($script:CCFSecretValues.Count) registered)"; Pattern = $null; Replacement = '[REDACTED]' }
    )
    $rules += foreach ($rule in $script:CCFBuiltInRules) {
        [pscustomobject]@{ Name = $rule.Name; Source = 'BuiltIn'; Description = $rule.Description; Pattern = $rule.Regex.ToString(); Replacement = $rule.Replacement }
    }
    $rules += foreach ($name in @($script:CCFCustomPatterns.Keys)) {
        $rule = $script:CCFCustomPatterns[$name]
        [pscustomobject]@{ Name = $name; Source = 'Custom'; Description = 'Added with Register-CCFRedactionPattern'; Pattern = $rule.Regex.ToString(); Replacement = $rule.Replacement }
    }
    $rules += [pscustomobject]@{ Name = 'KeyValue'; Source = 'BuiltIn'; Description = 'key=value, key: value and "key": "value" pairs whose key names a secret (password, token, secret, api key, cookie...)'; Pattern = $script:CCFKeyValueRegex.ToString(); Replacement = '[REDACTED]' }
    $rules += [pscustomobject]@{ Name = 'Entropy'; Source = 'BuiltIn'; Description = 'Words that look like random secrets (Test-CCFEntropyContent)'; Pattern = $script:CCFEntropyCandidateRegex.ToString(); Replacement = '[REDACTED-ENTROPY]' }

    if ($Source) { $rules = @($rules | Where-Object Source -EQ $Source) }
    return $rules
}

function Protect-CCFLogFile {
    <#
    .SYNOPSIS
        Writes a redacted copy of a log or transcript file.

    .DESCRIPTION
        Reads the file line by line and writes every line through the same rules as
        Protect-CCFSensitiveData. Private key blocks that span several lines are replaced as a
        whole. ANSI escape sequences (colors) and control characters are removed from the copy;
        they are not counted as redactions. Use it on transcripts (Start-Transcript), logs
        written by other tools, or old logs, before sharing or archiving them.
        By default the copy is written next to the file as <name>.redacted<extension>. To
        overwrite the original, pass it as -Destination as well, with -Force. Returns the source,
        the destination and the number of redactions. Supports -WhatIf and -Confirm.

    .PARAMETER Path
        The file to redact. Accepts pipeline input, including Get-ChildItem output.

    .PARAMETER Destination
        Where to write the redacted copy. Defaults to <name>.redacted<extension> in the same folder.

    .PARAMETER Force
        Overwrite the destination if it exists.

    .EXAMPLE
        Start-Transcript -Path .\deploy.txt; .\Deploy.ps1; Stop-Transcript; Protect-CCFLogFile -Path .\deploy.txt

        Writes deploy.redacted.txt without the secrets the deployment printed.

    .EXAMPLE
        Get-ChildItem C:\Logs -Filter *.log | Protect-CCFLogFile -WhatIf

        Shows which redacted copies would be written.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName')]
        [string]$Path,

        [string]$Destination,

        [switch]$Force
    )

    process {
        $source = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            Write-Error "File not found: $Path"
            return
        }
        $target = if ($Destination) {
            $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Destination)
        }
        else {
            $folder = [System.IO.Path]::GetDirectoryName($source)
            Join-Path $folder ([System.IO.Path]::GetFileNameWithoutExtension($source) + '.redacted' + [System.IO.Path]::GetExtension($source))
        }
        $inPlace = [string]::Equals([System.IO.Path]::GetFullPath($source), [System.IO.Path]::GetFullPath($target), [StringComparison]::OrdinalIgnoreCase)
        if ((Test-Path -LiteralPath $target) -and -not $Force) {
            Write-Error "The destination already exists; use -Force to overwrite it: $target"
            return
        }
        if (-not $PSCmdlet.ShouldProcess($target, "Write a redacted copy of $source")) { return }

        $temp = "$target.$([guid]::NewGuid().ToString('N')).tmp"
        $count = 0
        $reader = [System.IO.StreamReader]::new($source, [System.Text.UTF8Encoding]::new($false), $true)
        $writer = [System.IO.StreamWriter]::new($temp, $false, [System.Text.UTF8Encoding]::new($true))
        try {
            $inKey = $false
            while ($null -ne ($line = $reader.ReadLine())) {
                if ($inKey) {
                    if ($line -match '-----END [A-Z0-9 ]*PRIVATE KEY-----') { $inKey = $false }
                    continue
                }
                if ($line -match '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----' -and $line -notmatch '-----END [A-Z0-9 ]*PRIVATE KEY-----') {
                    $prefix = $line.Substring(0, $line.IndexOf('-----BEGIN'))
                    $writer.WriteLine((Invoke-CCFTextRedaction -Text $prefix) + '[REDACTED-PRIVATE-KEY]')
                    $count++
                    $inKey = $true
                    continue
                }
                # Escape sequences (colors in a transcript) are removed but do not count as redactions.
                $plain = ConvertTo-CCFPrintableText -Text $line
                $clean = Invoke-CCFTextRedaction -Text $plain
                if ($clean -cne $plain) { $count += [math]::Max(1, ([regex]::Matches($clean, '\[REDACTED')).Count - ([regex]::Matches($plain, '\[REDACTED')).Count) }
                $writer.WriteLine($clean)
            }
        }
        finally {
            $reader.Dispose()
            $writer.Dispose()
        }

        Move-Item -LiteralPath $temp -Destination $target -Force
        [pscustomobject]@{ Source = $source; Destination = $target; Redactions = $count; InPlace = $inPlace }
    }
}
