rule Suspicious_PowerShell_Base64
{
    meta:
        description = "Detects PowerShell command with base64 encoded payload"
        author = "Silas"
        date = "2025-08-11"
        threat = "Possible obfuscated PowerShell attack"
    strings:
        $ps_base64 = /powershell.*-encodedcommand\s+[A-Za-z0-9+/=]{20,}/ nocase
    condition:
        $ps_base64
}
