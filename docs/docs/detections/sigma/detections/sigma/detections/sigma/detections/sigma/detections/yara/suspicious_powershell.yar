rule Suspicious_PowerShell_PurpleTeam_2026
{
    meta:
        description = "Detects suspicious PowerShell patterns from Purple Team Exercise"
        author = "[Твоё имя]"
        date = "2026-07-17"
        reference = "Purple Team Exercise: Retail/E-commerce"
    
    strings:
        $a1 = "Invoke-Expression" nocase
        $a2 = "IEX" nocase
        $a3 = "DownloadString" nocase
        $a4 = "DownloadFile" nocase
        $a5 = "Invoke-WebRequest" nocase
        $a6 = "Net.WebClient" nocase
        $a7 = "FromBase64String" nocase
        
        $b1 = "-enc" nocase
        $b2 = "-encodedcommand" nocase
        $b3 = "-ExecutionPolicy Bypass" nocase
        $b4 = "-NoProfile" nocase
        
        $c1 = "__EventFilter" nocase
        $c2 = "__EventConsumer" nocase
        $c3 = "__FilterToConsumerBinding" nocase
        $c4 = "root\\subscription" nocase
    
    condition:
        filesize < 500KB and
        (
            (2 of ($a*)) or
            (1 of ($b*) and 1 of ($a*)) or
            (2 of ($c*))
        )
}
