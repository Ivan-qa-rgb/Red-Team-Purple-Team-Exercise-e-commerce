## detections/sigma/wmi_event_subscription.yml
title: WMI Event Subscription Persistence
id: 9b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: |
  Обнаружение создания WMI Event Subscription для persistence.
  Злоумышленники используют WMI для закрепления без создания файлов на диске.
  Результат Purple Team Exercise, ритейл/e-commerce, июль 2026.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'New-CimInstance'
      - '__EventFilter'
      - '__EventConsumer'
      - '__FilterToConsumerBinding'
      - 'root\\subscription'
  condition: selection
falsepositives:
  - Легитимное администрирование WMI
  - Системы мониторинга (SCOM и др.)
level: high
tags:
  - attack.persistence
  - attack.t1546.003
  - detection.purple-team-2026

##  detections/sigma/kerberoasting_detection.yml
title: Kerberoasting Detection
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: |
  Обнаружение аномального количества запросов TGS (Kerberoasting).
  Злоумышленники запрашивают TGS-билеты для сервисных учёток с целью оффлайн-крэкинга.
  Результат Purple Team Exercise, ритейл/e-commerce, июль 2026.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketOptions: '0x40810010'
    TicketEncryptionType:
      - '0x17'
      - '0x1'
  timeframe: 10m
  condition: selection | count() > 5
falsepositives:
  - Сервисные окна обслуживания
  - Легитимные сканеры безопасности
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
  - detection.purple-team-2026
    
## detections/sigma/dns_tunneling.yml
title: DNS Tunneling Detection
id: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: |
  Обнаружение DNS-туннелирования через анализ поддоменов.
  Злоумышленники кодируют данные в base64 и отправляют через DNS-запросы.
  Результат Purple Team Exercise, ритейл/e-commerce, июль 2026.
logsource:
  category: dns
detection:
  selection_length:
    query|re: '^([A-Za-z0-9+/]{50,}\\.)+[A-Za-z]{2,}$'
  selection_tld:
    query|endswith:
      - '.tk'
      - '.ml'
      - '.ga'
      - '.cf'
      - '.xyz'
      - '.top'
  condition: selection_length or selection_tld
falsepositives:
  - CDN с длинными хешами в поддоменах
  - Легитимные DGA-like домены
level: medium
tags:
  - attack.exfiltration
  - attack.t1048.003
  - detection.purple-team-2026

## detections/sigma/scheduled_task_powershell.yml
title: Suspicious Scheduled Task with PowerShell
id: 3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f
status: experimental
description: |
  Обнаружение создания Scheduled Task с запуском PowerShell.
  Часто используется для persistence и обхода политик выполнения.
  Результат Purple Team Exercise, ритейл/e-commerce, июль 2026.
logsource:
  category: process_creation
  product: windows
detection:
  selection_schtasks:
    CommandLine|contains:
      - 'schtasks'
      - '/Create'
  selection_powershell:
    CommandLine|contains:
      - 'powershell'
      - 'powershell.exe'
      - 'pwsh'
  selection_bypass:
    CommandLine|contains:
      - '-ExecutionPolicy Bypass'
      - '-ExecutionPolicy Unrestricted'
      - '-nop'
      - '-NoProfile'
  condition: selection_schtasks and selection_powershell and selection_bypass
falsepositives:
  - Легитимные административные скрипты
  - Системы развёртывания ПО
level: high
tags:
  - attack.persistence
  - attack.t1053.005
  - detection.purple-team-2026
    
## detections/yara/suspicious_powershell.yar
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



  
