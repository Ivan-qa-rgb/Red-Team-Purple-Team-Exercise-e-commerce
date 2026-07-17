# 📄 detections/sigma/powershell_encoded_command.yml

```yaml
title: PowerShell Encoded Command Execution
id: 8a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: |
  Обнаружение запуска PowerShell с encoded payload.
  Используется злоумышленниками для обхода детектов на уровне командной строки.
  Результат Purple Team Exercise, ритейл/e-commerce, июль 2026.
logsource:
  category: process_creation
  product: windows
detection:
  selection_powershell:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_encoded:
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
      - '-e '
  selection_download:
    CommandLine|contains:
      - 'DownloadString'
      - 'DownloadFile'
      - 'IEX'
      - 'Invoke-Expression'
  condition: selection_powershell and (selection_encoded or selection_download)
falsepositives:
  - Легитимные административные скрипты
  - Системы автоматизации (SCCM, Intune)
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - detection.purple-team-2026

    
    

  
