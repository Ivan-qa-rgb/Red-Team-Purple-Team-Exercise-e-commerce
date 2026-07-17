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





  
