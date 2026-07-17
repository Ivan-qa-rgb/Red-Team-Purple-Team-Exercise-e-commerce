# Приложение B: MITRE ATT&CK Mapping

## Использованные техники

| Фаза атаки | Тактика | Техника | ID | Подтехника | Детектировано |
|------------|---------|---------|-----|-----------|---------------|
| Reconnaissance | Reconnaissance | Gather Victim Identity Information | T1589 | — | N/A |
| Reconnaissance | Reconnaissance | Gather Victim Network Info | T1590 | — | N/A |
| Initial Access | Initial Access | Phishing | T1566 | T1566.001 | ❌ Нет |
| Execution | Execution | Command and Scripting Interpreter | T1059 | T1059.001 | ✅ Да |
| Execution | Execution | User Execution | T1204 | T1204.002 | ❌ Нет |
| Persistence | Persistence | Event Triggered Execution | T1546 | T1546.003 | ❌ Нет |
| Privilege Escalation | Credential Access | Steal or Forge Kerberos Tickets | T1558 | T1558.003 | ❌ Нет |
| Defense Evasion | Defense Evasion | Impair Defenses | T1562 | T1562.001 | ❌ Нет |
| Defense Evasion | Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | — | ❌ Нет |
| Defense Evasion | Defense Evasion | Indicator Removal | T1070 | T1070.006 | ❌ Нет |
| Discovery | Discovery | System Information Discovery | T1082 | — | ❌ Нет |
| Lateral Movement | Lateral Movement | Remote Services | T1021 | T1021.001 | ❌ Нет |
| Collection | Collection | Data from Local System | T1005 | — | ❌ Нет |
| Exfiltration | Exfiltration | Exfiltration Over Alternative Protocol | T1048 | T1048.003 | ❌ Нет |
| Command and Control | Command and Control | Application Layer Protocol | T1071 | T1071.001 | ❌ Нет |

## Детекты, разработанные после упражнения

| Техника | Детект | Статус |
|---------|--------|--------|
| T1566.001 | CORR-001: Макрос + PowerShell | ✅ Внедрён |
| T1059.001 | Sigma: PowerShell encoded command | ✅ Внедрён |
| T1546.003 | Sigma: WMI Event Subscription | ✅ Внедрён |
| T1558.003 | CORR-003: Kerberoasting | ✅ Внедрён |
| T1021.001 | CORR-005: RDP Lateral Movement | ✅ Внедрён |
| T1048.003 | CORR-006: DNS Tunneling | ✅ Внедрён |
| T1071.001 | CORR-007: HTTP Beaconing | ✅ Внедрён |
