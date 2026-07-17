# Приложение D: IR-плейбуки (обновлённые после упражнения)

## IR-001: Фишинг с макросами

### Триггер
- Alert: CORR-001 (Макрос + PowerShell)
- Письмо с вложением .docm/.xlsm от нового домена

### Шаги
1. Изолировать рабочую станцию получателя
2. Проверить запущенные процессы: `winword.exe` → `powershell.exe`
3. Собрать forensic-образ памяти
4. Проверить почтовый ящик: пересылки, правила
5. Просканировать всех получателей этого письма
6. Заблокировать домен отправителя на почтовом шлюзе

## IR-002: WMI Event Subscription

### Триггер
- Alert: CORR-004 (WMI Persistence)
- Sigma: WMI Event Subscription

### Шаги
1. Проверить WMI подписки:
   ```powershell
   Get-WmiObject -Class __EventFilter -Namespace root\subscription
