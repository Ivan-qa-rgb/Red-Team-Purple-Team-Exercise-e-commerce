# PowerShell: Hunt IoC после Purple Team Exercise

# 1. Поиск WMI Event Subscription
Write-Host "[*] Проверка WMI Event Subscription..." -ForegroundColor Cyan
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | 
    Select-Object Name, Query | Format-Table -AutoSize

Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer | 
    Select-Object Name, CommandLineTemplate | Format-Table -AutoSize

# 2. Поиск подозрительных Scheduled Tasks
Write-Host "[*] Поиск подозрительных Scheduled Tasks..." -ForegroundColor Cyan
Get-ScheduledTask | Where-Object {
    $_.TaskPath -eq "\" -and
    ($_.TaskName -like "*Update*" -or $_.TaskName -like "*System*" -or $_.TaskName -like "*Svc*")
} | Select-Object TaskName, State, Author | Format-Table -AutoSize

# 3. Поиск скриптов в системных директориях
Write-Host "[*] Поиск скриптов в C:\Windows\Tasks..." -ForegroundColor Cyan
Get-ChildItem "C:\Windows\Tasks\" -Include *.ps1,*.bat,*.vbs,*.js -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, Length | Format-Table -AutoSize

# 4. Анализ журналов Security (Event ID 4698, 4688, 4769)
Write-Host "[*] Анализ журналов Security..." -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4698; StartTime=(Get-Date).AddDays(-7)} |
    Select-Object TimeCreated, Id, Message | Format-Table -Wrap

# 5. Проверка DNS-запросов
Write-Host "[*] Проверка DNS-запросов (требуется Zeek/Wireshark)..." -ForegroundColor Yellow

Write-Host "[+] Hunt завершён" -ForegroundColor Green
