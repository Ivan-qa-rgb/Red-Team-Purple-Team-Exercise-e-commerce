# PowerShell: Hunt IoC после Purple Team Exercise
# Автор: [Твоё имя]
# Дата: 2026-07-17

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

scripts/blue-team/analyze_logs.ps1
# PowerShell: Анализ логов после Purple Team Exercise
# Автор: [Твоё имя]

param(
    [string]$LogPath = "C:\Logs\",
    [int]$Days = 7
)

$StartTime = (Get-Date).AddDays(-$Days)

# Event ID 4688: Process Creation (PowerShell)
Write-Host "[*] Анализ Event ID 4688 (Process Creation)..."
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=$StartTime} |
    Where-Object { $_.Message -like "*powershell*" -or $_.Message -like "*cmd*" } |
    Select-Object TimeCreated, @{N='Command';E={$_.Properties[8].Value}} |
    Export-Csv "$LogPath\powershell_execution.csv" -NoTypeInformation

# Event ID 4698: Scheduled Task Created
Write-Host "[*] Анализ Event ID 4698 (Scheduled Tasks)..."
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4698; StartTime=$StartTime} |
    Select-Object TimeCreated, @{N='TaskName';E={$_.Properties[1].Value}}, 
                  @{N='Author';E={$_.Properties[2].Value}} |
    Export-Csv "$LogPath\scheduled_tasks.csv" -NoTypeInformation

# Event ID 4769: Kerberos Service Ticket (Kerberoasting)
Write-Host "[*] Анализ Event ID 4769 (Kerberoasting)..."
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769; StartTime=$StartTime} |
    Group-Object -Property { $_.Properties[0].Value } |
    Where-Object { $_.Count -gt 5 } |
    Select-Object Name, Count |
    Export-Csv "$LogPath\kerberoasting.csv" -NoTypeInformation

Write-Host "[+] Анализ завершён. Результаты в $LogPath"

