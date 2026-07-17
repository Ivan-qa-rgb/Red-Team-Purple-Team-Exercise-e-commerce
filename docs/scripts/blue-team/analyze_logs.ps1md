# PowerShell: Анализ логов после Purple Team Exercise

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
