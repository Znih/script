#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           winlog-date.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\winlog-date.ps1
# DESCRIPTION:    summary eventlog entries witch date
#
# OPTION:         .\powershell.exe .\winlog-date.ps1 -p <string> -l <string> -d <date>
#                 ProtokollParameter:   application 'Windows PowerShell' HardwareEvents Security System
#                 LoglevelParameter:    Error FailureAudit Information SuccessAudit Warning
#
# eg.             Period Error Log Entries .\powershell.exe .\winlog-date.ps1 -p system -l error -d 01.02.2015
#                 Period Warning Log Entries .\powershell.exe .\winlog-date.ps1 -p system -l warning -d 14.02.2015
#
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0 & textfile
# BUGS:
# NOTES:          check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
# AUTHOR:         Marco Hinz
# COMPANY:        Justice
# VERSION:        1.0.3
# CREATED:        22.02.2015 - 22:26
# REVISION:       24.02.2015, 26.02.2015
# MAINTAINER:     Marco Hinz <https://github.com/hinzigers>
#=============================================================================

# see write-host vs echo
Param([string] $p,
      [string] $l,
      [string] $d)
      [string] $b = Get-Date -format d
      [string] $date = Get-Date -format o
      [string] $servers = "C:\Windows\System32\WindowsPowerShell\v1.0\computerlist.txt"

If (Test-Path C:\EventLog){
    # File exists
}Else{
    ni -path c:\ -name EventLogs -itemtype directory -force
    wh
    wh
}
wh "Help:"
wh "-----"
wh
wh "[-p] eg. Protokoll (application, 'Windows PowerShell', HardwareEvents, Security, System)"
wh "[-l] eg. LogLevel (Error, FailureAudit, Information, SuccessAudit, warning)"
wh "[-d] eg. StartDate (dd.mm.yyyy)"
wh
wh "Write the '$p' '$l' log entries from '$d' to '$b'into '$LOGDIR'..."

    $timestamp = Get-Date -Format '_yyyy-MM-dd_hh-mm-ss'
    $LOGDIR = '{0}\EventLogs\serverlogs{1}.csv' -f $env:HOMEDRIVE, $timestamp
wh
wh "Show servers:"
wh "-------------"
wh
wh (gc -path "$Servers")
wh "."
wh ".."
gel -LogName $p -cn (gc -path $servers) -EntryType $l -after $d -before $b | `
Select Index,EventID,MachineName,Category,CategoryNumber,EntryType,source,@{Name="MyMSG"; Expression = {$_.Message -replace "`r`n", ""}} | `
export-csv $LOGDIR -notypeinformation -delimiter "`t" -encoding utf8
wh "..."
wh "Done."
sleep -seconds 1
