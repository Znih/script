#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           winlog.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\winlog.ps1
# DESCRIPTION:    last summary eventlog entries
#
# OPTION:         .\powershell.exe .\winlog.ps1 -p <string> -l <string> -n <newest>
#                 ProtokollParameter:   application 'Windows PowerShell' HardwareEvents Security System
#                 LoglevelParameter:    Error FailureAudit Information SuccessAudit Warning
#
# eg.             Last Error Log Entries .\powershell.exe .\winlog.ps1 -p system -l error -n 5
#                 Last Warning Log Entries .\powershell.exe .\winlog.ps1 -p system -l warning -n 15
#
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0 & textfile
# BUGS:           
# NOTES:          check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
# AUTHOR:         Marco Hinz
# COMPANY:        Justice
# VERSION:        1.0.3
# CREATED:        21.02.2015 - 22:12
# REVISION:       24.02.2015, 26.02.2015
# MAINTAINER:     Marco Hinz <https://github.com/hinzigers>
#=============================================================================

# see write-host vs echo
Param([string] $p,
      [string] $l,
      [int16] $n)
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
#Get-EventLog -list | format-table entries, log -auto
wh
wh "[-p] eg. Protokoll (application, 'Windows PowerShell', HardwareEvents, Security, System)"
wh "[-l] eg. LogLevel (Error, FailureAudit, Information, SuccessAudit, warning)"
wh "[-n] eg. newest 'x' entries"
wh
wh "Write the '$n' newest '$p' '$l' log entries into '$LOGDIR'..."

      $timestamp = Get-Date -Format '_yyyy-MM-dd_hh-mm-ss'
      $LOGDIR = '{0}\EventLogs\serverlogs{1}.csv' -f $env:HOMEDRIVE, $timestamp
wh
wh "Show servers:"
wh "-------------"
wh
wh (gc -path "$Servers")
wh "."
wh ".."
gel -LogName $p -cn (gc -path $servers) -EntryType $l -Newest $n | `
Select Index,EventID,MachineName,Category,CategoryNumber,EntryType,source,@{Name="MyMSG"; Expression = {$_.Message -replace "`r`n", ""}} | `
export-csv  $LOGDIR -notypeinformation -delimiter "`t" -encoding utf8
wh "..."
wh "Done."
sleep -seconds 1
