#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           winlog-detail.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\winlog-detail.ps1
# DESCRIPTION:    detail eventlog entries
#
# OPTION:         .\powershell.exe .\winlog-detail.ps1 -p <string> -s <string> -id <id>
#
# eg.             Detail all DISK Log Entries
#                 .\powershell.exe .\winlog-detail.ps1 -p system -s disk -id 11
#                 .\powershell.exe .\winlog-detail.ps1 -p system -s 'service control manager' -id 7011
#
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0 & textfile
# BUGS:
# NOTES:          check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
# AUTHOR:         Marco Hinz
# COMPANY:        Justice
# VERSION:        1.0.3
# CREATED:        21.02.2015 - 23:56
# REVISION:       24.02.2015, 26.02.2015, 28.02.2015
# MAINTAINER:     Marco Hinz <https://github.com/hinzigers>
#=============================================================================

Param([string] $p,
      [string] $s,
      [string] $id)
      [string] $date = Get-Date -format o
      [string] $servers = "C:\Windows\System32\WindowsPowerShell\v1.0\computerlist.txt"
      #$s = $s -replace([Char](45), [char](32))

If (Test-Path C:\EventLog){
    # File exists
}Else{
    ni -path c:\ -name EventLogs -itemtype directory -force
}
wh
wh
wh "Help:"
wh "-----"
#Get-EventLog -list | format-table entries, log -auto
wh
wh "[-p] eg. Protokoll (application, 'Windows PowerShell', HardwareEvents, Security, System)"
wh "[-s] eg. LogLevel (Error, FailureAudit, Information, SuccessAudit, warning)"
wh "[-id] eg. Windows EventID"
wh

wh "Write the '$p' log entries out source '$s' and Windows EventID equal '$id' into '$LOGDIR'..."

      $timestamp = Get-Date -Format '_yyyy-MM-dd_hh-mm-ss'
      $LOGDIR = '{0}\EventLogs\serverlogs{1}.csv' -f $env:HOMEDRIVE, $timestamp
wh
wh "Show servers:"
wh "-------------"
wh
wh (gc -path "$Servers")
wh "."
wh ".."
gel -Log $p -cn (gc -path $servers) -source $s | where {$_.eventID -eq $id} | `
#Select Index,EventID,MachineName,Category,CategoryNumber,EntryType,source,@{Name="MyMSG"; Expression = {$_.Message -replace "`r`n", ""}} | `
export-csv  $LOGDIR -notypeinformation -delimiter "`t" -encoding utf8
wh "..."
wh "Done."
sleep -seconds 1
