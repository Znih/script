#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           Get-Log.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\Get-Log.ps1
# DESCRIPTION:    summary eventlog entries witch date
#
# OPTION:         .\powershell.exe .\Get-Log.ps1 -d <ddmmyyyy>
#                 ProtokollParameter:   application 'Windows PowerShell' HardwareEvents Security System
#                 LoglevelParameter:    Error FailureAudit Information SuccessAudit Warning
#
# eg.             .\powershell.exe .\Get-Log.ps1 -d 01.02.2015
#
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0 & textfile
# BUGS:
# NOTES:          check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
#                 switch netsh firewall set service RemoteAdmin enable
# AUTHOR:         Marco Hinz
# COMPANY:        Justice
# VERSION:        1.0.5
# CREATED:        22.02.2015 - 22:26
# REVISION:       24.02.2015, 26.02.2015, 03.03.2015, 05.03.2015
# MAINTAINER:     Marco Hinz <https://github.com/hinzigers>
#=============================================================================

# see write-host vs echo
Param([string] $d)
      [string] $b = Get-Date -format d
      [string] $date = Get-Date -format o
      [string] $servers = "C:\Windows\System32\WindowsPowerShell\v1.0\computerlist.txt"
      [string] $protokoll = "application"
      [string] $loglevel = "error"

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
wh "Protokoll: application, Security, System"
wh "LogLevel:  Error, FailureAudit, warning"
wh "[-d] eg.   StartDate (dd.mm.yyyy)"
wh
wh "Show servers:"
wh "-------------"
wh
wh (gc -path "$Servers")| foreach{ $_.insert(0, $_.ReadCount)}
wh
wh "Writing the ERROR and WARNING log entries from '$d' to '$b'..."

               $timestamp = Get-Date -Format '_yyyy-MM-dd_hh-mm-ss'
      [string] $LOGDIR = '{0}\EventLogs\app-server-errorlogs{1}.csv' -f $env:HOMEDRIVE, $timestamp

wh "$protokoll" "$loglevel"
gel -LogName $protokoll -cn (gc -path $servers) -EntryType $loglevel -after $d -before $b | `
Select Index,EventID,MachineName,Category,CategoryNumber,EntryType,source,@{Name="MyMSG"; Expression = {$_.Message -replace "`r`n", ""}} | `
export-csv $LOGDIR -notypeinformation -delimiter "`t" -encoding utf8
#---------------------------------------------------------------------------

               $timestamp = Get-Date -Format '_yyyy-MM-dd_hh-mm-ss'
      [string] $LOGDIR = '{0}\EventLogs\app-server-warninglogs{1}.csv' -f $env:HOMEDRIVE, $timestamp
      [string] $loglevel = "warning"

wh "$protokoll" "$loglevel"
gel -LogName $protokoll -cn (gc -path $servers) -EntryType $loglevel -after $d -before $b | `
Select Index,EventID,MachineName,Category,CategoryNumber,EntryType,source,@{Name="MyMSG"; Expression = {$_.Message -replace "`r`n", ""}} | `
export-csv $LOGDIR -notypeinformation -delimiter "`t" -encoding utf8
#---------------------------------------------------------------------------

               $timestamp = Get-Date -Format '_yyyy-MM-dd_hh-mm-ss'
      [string] $LOGDIR = '{0}\EventLogs\sys-server-errorlogs{1}.csv' -f $env:HOMEDRIVE, $timestamp
      [string] $protokoll = "system"
      [string] $loglevel = "error"

wh "$protokoll" "$loglevel"
gel -LogName $protokoll -cn (gc -path $servers) -EntryType $loglevel -after $d -before $b | `
Select Index,EventID,MachineName,Category,CategoryNumber,EntryType,source,@{Name="MyMSG"; Expression = {$_.Message -replace "`r`n", ""}} | `
export-csv $LOGDIR -notypeinformation -delimiter "`t" -encoding utf8
#---------------------------------------------------------------------------

               $timestamp = Get-Date -Format '_yyyy-MM-dd_hh-mm-ss'
      [string] $LOGDIR = '{0}\EventLogs\sys-server-warninglogs{1}.csv' -f $env:HOMEDRIVE, $timestamp
      [string] $protokoll = "system"
      [string] $loglevel = "warning"

wh "$protokoll" "$loglevel"
gel -LogName $protokoll -cn (gc -path $servers) -EntryType $loglevel -after $d -before $b | `
Select Index,EventID,MachineName,Category,CategoryNumber,EntryType,source,@{Name="MyMSG"; Expression = {$_.Message -replace "`r`n", ""}} | `
export-csv $LOGDIR -notypeinformation -delimiter "`t" -encoding utf8
#---------------------------------------------------------------------------

    $timestamp = Get-Date -Format '_yyyy-MM-dd_hh-mm-ss'
      [string] $LOGDIR = '{0}\EventLogs\sec-server-failureauditlogs{1}.csv' -f $env:HOMEDRIVE, $timestamp
      [string] $protokoll = "security"
      [string] $loglevel = "FailureAudit"

wh "$protokoll" "$loglevel"
gel -LogName $protokoll -cn (gc -path $servers) -EntryType $loglevel -after $d -before $b | `
Select Index,EventID,MachineName,Category,CategoryNumber,EntryType,source,@{Name="MyMSG"; Expression = {$_.Message -replace "`r`n", ""}} | `
export-csv $LOGDIR -notypeinformation -delimiter "`t" -encoding utf8
wh "."
wh ".."
wh "..."
sleep -seconds 1
wh "Done."
