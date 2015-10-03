#=============================================================================
# HELP:         https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:         installed-updates-checken.ps1
# USAGE:        powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\installed-updates-checken.ps1
# DESCRIPTION:  checked installed windows updates from all computers in the textfile
#
# OPTION:       .\powershell.exe .\installed-updates-checken.ps1
#
# eg.           listed all installed Windows Updates from all computers .\powershell.exe installed-updates-checken.ps1
#
# REQUIREMENTS: dotnet 4.5.2 & powershell 4.0 & textfile
# BUGS:         no return by import from computerlist.txt
# NOTES:        check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
# AUTHOR:       Marco Hinz
# COMPANY:      Justice
# VERSION:      1.0.1
# CREATED:      25.02.2015 - 20:46
# REVISION:     26.02.2015
# MAINTAINER:   Marco Hinz <https://github.com/hinzigers>
#=============================================================================

Param([string] $p,
      [string] $ll,
      [int16] $n)
      [string] $date = Get-Date -format o
      [string] $servers = "C:\Windows\System32\WindowsPowerShell\v1.0\computerlist.txt"

If (Test-Path C:\InstalledUpdates){
# File exists
}Else{
ni -path c:\ -name InstalledUpdates -itemtype directory -force
}
wh
wh
wh "Help:"
wh "-----"
wh
wh "Write all installed Windows Updates from all computers into '$LOGDIR'..."
    $timestamp = Get-Date -Format '_yyyy-MM-dd_hh-mm-ss'
    $LOGDIR = '{0}\InstalledUpdates\updatelist{1}.csv' -f $env:HOMEDRIVE, $timestamp
wh
wh "Show servers:"
wh "-------------"
wh
wh (gc -path "$Servers")
wh "."
wht ".."
gh –cn (gc -Path "$servers") | sort HotfixID | `
Out-File $LOGDIR
wh "..."
wh "Done."
sleep -seconds 1
