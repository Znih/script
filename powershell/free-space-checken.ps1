#=============================================================================
# HELP:         https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:         free-space-checken.ps1
# USAGE:        powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\free-space-checken.ps1
# DESCRIPTION:  checked installed windows updates from all computers in the textfile
#
# OPTION:       .\powershell.exe .\free-space-checken.ps1 -p <string> -s <string> -id <id>
#
# eg.           listed free space from all computers in textfile .\powershell.exe .\free-space-checken.ps1 -p system -s Service Control Manager -id 11
#
# REQUIREMENTS: dotnet 4.5.2 & powershell 4.0
# BUGS: 
# NOTES:        check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
# AUTHOR:       Marco Hinz
# COMPANY:      Justice
# VERSION:      1.0
# CREATED:      25.02.2015 - 18:56
# REVISION: 
# MAINTAINER:   Marco Hinz <https://github.com/hinzigers>
#=============================================================================

#Param([string] $computer)
      [string] $date = Get-Date -format o
      [string] $COMPUTERLIST = "C:\Windows\System32\WindowsPowerShell\v1.0\computerlist.txt"

If (Test-Path C:\FreeSpaceLogs){
    # File exists
}Else{
    new-item -path c:\ -name FreeSpaceLogs -itemtype directory -force
}
wh ""
wh ""
wh "Help:"
wh "-----"
wh ""
wh "you don't need"
wh ""
wh "Write free space form all computers out the textfile into '$COMPUTERLIST':"
    $timestamp = Get-Date -Format '_yyyy-MM-dd_hh-mm-ss'
    $LOGDIR = '{0}\FreeSpaceLogs\Probook{1}.txt' -f $env:HOMEDRIVE, $timestamp
wh "."
wh ".."
gwmi Win32_LogicalDisk -cn (gc -Path $COMPUTERLIST) | ? { $_.DriveType -eq 3 } | `
Select SystemName, DeviceID, Size, FreeSpace, VolumeName | ft | out-file $LOGDIR
wh "..."
wh "Done."
sleep -seconds 1
wh "List $LOGDIR successful generated and saved."

# check
#$aryComputers = (gc -Path $COMPUTERLIST)
#Set-Variable -name intDriveType -value 3 -option constant
#foreach ($strComputer in $aryComputers)
#{
#     "Hard drives on: " + $strComputer
#     Get-WmiObject -class win32_logicaldisk -computername $strComputer |
#     Where { $_.drivetype -eq $intDriveType } | Format-table
#}
