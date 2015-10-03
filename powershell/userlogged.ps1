#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           userlogged.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\userlogged.ps1
# DESCRIPTION:    listed all user which logged on system 
#
# OPTION:         .\powershell.exe .\userlogged.ps1
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0
# BUGS:
# NOTES:          check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
# AUTHOR:         Marco Hinz
# COMPANY:        Justice
# VERSION:        1.0
# CREATED:        22.02.2015 - 01:55
# REVISION:
# MAINTAINER:     Marco Hinz <https://github.com/hinzigers>
#=============================================================================

# listed all NT users - systemuser - which logged
#get-eventlog -log system -username NT* | group-object -property username -noelement | format-table Count, Name -auto

# listed all users which logged
gel -log system -username * | group-object -property username -noelement | format-table Count, Name -auto
