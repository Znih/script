#  Copyright (c) Microsoft Corporation.  All rights reserved.
#  
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           profile1.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1
# DESCRIPTION:    listed eventlog entries in summary
#
# OPTION:         (see USAGE) autostartscript
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0
# BUGS:
# NOTES:          powershell default profile file copy to C:\Windows\System32\WindowsPowerShell\v1.0
#                 check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
#                 update get-help > Update-Help
# AUTHOR:         Marco Hinz
# COMPANY:        Justice
# VERSION:        1.0.1
# CREATED:        21.02.2015
# REVISION:
# MAINTAINER:     Marco Hinz <https://github.com/hinzigers>
#=============================================================================

# fill placeholder $scriptpath directory with powershell profile path
$scriptpath = "C:\Windows\System32\WindowsPowerShell\v1.0"

# set new aliases
New-Alias na New-Alias
na ga Get-Alias
# enabled grep as alias (eg. ls | grep -I -N exe) check with alias grep
na grep findstr
na gel Get-EventLog
na wh Write-Host
na gh Get-Hotfix
na of Out-File

# show version table and set scriptpath
$PSVersionTable
cd $scriptpath
