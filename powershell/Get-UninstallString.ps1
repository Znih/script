#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           Get-UninstallString.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\Get-UninstallString.ps1
# DESCRIPTION:    read the Uninstall String from ther registry entries DisplayName and UninstallString for OPSI 
#
# OPTION:         parameters input eg. displayname,unstallstring
#                 UninstallString
#                 AuthorizedCDFPrefix
#                 Comments
#                 Contact
#                 DisplayVersion
#                 HelpLink
#                 HelpTelephone
#                 InstallDate
#                 InstallLocation
#                 InstallSource
#                 NoRemove
#                 Publisher
#                 Readme
#                 Size
#                 EstimatedSize
#                 URLInfoAbout
#                 URLUpdateInfo
#                 VersionMajor
#                 VersionMinor
#                 WindowsInstaller
#                 Version
#                 Language
#                 DisplayName
#                 PSPath
#                 PSParentPath
#                 PSChildName
#                 PSProvider
#
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0
# BUGS:
# NOTES:          see <https://github.com/hinzigers/opsi/tree/master/adobe-flashplayer/CLIENT_DATA>
#                 check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
# 
# AUTHOR:         Marco Hinz
# COMPANY:        Justice
# VERSION:        1.0
# CREATED:        01.03.2015
# REVISION:
# MAINTAINER:     Marco Hinz <https://github.com/hinzigers>
#=============================================================================

    $temp = "C:\Temp\uninstallstrings.txt"


If (Test-Path C:\Temp){
    # File exists
}Else{
    ni -path c:\ -name Temp -itemtype directory -force
}


Get-ChildItem hklm:\software\microsoft\windows\currentversion\uninstall | `
ForEach-Object {gp $_.pspath | `
select -property DisplayName, UninstallString | Format-List} | `
of -encoding utf8 $temp

