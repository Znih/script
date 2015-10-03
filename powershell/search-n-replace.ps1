#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           search-n-replace.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\search-n-replace.ps1
# DESCRIPTION:    summary eventlog entries witch date
#
# OPTION:         -ext <string> -path <string> -old <string> -new <string>
#
# eg.             .\search-n-replace.ps1 -path C:\EventLogs\ -ext csv -old Error -new ERROR
#
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0 & textfile
# BUGS:
# NOTES:          check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
# AUTHOR:         Marco Hinz
# COMPANY:        Justice
# VERSION:        1.0
# CREATED:        02.03.2015 - 22:00
# REVISION:       
# MAINTAINER:     Marco Hinz <https://github.com/hinzigers>
#=============================================================================

Param([string] $path,
      [string] $ext,
      [string] $old,
      [string] $new)

wh "All '$ext'-files in folder '$path' to become changed."
pause
Get-ChildItem -Recurse ("$path"+[Char](42)+[Char](46)+"$ext")| `
foreach-object -Process {$newText = (Get-Content $_.FullName).replace("$old","$new");
Set-content -Path $_.FullName -Value $newText}
