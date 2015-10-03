#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           set-mapdrive.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\set-mapdrive.ps1
# DESCRIPTION:    
#
# OPTION:         .\powershell.exe .\set-mapdrive.ps1
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0
# BUGS:
# NOTES:          check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
# AUTHOR:         Marco Hinz
# COMPANY:        Justice
# VERSION:        1.0
# CREATED:        28.02.2015 - 21:36
# REVISION:
# MAINTAINER:     Marco Hinz <https://github.com/hinzigers>
#=============================================================================

    $server ="xxxxxxxx"
    $share = "C$"
    $sharepath = [Char](92)+[Char](92)+$server+[Char](92)+$share
    $mapdrive = "S:"
    $mapfolder = "powershell"
    $mappath = $mapdrive+[Char](92)+$mapfolder+[Char](92)

# first, make sure that s: is mapped to your script share
if (! (test-path -isvalid $mappath)) {
    net use s: $sharepath
}
# Now, create the $profile directory if it doesn’t exist
    $prodir = (split-path $profile)
if ( ! (test-path -pathtype container $prodir)) {
   mkdir $prodir
   #cp $mappath* $prodir
} else {
   #cp $mappath* $prodir
}

