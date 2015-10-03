#  Copyright (c) Microsoft Corporation.  All rights reserved.
#  
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           block-telemetry-domains.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\block-telemetry-domains.ps1
# DESCRIPTION:    listed eventlog entries in summary
#
# OPTION:         (see USAGE) autostartscript
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0
# BUGS:
# NOTES:          powershell default profile file copy to C:\Windows\System32\WindowsPowerShell\v1.0
#                 check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
#                 update get-help > Update-Help
# AUTHOR:         Alex Hirsch
# COMPANY:        -
# VERSION:        In Progress
# CREATED:        n.b.
# REVISION:
# EDITOR:         Marco Hinz <https://github.com/hinzigers>
# SOURCE:         Alex Hirsch <https://github.com/W4RH4WK/Debloat-Windows-10>
#=============================================================================

#   Description:
# This script blocks telemetry related domains via the hosts file and related
# IPs via Windows Firewall.

echo "Adding telemetry domains to hosts file"
$hosts = cat "$PSScriptRoot\..\res\telemetry-hosts.txt"
$hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
[ipaddress[]] $ips = @()
foreach ($h in $hosts) {
    try {
        # store for next part
        $ips += [ipaddress]$h
    } catch [System.InvalidCastException] {
        $contaisHost = Select-String -Path $hosts_file -Pattern $h
        If (-Not $contaisHost) {
            # can be redirected by hosts
            echo "127.0.0.1 $h" | Out-File -Encoding ASCII -Append $hosts_file
        }
    }
}

echo "Adding telemetry ips to firewall"
Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound `
    -Action Block -RemoteAddress ([string[]]$ips)
