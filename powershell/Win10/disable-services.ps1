#  Copyright (c) Microsoft Corporation.  All rights reserved.
#  
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           disable-services.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\disable-services.ps1
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
# This script disables unwanted Windows services. If you do not want to disable
# certain services comment out the corresponding lines below.

$services = @(
    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"                                # Diagnostics Tracking Service
    "dmwappushservice"                         # WAP Push Message Routing Service
    "HomeGroupListener"                        # HomeGroup Listener
    "HomeGroupProvider"                        # HomeGroup Provider
    "lfsvc"                                    # Geolocation Service
    "MapsBroker"                               # Downloaded Maps Manager
    "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
    "RemoteAccess"                             # Routing and Remote Access
    "RemoteRegistry"                           # Remote Registry
    "SharedAccess"                             # Internet Connection Sharing (ICS)
    "TrkWks"                                   # Distributed Link Tracking Client
    "WbioSrvc"                                 # Windows Biometric Service
    #"WlanSvc"                                 # WLAN AutoConfig
    "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
    "wscsvc"                                   # Windows Security Center Service
    "WSearch"                                  # Windows Search
    "XblAuthManager"                           # Xbox Live Auth Manager
    "XblGameSave"                              # Xbox Live Game Save Service
    "XboxNetApiSvc"                            # Xbox Live Networking Service
    "WerSvc"
    "WebClient"
    "upnphost"
    "DoSvc"
    "SSDPSRV"
    "PcaSvc"
    "PolicyAgent"
    "ALG"
    "Fax"
    "WcsPlugInService"
    "Wecsvc"
    "MpsSvc"                                     # Windows Firewall
    "WbioSrvc"                                   # Windows-Biometriedienst
    "icssvc"                                     # Windows-Dienst für mobile Hotspots
    "NcaSvc"                                     # Netzwerkkonnektivitäts-Assistent
    "iphlpsvc"                                   # IP-Hilfsdienst
    "WinHttpAutoProxySvc"                        # WinHTTP-Web Proxy Auto-Discovery-Dienst
    #"embeddedmode"
    "AppReadiness"
    #"Schedule"
    "DevQueryBroker"
    #"SystemEventsBroker"
pause


    # Services which cannot be disabled
    #"WdNisSvc"
)

foreach ($service in $services) {
    Get-Service -Name $service | Set-Service -StartupType Disabled
}
