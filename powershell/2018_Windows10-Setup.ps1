#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           2018_Windows10-Setup.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\2018_Windows10-Setup.ps1
# DESCRIPTION:    Verwalten von Verbindungen zwischen Windows-Betriebssystemkomponenten und Microsoft-Diensten regeln
#
# OPTION:         (see USAGE) cleaningscript
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0
# BUGS:
# NOTES:          powershell default profile file copy to C:\Windows\System32\WindowsPowerShell\v1.0
#                 check Get-ExecutionPolicy (switch Unrestricted to Set-ExecutionPolicy RemoteSigned)
#                 update get-help > Update-Help
# AUTHOR:         Marco Hinz <https://github.com/hinzigers>
# COMPANY:        matrixhacker.de
# VERSION:        1.0.5
# CREATED:        06.12.2017
# REVISION:       07.12.2017, 10.12.2017, 12.12.2017, 25.12.2017
# EDITOR:         Marco Hinz <https://github.com/hinzigers>
# SOURCE:         Microsoft <https://docs.microsoft.com/de-de/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services>
#=============================================================================

# assimiliert von Alex Hirsch
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\force-mkdir.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\mkdirpath-force.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

# Nick Craver <https://gist.github.com/NickCraver/7ebf9efbfd0c3eab72e9>
# WiFi Sense: HotSpot Sharing: Disable
sp "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" "value" 0
# WiFi Sense: Shared HotSpot Auto-Connect: Disable
sp "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" "value" 0
# Start Menu: Disable Bing Search Results
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0
# To Restore (Enabled):
# Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 1
# These make "Quick Access" behave much closer to the old "Favorites"
# Disable Quick Access: Recent Files
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "ShowRecent" 0
# Disable Quick Access: Frequent Folders
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "ShowFrequent" 0
# Disable TelemetrySalt
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "TelemetrySalt" 0
# To Restore:
#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 1
#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 1
#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name TelemetrySalt -Type DWord -Value 1
sp "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" 1
sp "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "DisableQueue" 1
sp "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "DontSendAdditionalData" 1
# To Restore:
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Type Dword -Value 0
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name DisableQueue -Type Dword -Value 0
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name DontSendAdditionalData -Type Dword -Value 0

# Disable the Lock Screen (the one before password prompt - to prevent dropping the first character)
If (-Not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization)) {
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name Personalization | Out-Null
}
sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreen" 1
sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "AllowChangeDesktopBackground" 0
sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "AllowPersonalization" 0
# To Restore:
#Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 
#Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name AllowChangeDesktopBackground -Type DWord -Value 1
#Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name AllowPersonalization -Type DWord -Value 1
#sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableRegistryTools" 1
#sp "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareWks" 0
sp "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisablePagingExecutive" 1
sp "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 0


# Scripts Alex Hirsch in Reihenfolge eingepflegt

# 1. 1_block-telemetry
Write-Output "Disabling telemetry via Group Policies"
force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

Write-Output "Adding telemetry domains to hosts file"
$hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
$domains = @(
    "184-86-53-99.deploy.static.akamaitechnologies.com"
    "a-0001.a-msedge.net"
    "a-0002.a-msedge.net"
    "a-0003.a-msedge.net"
    "a-0004.a-msedge.net"
    "a-0005.a-msedge.net"
    "a-0006.a-msedge.net"
    "a-0007.a-msedge.net"
    "a-0008.a-msedge.net"
    "a-0009.a-msedge.net"
    "a1621.g.akamai.net"
    "a1856.g2.akamai.net"
    "a1961.g.akamai.net"
    #"a248.e.akamai.net"            # makes iTunes download button disappear (#43)
    "a978.i6g1.akamai.net"
    "a.ads1.msn.com"
    "a.ads2.msads.net"
    "a.ads2.msn.com"
    "ac3.msn.com"
    "ad.doubleclick.net"
    "adnexus.net"
    "adnxs.com"
    "ads1.msads.net"
    "ads1.msn.com"
    "ads.msn.com"
    "aidps.atdmt.com"
    "aka-cdn-ns.adtech.de"
    "a-msedge.net"
    "any.edge.bing.com"
    "a.rad.msn.com"
    "az361816.vo.msecnd.net"
    "az512334.vo.msecnd.net"
    "b.ads1.msn.com"
    "b.ads2.msads.net"
    "bingads.microsoft.com"
    "b.rad.msn.com"
    "bs.serving-sys.com"
    "c.atdmt.com"
    "cdn.atdmt.com"
    "cds26.ams9.msecn.net"
    "choice.microsoft.com"
    "choice.microsoft.com.nsatc.net"
    "c.msn.com"                                 # can cause issues with Skype
    "compatexchange.cloudapp.net"
    "corpext.msitadfs.glbdns2.microsoft.com"
    "corp.sts.microsoft.com"
    "cs1.wpc.v0cdn.net"
    "db3aqu.atdmt.com"
    "df.telemetry.microsoft.com"
    "diagnostics.support.microsoft.com"
    "e2835.dspb.akamaiedge.net"
    "e7341.g.akamaiedge.net"
    "e7502.ce.akamaiedge.net"
    "e8218.ce.akamaiedge.net"
    "ec.atdmt.com"
    "fe2.update.microsoft.com.akadns.net"
    "feedback.microsoft-hohm.com"
    "feedback.search.microsoft.com"
    "feedback.windows.com"
    "flex.msn.com"
    "g.msn.com"
    "h1.msn.com"
    "h2.msn.com"
    "hostedocsp.globalsign.com"
    "i1.services.social.microsoft.com"
    "i1.services.social.microsoft.com.nsatc.net"
    "ipv6.msftncsi.com"
    "ipv6.msftncsi.com.edgesuite.net"
    "lb1.www.ms.akadns.net"
    "live.rads.msn.com"
    "m.adnxs.com"
    "msedge.net"
    "msftncsi.com"
    "msnbot-65-55-108-23.search.msn.com"
    "msntest.serving-sys.com"
    "oca.telemetry.microsoft.com"
    "oca.telemetry.microsoft.com.nsatc.net"
    "onesettings-db5.metron.live.nsatc.net"
    "pre.footprintpredict.com"
    "preview.msn.com"
    "rad.live.com"
    "rad.msn.com"
    "redir.metaservices.microsoft.com"
    "reports.wes.df.telemetry.microsoft.com"
    "schemas.microsoft.akadns.net"
    "secure.adnxs.com"
    "secure.flashtalking.com"
    "services.wes.df.telemetry.microsoft.com"
    "settings-sandbox.data.microsoft.com"
    "settings-win.data.microsoft.com"
    "sls.update.microsoft.com.akadns.net"
    "sls.update.microsoft.com.nsatc.net"
    "sqm.df.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com.nsatc.net"
    "ssw.live.com"
    "static.2mdn.net"
    "statsfe1.ws.microsoft.com"
    "statsfe2.update.microsoft.com.akadns.net"
    "statsfe2.ws.microsoft.com"
    "survey.watson.microsoft.com"
    "telecommand.telemetry.microsoft.com"
    "telecommand.telemetry.microsoft.com.nsatc.net"
    "telemetry.appex.bing.net"
    "telemetry.appex.bing.net:443"
    "telemetry.microsoft.com"
    "telemetry.urs.microsoft.com"
    "vortex-bn2.metron.live.com.nsatc.net"
    "vortex-cy2.metron.live.com.nsatc.net"
    "vortex.data.microsoft.com"
    "vortex-sandbox.data.microsoft.com"
    "vortex-win.data.microsoft.com"
    "cy2.vortex.data.microsoft.com.akadns.net"
    "watson.live.com"
    "watson.microsoft.com"
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "wes.df.telemetry.microsoft.com"
    "win10.ipv6.microsoft.com"
    "www.bingads.microsoft.com"
    "www.go.microsoft.akadns.net"
    "www.msftncsi.com"
    "client.wns.windows.com"
    "wdcp.microsoft.com"
    "dns.msftncsi.com"
    "storeedgefd.dsx.mp.microsoft.com"
    "login.live.com"
    "wdcpalt.microsoft.com"
    "settings-ssl.xboxlive.com"
    "settings-ssl.xboxlive.com-c.edgekey.net"
    "settings-ssl.xboxlive.com-c.edgekey.net.globalredir.akadns.net"
    "e87.dspb.akamaidege.net"
    "insiderservice.microsoft.com"
    "insiderservice.trafficmanager.net"
    "e3843.g.akamaiedge.net"
    "flightingserviceweurope.cloudapp.net"
    "sls.update.microsoft.com" # wird ignoriert res. umgangen
    "static.ads-twitter.com"
    "www-google-analytics.l.google.com"
    "p.static.ads-twitter.com"
    "hubspot.net.edge.net"
    "e9483.a.akamaiedge.net"

    #"www.google-analytics.com"
    #"padgead2.googlesyndication.com"
	#"mirror1.malwaredomains.com"
	#"mirror.cedia.org.ec"
    "stats.g.doubleclick.net"
    "stats.l.doubleclick.net"
    "adservice.google.de"
    "adservice.google.com"
    "googleads.g.doubleclick.net"
    "pagead46.l.doubleclick.net"
    "hubspot.net.edgekey.net" #trotz Deaktivierung von hubspot
    "insiderppe.cloudapp.net" # Feedback-Hub
    "livetileedge.dsx.mp.microsoft.com"
    

    # extra
    "fe2.update.microsoft.com.akadns.net"
    "s0.2mdn.net"
    "statsfe2.update.microsoft.com.akadns.net",
    "survey.watson.microsoft.com"
    "view.atdmt.com"
    "watson.microsoft.com",
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com",
    "watson.telemetry.microsoft.com.nsatc.net"
    "wes.df.telemetry.microsoft.com"
    "ui.skype.com",                             # can cause issues with Skype
    "pricelist.skype.com"                       # can cause issues with Skype
    "apps.skype.com"                            # can cause issues with Skype
    "m.hotmail.com"
    "s.gateway.messenger.live.com"              # can cause issues with Skype
)
Write-Output "" | Out-File -Encoding ASCII -Append $hosts_file
foreach ($domain in $domains) {
    if (-Not (Select-String -Path $hosts_file -Pattern $domain)) {
        Write-Output "0.0.0.0 $domain" | Out-File -Encoding ASCII -Append $hosts_file
    }
}

Write-Output "Adding telemetry ips to firewall"
$ips = @(
    "134.170.30.202"
    "137.116.81.24"
    "157.56.106.189"
    "184.86.53.99"
    "2.22.61.43"
    "2.22.61.66"
    "204.79.197.200"
    "23.218.212.69"
    "65.39.117.230"
    "65.52.108.33"
    "65.55.108.23"
    "64.4.54.254"
)
Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound `
    -Action Block -RemoteAddress ([string[]]$ips)

# 2. fix-privacy-settings
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Defuse Windows search settings"
Set-WindowsSearchSetting -EnableWebResultsSetting $false

Write-Output "Set general privacy options"
Set-ItemProperty "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1
force-mkdir "HKCU:\Printers\Defaults"
Set-ItemProperty "HKCU:\Printers\Defaults" "NetID" "{00000000-0000-0000-0000-000000000000}"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Input\TIPC"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Input\TIPC" "Enabled" 0
force-mkdir "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0

Write-Output "Disable synchronisation of settings"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" 0x3c
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "DeviceMetadataUploaded" 0
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "PriorLogons" 1
$groups = @(
    "Accessibility"
    "AppSync"
    "BrowserSettings"
    "Credentials"
    "DesktopTheme"
    "Language"
    "PackageState"
    "Personalization"
    "StartLayout"
    "Windows"
)
foreach ($group in $groups) {
    force-mkdir "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group"
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group" "Enabled" 0
}

Write-Output "Set privacy policy accepted state to 0"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0

Write-Output "Do not scan contact informations"
force-mkdir "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0

Write-Output "Inking and typing settings"
force-mkdir "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1

Write-Output "Microsoft Edge settings"
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" "DoNotTrack" 1
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" "ShowSearchSuggestionsGlobal" 0
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" "FPEnabled" 0
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" "EnabledV9" 0

Write-Output "Disable background access of default apps"
foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
}

Write-Output "Denying device access"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Type" "LooselyCoupled"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Value" "Deny"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "InitialAppValue" "Unspecified"
foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global")) {
    if ($key.PSChildName -EQ "LooselyCoupled") {
        continue
    }
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Type" "InterfaceClass"
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Value" "Deny"
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "InitialAppValue" "Unspecified"
}

Write-Output "Disable location sensor"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0

#Write-Output "Disable submission of Windows Defender findings (w/ elevated privileges)"
#Takeown-Registry ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet")
#Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpyNetReporting" 0       # write-protected even after takeown ?!
#Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" 0

Write-Output "Do not share wifi networks"
$user = New-Object System.Security.Principal.NTAccount($env:UserName)
$sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).value
force-mkdir ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid)
Set-ItemProperty ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid) "FeatureStates" 0x33c
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseCredShared" 0
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseOpen" 0

# 3_disable-scheduled-tasks
$tasks = @(
    # Windows base scheduled tasks
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319"
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64"
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical"
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical"

    "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)"
    "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)"

    "\Microsoft\Windows\AppID\EDP Policy Manager"
    "\Microsoft\Windows\AppID\PolicyConverter"
    #"\Microsoft\Windows\AppID\SmartScreenSpecific" #Not found
    "\Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck"

    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "\Microsoft\Windows\Application Experience\StartupAppTask"
	
	#"\Microsoft\Windows\BitLocker\BitLocker MDM policy Refresh" # Zugriff verweigert
	
	#"\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask"

    #"\Microsoft\Windows\ApplicationData\CleanupTemporaryState"
    #"\Microsoft\Windows\ApplicationData\DsSvcCleanup"

    #"\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup"

    "\Microsoft\Windows\Autochk\Proxy"

    #"\Microsoft\Windows\Bluetooth\UninstallDeviceTask"

    #"\Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask"
    #"\Microsoft\Windows\CertificateServicesClient\KeyPreGenTask"
    #"\Microsoft\Windows\CertificateServicesClient\SystemTask"
    #"\Microsoft\Windows\CertificateServicesClient\UserTask"
    #"\Microsoft\Windows\CertificateServicesClient\UserTask-Roam"

    #"\Microsoft\Windows\Chkdsk\ProactiveScan"

    "\Microsoft\Windows\Clip\License Validation"

    "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"

    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"

    # only ssd
    #"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan"
    #"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery"

    # only ssd
    #"\Microsoft\Windows\Defrag\ScheduledDefrag"

    #"\Microsoft\Windows\Diagnosis\Scheduled"

    #"\Microsoft\Windows\DiskCleanup\SilentCleanup"

    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    #"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"

    #"\Microsoft\Windows\DiskFootprint\Diagnostics"

    "\Microsoft\Windows\Feedback\Siuf\DmClient"
    "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
	
    "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync"
	
	"\Microsoft\Windows\License Manager\TempSignedLicenseExchange"

    #"\Microsoft\Windows\FileHistory\File History (maintenance mode)"

    #"\Microsoft\Windows\LanguageComponentsInstaller\Installation"
    #"\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation"

    "\Microsoft\Windows\Location\Notifications"
    "\Microsoft\Windows\Location\WindowsActionDialog"

    "\Microsoft\Windows\Maintenance\WinSAT"
	
	"\Microsoft\Windows\Management\Provisioning\Cellular"
	"\Microsoft\Windows\Management\Provisioning\Logon"
	
	"\Microsoft\Windows\NlaSvc\WiFiTask"

    "\Microsoft\Windows\Maps\MapsToastTask"
    "\Microsoft\Windows\Maps\MapsUpdateTask"

    #"\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents"
    #"\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic"

    "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"

    #"\Microsoft\Windows\MUI\LPRemove"

    #"\Microsoft\Windows\Multimedia\SystemSoundsService"

    #"\Microsoft\Windows\NetCfg\BindingWorkItemQueueHandler"

    "\Microsoft\Windows\NetTrace\GatherNetworkInfo"

    "\Microsoft\Windows\Offline Files\Background Synchronization"
    "\Microsoft\Windows\Offline Files\Logon Synchronization"
    
    "\Microsoft\Windows\PI\Secure-Boot-Update"
    "\Microsoft\Windows\PI\Sqm-Tasks"

    #"\Microsoft\Windows\Plug and Play\Device Install Group Policy"
    #"\Microsoft\Windows\Plug and Play\Device Install Reboot Required"
    #"\Microsoft\Windows\Plug and Play\Plug and Play Cleanup"
    #"\Microsoft\Windows\Plug and Play\Sysprep Generalize Drivers"

    #"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"

    #"\Microsoft\Windows\Ras\MobilityManager"

    #"\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE"

    #"\Microsoft\Windows\Registry\RegIdleBackup"

    "Microsoft\Windows\RetailDemo\CleanupOfflineContent"

    "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask"

    #"\Microsoft\Windows\RemovalTools\MRT_HB"

    #"\Microsoft\Windows\Servicing\StartComponentCleanup"

    #"\Microsoft\Windows\SettingSync\BackgroundUploadTask" # Zugriff verweigert
	"\Microsoft\Windows\SettingSync\BackupTask"
	"\Microsoft\Windows\SettingSync\NetworkStateChangeTask"

    #"\Microsoft\Windows\Shell\CreateObjectTask"
    "\Microsoft\Windows\Shell\FamilySafetyMonitor"
	"\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask"
    "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" #berichtigt
    "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance"

    "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask"
    "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon"
    "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork"
	
	"\Microsoft\Windows\Speech\SpeechModelDownloadTask"
	
	"\Microsoft\Windows\Subscription\EnableLicenseAcquisition"

    #"\Microsoft\Windows\SpacePort\SpaceAgentTask"

    "\Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate"
    "\Microsoft\Windows\Sysmain\HybridDriveCacheRebalance"
    #"\Microsoft\Windows\Sysmain\ResPriStaticDbSync"
    #"\Microsoft\Windows\Sysmain\WsSwapAssessmentTask"

    #"\Microsoft\Windows\SystemRestore\SR"

    #"\Microsoft\Windows\Task Manager\Interactive"

    #"\Microsoft\Windows\TextServicesFramework\MsCtfMonitor"

    #"\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime"
    #"\Microsoft\Windows\Time Synchronization\SynchronizeTime"

    #"\Microsoft\Windows\Time Zone\SynchronizeTimeZone"

    "\Microsoft\Windows\TPM\Tpm-HASCertRetr"
    "\Microsoft\Windows\TPM\Tpm-Maintenance"

    "\Microsoft\Windows\UpdateOrchestrator\Maintenance Install"
    "\Microsoft\Windows\UpdateOrchestrator\Policy Install"
    "\Microsoft\Windows\UpdateOrchestrator\Reboot"
	"\Microsoft\Windows\UpdateOrchestrator\Refresh Settings"
    "\Microsoft\Windows\UpdateOrchestrator\Resume On Boot"
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
    "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display"
    "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot"

    "\Microsoft\Windows\UPnP\UPnPHostConfig"

    "\Microsoft\Windows\User Profile Service\HiveUploadTask"

    "\Microsoft\Windows\WCM\WiFiTask"

    "\Microsoft\Windows\WDI\ResolutionHost"

    #"\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
    #"\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
    #"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
    #"\Microsoft\Windows\Windows Defender\Windows Defender Verification"

    "\Microsoft\Windows\Windows Error Reporting\QueueReporting"

    #"\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange"

    #"\Microsoft\Windows\Windows Media Sharing\UpdateLibrary"

    #"\Microsoft\Windows\WindowsColorSystem\Calibration Loader"

    "\Microsoft\Windows\WindowsUpdate\Automatic App Update"
    "\Microsoft\Windows\WindowsUpdate\Scheduled Start"
    "\Microsoft\Windows\WindowsUpdate\sih"
    "\Microsoft\Windows\WindowsUpdate\sihboot"

    #"\Microsoft\Windows\Wininet\CacheTask"

    #"\Microsoft\Windows\WOF\WIM-Hash-Management"
    #"\Microsoft\Windows\WOF\WIM-Hash-Validation"

    "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization"
    "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work"

    "\Microsoft\Windows\Workplace Join\Automatic-Device-Join"
	
	"\Microsoft\Windows\DUSM\dusmtask"
	
	#"\Microsoft\Windows\EDP\DUSM\EDP App Launch Task" # Pseudo Not found
	#"\Microsoft\Windows\EDP\EDP Auth Task" # Zugriff verweigert
	#"\Microsoft\Windows\EDP\DUSM\EDP Inaccessible Credentials Task" # Pseudo Not found
	#"\Microsoft\Windows\EDP\StorageCardEncryption Task" # Zugriff verweigert

    #"\Microsoft\Windows\WS\License Validation" #Not found
    #"\Microsoft\Windows\WS\WSTask"

    # Scheduled tasks which cannot be disabled
    #"\Microsoft\Windows\Device Setup\Metadata Refresh"
    #"\Microsoft\Windows\SettingSync\BackgroundUploadTask"
	
	"\Microsoft\Windows\WwanSvc\NotificationTask"
	"\Microsoft\XblGameSave\XblGameSaveTask"

)

foreach ($task in $tasks) {
    $parts = $task.split('\')
    $name = $parts[-1]
    $path = $parts[0..($parts.length-2)] -join '\'

    Disable-ScheduledTask -TaskName "$name" -TaskPath "$path"
}

# 4_remove-default-apps
Write-Output "Elevating privileges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Uninstalling default apps"
$apps = @(
    # default Windows 10 apps
    "Microsoft.3DBuilder"
    "Microsoft.Appconnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingWeather"
    #"Microsoft.FreshPaint"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    #"Microsoft.MicrosoftStickyNotes"
    "Microsoft.Office.OneNote"
    #"Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.SkypeApp"
    #"Microsoft.Windows.Photos"
    "Microsoft.WindowsAlarms"
    #"Microsoft.WindowsCalculator"
    "Microsoft.WindowsCamera"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    #"Microsoft.WindowsStore"
    "Microsoft.XboxApp"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "microsoft.windowscommunicationsapps"
    "Microsoft.MinecraftUWP"
    "Microsoft.MicrosoftPowerBIForWindows"
    "Microsoft.NetworkSpeedTest"
    
    # Threshold 2 apps
    "Microsoft.CommsPhone"
    "Microsoft.ConnectivityStore"
    "Microsoft.Messaging"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.WindowsFeedbackHub"


    #Redstone apps
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingTravel"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.WindowsReadingList"

    # non-Microsoft
    "9E2F88E3.Twitter"
    "PandoraMediaInc.29680B314EFC2"
    "Flipboard.Flipboard"
    "ShazamEntertainmentLtd.Shazam"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"
    "king.com.*"
    "ClearChannelRadioDigital.iHeartRadio"
    "4DF9E0F8.Netflix"
    "6Wunderkinder.Wunderlist"
    "Drawboard.DrawboardPDF"
    "2FE3CB00.PicsArt-PhotoStudio"
    "D52A8D61.FarmVille2CountryEscape"
    "TuneIn.TuneInRadio"
    "GAMELOFTSA.Asphalt8Airborne"
    #"TheNewYorkTimes.NYTCrossword"
    "DB6EA5DB.CyberLinkMediaSuiteEssentials"
    "Facebook.Facebook"
    "flaregamesGmbH.RoyalRevolt2"
    "Playtika.CaesarsSlotsFreeCasino"
    "A278AB0D.MarchofEmpires"
    "KeeperSecurityInc.Keeper"
    "ThumbmunkeysLtd.PhototasticCollage"
    "XINGAG.XING"
    "89006A2E.AutodeskSketchBook"
    "D5EA27B7.Duolingo-LearnLanguagesforFree"
    "46928bounde.EclipseManager"
    "ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC


    # apps which cannot be removed using Remove-AppxPackage
    #"Microsoft.BioEnrollment"
    #"Microsoft.MicrosoftEdge"
    #"Microsoft.Windows.Cortana"
    #"Microsoft.WindowsFeedback"
    #"Microsoft.XboxGameCallableUI"
    #"Microsoft.XboxIdentityProvider"
    #"Windows.ContactSupport" #Hilfe Anfordern
)

foreach ($app in $apps) {
    Write-Output "Trying to remove $app"

    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

    Get-AppXProvisionedPackage -Online |
        Where-Object DisplayName -EQ $app |
        Remove-AppxProvisionedPackage -Online
}

# Prevents "Suggested Applications" returning
force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content"
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content" "DisableWindowsConsumerFeatures" 1

# 5_remove-onedrive
Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Output "Removing scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Restarting explorer"
Start-Process "explorer.exe"

Write-Output "Waiting for explorer to complete loading"
Start-Sleep 10

Write-Output "Removing additional OneDrive leftovers"
foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
    Takeown-Folder $item.FullName
    Remove-Item -Recurse -Force $item.FullName
}


# 6_experimental_unfuckery
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Force removing system apps"
$needles = @(
    #"Anytime"
    "BioEnrollment"
    #"Browser"
    "ContactSupport"
    #"Cortana"       # This will disable startmenu search.
    #"Defender"
    "Feedback"
    "Flash"
    "Gaming"
    #"InternetExplorer"
    #"Maps"
    "OneDrive"
    #"Wallet"
    #"Xbox"          # This will result in a bootloop since upgrade 1511
)

foreach ($needle in $needles) {
    Write-Output "Trying to remove all packages containing $needle"

    $pkgs = (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" |
        Where-Object Name -Like "*$needle*")

    foreach ($pkg in $pkgs) {
        $pkgname = $pkg.Name.split('\')[-1]

        Takeown-Registry($pkg.Name)
        Takeown-Registry($pkg.Name + "\Owners")

        Set-ItemProperty -Path ("HKLM:" + $pkg.Name.Substring(18)) -Name Visibility -Value 1
        New-ItemProperty -Path ("HKLM:" + $pkg.Name.Substring(18)) -Name DefVis -PropertyType DWord -Value 2
        Remove-Item      -Path ("HKLM:" + $pkg.Name.Substring(18) + "\Owners")

        dism.exe /Online /Remove-Package /PackageName:$pkgname /NoRestart
    }
}


# 7_disable-services
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
    #"SharedAccess"                             # Internet Connection Sharing (ICS)
    "TrkWks"                                   # Distributed Link Tracking Client
    "WbioSrvc"                                 # Windows Biometric Service
    #"WlanSvc"                                 # WLAN AutoConfig
    #"WMPNetworkSvc"                            # Windows Media Player Network Sharing Service | ausklammern wenn der Player bereits deinstalliert wurde
    "wscsvc"                                   # Windows Security Center Service
    "WSearch"                                  # Windows Search
    "XblAuthManager"                           # Xbox Live Auth Manager | ausklammern wenn der Player bereits deinstalliert wurde
    "XblGameSave"                              # Xbox Live Game Save Service | ausklammern wenn der Player bereits deinstalliert wurde
    "XboxNetApiSvc"                            # Xbox Live Networking Service | ausklammern wenn der Player bereits deinstalliert wurde
    "XboxGipSvc"                               # Xbox Accessory Management Service | ausklammern wenn der Player bereits deinstalliert wurde
    #"xbgm"                                     # Xbox Game Monitoring | ZUGRIFF VERWEIGERT!!! Dienst löschen!!
    "SEMgrSvc"                                 # Zahlungs- und NFC/SE-Manager
    #"MessagingService_3cdefe"                  # MessagingService_3cdefe
    #"UnistoreSvc_3cdefe"                       # Benutzerdatenspeicher _3cdefe
    #"UserDataSvc_3cdefe"                       # Benutzerdatenzugriff_3cdefe
    #"CDPUserSvc_3cdefe"                        # Benutzerdienst für die Plattform für verbundene Geräte_3cdefe
    "DiagTrack"                                # Benutzererfahrung und Telemetrie im verbundenen Modus
    #"UserDataSvc_23721"
    #"UnistoreSvc_23721"
	"WpnService"                                # Windows-Pushbenachrichtigungssystemdienst
	
    
    "WerSvc"
    "WebClient"
    "upnphost"
    "DoSvc"
    "SSDPSRV"
    "PcaSvc"
    "PolicyAgent"
    "ALG"
    "Fax"
    #"WcsPlugInService"
    "Wecsvc"
    #"MpsSvc"                                     # Windows Firewall
    "WbioSrvc"                                   # Windows-Biometriedienst
    "icssvc"                                     # Windows-Dienst fÃ¼r mobile Hotspots
    "NcaSvc"                                     # NetzwerkkonnektivitÃ¤ts-Assistent
    "iphlpsvc"                                   # IP-Hilfsdienst
    "WinHttpAutoProxySvc"                        # WinHTTP-Web Proxy Auto-Discovery-Dienst
    "WalletService"                              # Von Clients der Funktion 'Brieftasche' verwendete Hostobjekte
	#"UsoSvc"                                     # Update Orchestrator Service | wenn Dienst deaktiviert wird, lassen sich in den Einstellungen Update und Sicherheit nicht mehr oeffnen
	"PhoneSvc"                                   # Verwaltet den Telefoniestatus des Geräts
	"TapiSrv"                                    # Bietet Telefonie-API-Unterstützung (TAPI) für Programme, die lokale und über das LAN auf Servern, die diesen Dienst ebenfalls ausführen, angebundene Telefoniegeräte steuern (auch Modem/DFÜ)
    #"EntAppSvc"                                  # Verwaltungsdienst für Unternehmens-Apps | ZUGRIFF VERWEIGERT!!! Dienst löschen!!
	"spectrum"                                   # Windows Perception Service (Ermöglicht die räumliche Wahrnehmung, räumliche Eingaben und holografisches Rendering.)
	"wisvc"                                      # Windows-Insider-Dienst
	"FrameServer"                                # Windows-Kamera-FrameServer
	"LicenseManager"                             # Windows-Lizenz-Manager-Dienst
	"WinRM"                                      # Windows-Remoteverwaltung (WS-Verwaltung)
	"wcncsvc"                                    # Windows-Sofortverbindung - Konfigurationsregistrierungsstelle | Implementierung des WPS (Wireless Protected Setup)-Protokoll
	"RetailDemo"                                 # Dienst für Einzelhandelsdemos
	"SmsRouter"                                  # Microsoft Windows SMS-Routerdienst
	"PNRPsvc"                                    # Peer Name Resolution-Protokoll
	"p2psvc"                                     # Peernetzwerk-Gruppenzuordnung
	"p2pimsvc"                                   # Peernetzwerkidentitäts-Manager
	"PNRPAutoReg"                                # PNRP-Computernamenveröffentlichungs-Dienst
	"HvHost"                                     # HV-Hostdienst
	"vmicvmsession"                              # Hyper-V PowerShell Direct-Dienst
	"vmickvpexchange"                            # Hyper-V-Datenaustauschdienst
	"vmictimesync"                               # Hyper-V-Dienst für Zeitsynchronisierung
	"vmicshutdown"                               # Hyper-V-Dienst zum Herunterfahren des Gasts
	"vmicguestinterface"                         # Hyper-V-Gastdienstschnittstelle
	"vmicrdv"                                    # Hyper-V-Remotedesktopvirtualisierungsdienst
	"vmicheartbeat"                              # Hyper-V-Taktdienst
	"vmicvss"                                    # Hyper-V-Volumeschattenkopie-Anforderer
	"AJRouter"                                   # AllJoyn-Routerdienst
	#"wlidsvc"                                   # Anmelde-Assistent für Microsoft-Konten | gilt auch für UNC Mapping
	#"embeddedmode"
    "AppReadiness"
    #"Schedule"
    "DevQueryBroker"
    #"SystemEventsBroker"


    # Services which cannot be disabled
    #"WdNisSvc"
)

foreach ($service in $services) {
    Get-Service -Name $service | Set-Service -StartupType Disabled
}


### Ende fremdskripte ####



# Testpath: Berechtigungen fehlen
#mkdirpath-force "HKLM:\Policies\Microsoft\Windows\AppPrivacy"

# Test Variablen zur Interfacebestimmung (experimentell, da grep/get-content keine Leerzeichen entfernt)
$NIC="Ethernet" # wenn nicht bekannt kann eine Liste mit Get-NetAdapter ausgegeben oder gleich in eine Variable gepackt werden
# Zeilen schneiden mit $xyz=$xyz.Name.split('\')[-1]
$Iface=Get-NetAdapter -Name $NIC | Select-Object -Property InterfaceGuid | grep -I '\{'
#$Iface=Get-NetAdapter -Name $NIC | Select-Object -Property InterfaceGuid | select Name, InterfaceGuid | select InterfaceGuid | grep -I "{"
# oder alle Adapter angezeigt werden (Reg-Key)
ls -Path "HKLM:\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces" | select -Property name
$iptemp=ipconfig.exe | grep -I "IPv4"
#$LANIP=Get-NetIPAddress -InterfaceAlias Ethernet | select -Property IPAddress | grep -I "1"
$LANIP=$iptemp.Split(': ')[-1]
$gwtemp=ipconfig.exe | grep -I "gateway"
#$GW=Get-NetRoute | select NextHop | grep -I "1"
$GW=$gwtemp.Split(': ')[-1]
$dnstemp=ipconfig.exe /all | grep -I "DNS-Server"
$DNS=$dnstemp.Split(': ')[-1]
# WICHTIG: grep -I "1" ist zu nem geringen Anteil fehleranfaellig (10/8 ok; 192.168/24 ok; 172.16/16 ok; aber z.B. 100/24 nicht ok wenn PC direkt im inet oder falsch konfiguriert!!! Besser Split)
Write-Output ""
Write-Output "Der Name des aktiven $NIC Adapter lautet: $Iface"
Write-Output "Die IP Adresse lautet: $LANIP (Gateway=$GW/DNS=$DNS)"

Write-Output "Vertraute IPs werden eingelesen"
$trustips = @(
#    "192.168.228.50"
    "192.168.228.44"
#    "192.168.228.41"
#    "192.168.228.60"
)
Write-Output "Devil IPs werden eingelesen"
$untrustips = @(
#    "192.168.228.50"
#    "192.168.228.44"
#    "192.168.228.41"
    "192.168.228.60"
)
# Ermittlung angemeldeter Benutzer (ggfs. muss das Skript je Benutzer ausgefuehrt werden)
# assimiliert von Alex Hirsch
$User = New-Object System.Security.Principal.NTAccount($env:UserName)
$SID = $User.Translate([System.Security.Principal.SecurityIdentifier]).value
Write-Output "Der angemeldete Benutzer ist '$User' und seine SID lautet: $SID"

#-----------------------------------------------------------------------------
# Disable Desktop Theme SettingSync
$Wert1="DisableDesktopThemeSettingSync"
$Wert2="DisableDesktopThemeSettingSyncUserOverride"
$Wert3="EnableBackupForWin8Apps"
$DWord="0"
$Key="SettingSync"
$Path="HKLM:\Software\Policies\Microsoft\Windows"
Write-Output "Der Key $Key wird konfiguriert"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path $Path\$Key -Name $Wert1 -Type DWord -Value $DWord -Force
    New-ItemProperty -Path $Path\$Key -Name $Wert2 -Type DWord -Value $DWord -Force
    New-ItemProperty -Path $Path\$Key -Name $Wert3 -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path\$Key -Name $Wert1 -Type DWord -Value $DWord -Force
Set-ItemProperty -Path $Path\$Key -Name $Wert2 -Type DWord -Value $DWord -Force
Set-ItemProperty -Path $Path\$Key -Name $Wert3 -Type DWord -Value $DWord -Force
# Die möglichen Enumerationswerte sind "String, ExpandString, Binary, DWord, MultiString, QWord, Unknown
#-----------------------------------------------------------------------------

# Enable Desktop LightTheme / DarkTheme
$Wert="AppsUseLightTheme"
$DWord="0"
mkdirpath-force "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
$Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
Write-Output "Der Wert $Wert wird konfiguriert"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"

If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# Allow a Windows app to share application data between users
$Wert="AllowSharedLocalAppData"
$DWord="0"
$Path="HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager"
Write-Output "Der Wert $Wert wird konfiguriert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    #New-Item -ItemType Directory -Force -Path $path
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force 

#-----------------------------------------------------------------------------
# Configure Watson events
$Wert="DisableGenericReports"
$DWord="1"
$Key="Microsoft Antimalware"
$SubKey="Reporting"
$Path="HKLM:\SOFTWARE\Policies\Microsoft"
Write-Output "Der Wert $Wert wird konfiguriert"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-Item -Path $Path\$Key -Name $SubKey -Force | Out-Null
    New-ItemProperty -Path $Path\$Key\$SubKey -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path $Path\$Key\$SubKey -Name $Wert -Type DWord -Value $DWord -Force 

#-----------------------------------------------------------------------------
# Windows Error Reporting
$Wert="disabled"
$DWord="1"
$Key="Microsoft Antimalware"
$SubKey="Reporting"
$Path="HKLM:\SOFTWARE\Policies\Microsoft"
Write-Output "Disable-WindowsErrorReporting wird ausgeführt"
Disable-WindowsErrorReporting

#-----------------------------------------------------------------------------
# Turn on behavior monitoring
$Wert="DisableBehaviorMonitoring"
$DWord="1"
$Key="Real-Time Protection"
$Path="HKLM:\Software\Policies\Microsoft\Microsoft Antimalware"
Write-Output "Der Wert $Wert wird konfiguriert"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value $DWord -Force 

#-----------------------------------------------------------------------------
# Verwalten von Verbindungen zwischen Windows-Betriebssystemkomponenten und Microsoft-Diensten
#-----------------------------------------------------------------------------


# 1. Automatisches Update von Stammzertifikaten deaktivieren
# Root Zertifikate sollten auf Stand gehalten werden
# ggfs. muss die Einstellung via GPO wiederholt werden

$Wert="DisableRootAutoUpdate"
$DWord="0"
$Key="AuthRoot"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates"
Write-Output "1. Automatisches Update von Stammzertifikaten wird nicht deaktiviert"
#If (-Not (Test-Path $Path\$Key)) {
#	New-Item -Path $Path -Name $Key -Force | Out-Null
#    New-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 1 -Force 
#}
#Set-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 1 -Force 


# 2. Cortana und Suche trennen / deaktivieren
# AllowCortana kann ausgeschaltet werden, doch langt der Rest bereits

$Key="Windows Search"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows"
Write-Output "2. Anpassungen zu Cortana und Suche werden angelegt"
If (-Not (Test-Path "$Path\$Key")) {
	New-Item -Path $Path -Name "$Key" -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name AllowCortana -Type DWord -Value 0 -Force 
    New-ItemProperty -Path "$Path\$Key" -Name AllowSearchToUseLocation -Type DWord -Value 0 -Force 
    New-ItemProperty -Path "$Path\$Key" -Name DisableWebSearch -Type DWord -Value 1 -Force 
    New-ItemProperty -Path "$Path\$Key" -Name ConnectedSearchUseWeb -Type DWord -Value 0 -Force 
    New-ItemProperty -Path "$Path\$Key" -Name ConnectedSearchPrivacy -Type DWord -Value 3 -Force 
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type DWord -Value 0 -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowSearchToUseLocation -Type DWord -Value 0 -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name DisableWebSearch -Type DWord -Value 1 -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name ConnectedSearchUseWeb -Type DWord -Value 0 -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name ConnectedSearchPrivacy -Type DWord -Value 3 -Force 


# 3. Datum und Uhrzeit am Synchronisieren hindern
# Standardwert fuer Type ist NTP

$Wert="Type"
$Key="Parameters"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\W32Time"
Write-Output "3. Die Zeit Synchronisation und der NtpClient werden abgeschaltet"
Set-ItemProperty -Path $Path\$Key -Name $Wert -Value NoSync -Force 


$Wert="Enabled"
$Key="W32time"
$SubKey="TimeProviders"
$SubKey2="NtpClient"
$Path="HKLM:\SOFTWARE\Policies\Microsoft"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-Item -Path $Path\$Key -Name $SubKey -Force | Out-Null
    New-Item -Path $Path\$Key\$SubKey -Name $SubKey2 -Force | Out-Null
    New-ItemProperty -Path $Path\$Key\$SubKey\$SubKey2 -Name $Wert -Type DWord -Value 0 -Force 
}

Set-ItemProperty -Path $Path\$Key\$SubKey\$SubKey2 -Name $Wert -Type DWord -Value 0 -Force 


# 4. Abrufen von Gerätemetadaten unterbinden
# 5. Mein Gerät suchen; ggfs. muss die Einstellung via GPO vorgenommen werden
# Abrufen von Gerätemetadaten aus dem Internet verhindern
$Wert="PreventDeviceMetadataFromNetwork"
$Key="Device Metadata"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows"
Write-Output "4. Abrufen von Gerätemetadaten wird bearbeitet (5. dt)"
If (-Not (Test-Path "$Path\$Key")) {
	New-Item -Path $Path -Name "$Key" -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value 1 -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value 1 -Force 



# 6. Streamen von Schriftarten

$Wert="EnableFontProviders"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
Write-Output "6. Streamen von Schriftarten wird abgeschaltet"
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value 0 -Force 


# 7. Insider Preview-Builds

$Wert="AllowBuildPreview"
$Key="PreviewBuilds"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows"
Write-Output "7. Insider Preview-Builds Download wird blockiert"
If (-Not (Test-Path "$Path\$Key")) {
	New-Item -Path $Path -Name "$Key" -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value 0 -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value 0 -Force 


# 8. Internet Explorer | Turn on Suggested Sites
# https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.InternetExplorer::EnableSuggestedSites#

$Wert="Enabled"
$Key="Internet Explorer"
$SubKey="Suggested Sites"
$Path="HKLM:\SOFTWARE\Policies\Microsoft"
Write-Output "8. Internet Explorer | Turn on Suggested Sites ('Vorgeschlagene Sites' aktivieren) wird deaktiviert"
If (-Not (Test-Path "$Path\$Key")) {
	New-Item -Path $Path -Name "$Key" -Force | Out-Null
	New-Item -Path $Path\$Key -Name "$SubKey" -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key\$SubKey" -Name $Wert -Type DWord -Value 0 -Force 
}
Set-ItemProperty -Path "$Path\$Key\$SubKey" -Name $Wert -Type DWord -Value 0 -Force 

$SubKey=""
$Wert="AllowServicePoweredQSA"
$Key="Internet Explorer"
$Path="HKLM:\SOFTWARE\Policies\Microsoft"
Write-Output "8. Internet Explorer | Bereitstellen von erweiterten Vorschlägen unterbinden"
New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value 0 -Force 

# 8. Internet Explorer | AutoVervollständigen für Webadressen deaktivieren

$Wert="AutoSuggest"
$Key="Explorer"
$SubKey="AutoComplete"
$Path="HKLM:\SOFTWARE\Policies\Microsoft"
Write-Output "8. Internet Explorer | AutoVervollständigen für Webadressen wird deaktiviert"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
	New-Item -Path $Path\$Key -Name $SubKey -Force | Out-Null
    New-ItemProperty -Path $Path\$Key\$SubKey -Name $Wert -Value No -Force 
}
Set-ItemProperty -Path $Path\$Key\$SubKey -Name $Wert -Value No -Force 


# 8. Internet Explorer | Browser-Geolocation deaktivieren

$Wert="PolicyDisableGeolocation"
$Key="Geolocation"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer"
Write-Output "8. Internet Explorer | Browser-Geolocation wird deaktiviert"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 1 -Force 
}
Set-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 1 -Force 


# 8. Internet Explorer | Verwaltung von SmartScreen-Filtern verhindern

$Wert="EnabledV9"
$Key="PhishingFilter"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer"
Write-Output "8. Internet Explorer | Verwaltung von SmartScreen-Filtern verhindert"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 0 -Force 
}
Set-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 0 -Force 


# 8. Internet Explorer | Kompatibilitätsansicht sperren

$Wert="MSCompatibilityMode"
$Key="MicrosoftEdge"
$SubKey="BrowserEmulation"
$Path="HKLM:\SOFTWARE\Policies\Microsoft"
Write-Output "8. Internet Explorer | Kompatibilitätsansicht wird gesperrt"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
	New-Item -Path $Path\$Key -Name $SubKey -Force | Out-Null
    New-ItemProperty -Path $Path\$Key\$SubKey -Name $Wert -Type DWord -Value 0 -Force 
}
Set-ItemProperty -Path $Path\$Key\$SubKey -Name $Wert -Type DWord -Value 0 -Force 


# 8. Internet Explorer | Vorblättern mit Seitenvorhersage deaktivieren

$Wert="Enabled"
$Key="FlipAhead"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer"
Write-Output "8. Internet Explorer | Vorblättern mit Seitenvorhersage wird deaktiviert"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 0 -Force 
}
Set-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 0 -Force 


# 8. Internet Explorer | Hintergrundsynchronisierung für Feeds und Web Slices deaktivieren

$Wert="BackgroundSyncStatus"
$Key="Feeds"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer"
Write-Output "8. Internet Explorer | Hintergrundsynchronisierung für Feeds und Web Slices wird deaktiviert"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 0 -Force 
}
Set-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 0 -Force 


# 8. Internet Explorer | 8.1 Blockieren von ActiveX-Steuerelementen

$Wert="DownloadVersionList"
$Key="VersionManager"
$Path="HKCU:\Software\Microsoft\Internet Explorer"
Write-Output "8. Internet Explorer | 8.1 ActiveX-Steuerelemente werden deaktiviert"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 0 -Force 
}
Set-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 0 -Force 


# 9. Live-Kacheln abschalten

$Wert="NoCloudApplicationNotification"
$Key="PushNotifications"
$Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion"
Write-Output "9. Live-Kacheln werden abgestellt"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 1 -Force 
}
Set-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value 1 -Force 


# 10. E-Mail-Synchronisierung für Microsoft-Konten abschalten

$Wert="ManualLaunchAllowed"
$Key="Windows Mail"
$Path="HKLM:\SOFTWARE\Policies\Microsoft"
Write-Output "10. E-Mail-Synchronisierung wird abgeschaltet"
If (-Not (Test-Path "$Path\$Key")) {
	New-Item -Path $Path -Name "$Key" -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value 0 -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value 0 -Force 


# 11. Microsoft-Konto
#     Kommunikation mit dem Clouddienst für die Authentifizierung mithilfe eines Microsoft-Kontos unterbinden.

$Wert="NoConnectedUser"
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Write-Output "11. Microsoft-Konto | NoConnectedUser wird abgeschaltet"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value 3 -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value 3 -Force 

# Benutzer können keine Microsoft-Konten hinzufügen
$Wert="wlidsvc"
$Path="HKLM:\System\CurrentControlSet\Services"
Write-Output "11. Microsoft-Konto | wlidsvc wird abgeschaltet"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value 3 -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value 3 -Force 


# 12. Microsoft Edge Einstellungen verwalten

$Wert="Use FormSuggest"
$Key="Main"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge"
Write-Output "12. Microsoft Edge | AutofAusfüllen konfigurieren"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Value no -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Value no -Force 

$Wert="DoNotTrack"
$Key="Main"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
Write-Output "12. Microsoft Edge | DoNotTrack wird konfiguriert"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value 1 -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value 1 -Force 

$Wert="FormSuggest Passwords"
$Key="Main"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
Write-Output "12. Microsoft Edge | Kennwort-Manager wird konfiguriert"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Value no -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Value no -Force

$Wert="ShowSearchSuggestionsGlobal"
$Key="SearchScopes"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge"
Write-Output "12. Microsoft Edge | Suchvorschläge in Adressleiste konfigurieren"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value 0 -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value 0 -Force 

# Windows Defender SmartScreen-Filter (Windows10 Version 1703) konfigurieren
$Wert="EnabledV9"
$Key="PhishingFilter"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge"
Write-Output "12. Microsoft Edge | Suchvorschläge in Adressleiste konfigurieren"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value 0 -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value 0 -Force 

# Webinhalte auf der Seite „Neuer Tab“ zulassen
$Wert="AllowWebContentOnNewTabPage"
$Key="Main"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes"
Write-Output "12. Microsoft Edge | Webinhalte in 'Neuer Tab' wird konfiguriert"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Value no -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Value no -Force

# Unternehmensstartseiten konfigurieren
$Wert="ProvisionedHomePages"
$DWord="1"
$Key="ServiceUI"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge"
Write-Output "12. Microsoft Edge | ProvisionedHomePages wird auf $DWord gesetzt"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force


# 13. Netzwerkverbindungs-Statusanzeige konfigurieren

# Aktive Tests der Windows-Netzwerkverbindungs-Statusanzeige deaktivieren
$Wert="NoActiveProbe"
$DWord="1"
$Key="NetworkConnectivityStatusIndicator"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows"
Write-Output "13. Netzwerkverbindungs-Statusanzeigetest wird deaktiviert"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force


# 14. Offlinekarten konfigurieren

$Wert="AutoDownloadAndUpdateMapData"
$DWord="0"
$Key="Maps"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows"
Write-Output "14. Offlinekarten wird deaktiviert | Auto Download And Update MapData wird abgeschaltet"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force

# (Windows 10 Version 1607 und höher)
$Wert="AllowUntriggeredNetworkTrafficOnSettingsPage"
$DWord="0"
$Key="Maps"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows"
Write-Output "14. Offlinekarten wird deaktiviert | Disallow Untriggered Network Traffic On Settings Page"
If (-Not (Test-Path "$Path\$Key")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

# 15. OneDrive deaktivieren
# Das Script remove-onedrive.ps1 kann im Abschluss zum Deinstallieren verwendet werden
# WICHTIG! OneDrive zum Schluss deinstalieren

$Wert="DisableFileSyncNGSC"
$DWord="1"
$Key="OneDrive"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows"
Write-Output "15. OneDrive wird deaktiviert (DisableFileSyncNGSC)"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force

# 16. Vorinstallierte Apps deinstallieren
# Das Script remove-default-apps.ps1 kann im Abschluss zum Deinstallieren verwendet werden
# WICHTIG! Die APPs zum Schluss deinstalieren

# Nachrichten-App
#Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingNews"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get-AppxPackage Microsoft.BingNews | Remove-AppxPackage

# Wetter-App
#Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingWeather"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get-AppxPackage Microsoft.BingWeather | Remove-AppxPackage

# Money-App
#Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingFinance"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get-AppxPackage Microsoft.BingFinance | Remove-AppxPackage

# Sport-App
#Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingSports"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get-AppxPackage Microsoft.BingSports | Remove-AppxPackage

# Twitter-App
#Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "*.Twitter"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get-AppxPackage *.Twitter | Remove-AppxPackage

#XBOX-App
#Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.XboxApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage

# Sway-App
#Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.Office.Sway"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get-AppxPackage Microsoft.Office.Sway | Remove-AppxPackage

# OneNote-App
#Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.Office.OneNote"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get-AppxPackage Microsoft.Office.OneNote | Remove-AppxPackage

# App zum Beziehen von Office
#Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.MicrosoftOfficeHub"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get-AppxPackage Microsoft.MicrosoftOfficeHub | Remove-AppxPackage

# App zum Beziehen von Skype
#Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.SkypeApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage

# Kurznotizen-App
#Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.MicrosoftStickyNotes"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}.
#Get-AppxPackage Microsoft.MicrosoftStickyNotes | Remove-AppxPackage.

# 17. Einstellungen > Datenschutz
# 17.1 Allgemein

# Apps die Verwendung meiner Werbe-ID für die App-übergreifende Nutzung verbieten
$Wert="Enabled"
$Alternativwert="DisabledByGroupPolicy"
$DWord="0"
$AlternativDWord="1"
$Key="AdvertisingInfo"
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
Write-Output "17. Einstellungen > Datenschutz | 17.1 Allgemein konfiguriert ($Key)"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force
    New-ItemProperty -Path "$Path\$Key" -Name $Alternativwert -Type DWord -Value $AlternativDWord -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force
Set-ItemProperty -Path "$Path\$Key" -Name $Alternativwert -Type DWord -Value $AlternativDWord -Force

# Websites den Zugriff auf die eigene Sprachliste verbieten, um die Anzeige lokal relevanter Inhalte zu verhindern
# [Windows10Bug]: Der Wert muss negiert werden, also statt der 0 muss 1 gesetzt werden
# erledigt auch fix-privacy-settings.ps1
$Wert="HttpAcceptLanguageOptOut"
$DWord="1"
$Key=""
$Path="HKCU:\Control Panel\International\User Profile"
Write-Output "17. Einstellungen > Datenschutz | 17.1 Allgemein wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

# Windows verbieten, das Starten von Apps nachzuverfolgen, um Start und Suchergebnisse zu verbessern
# oder wohl eher bedas im Profiling zu verbessern
# (in der Pro Version 1703 ist der Wert für [HKCU] bereits richtig gesetzt)
$Wert="Start_TrackProgs"
$DWord="0"
$Key=""
$Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Write-Output "17. Einstellungen > Datenschutz | 17.1 Allgemein konfiguriert (Start_TrackProgs)"
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

# SmartScreen-Filter ausschalten, um von Microsoft Store-Apps verwendete Webinhalte (URLs) nicht zu überprüfen
# SmartScreen-Filter filtert auch im Windows Explorer
# erledigt auch fix-privacy-settings.ps1 in HKCU
$Wert="EnableWebContentEvaluation"
$DWord="0"
$Key=""
$Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
Write-Output "17. Einstellungen > Datenschutz | 17.1 Allgemein wird konfiguriert ($Wert)"
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
# (experimentell) >> Berechtigungen fehlen
#$Wert="CheckExeSignatures"
#$String="no"
#$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\Download"
#Write-Output "17. Einstellungen > Datenschutz | 17.1 Allgemein (optional) wird konfiguriert ($Wert)"
#Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
#$Wert="Error Dlg Displayed On Every Error"
#$String="no"
#$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\Main"
#Write-Output "17. Einstellungen > Datenschutz | 17.1 Allgemein (optional) wird konfiguriert ($Wert)"
#Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
#$Wert="DEPOff"
#$DWord="0"
#Write-Output "17. Einstellungen > Datenschutz | 17.1 Allgemein (optional) wird konfiguriert ($Wert)"
#Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
#$Wert="Force Offscreen Composition"
#$DWord="1"
#Write-Output "17. Einstellungen > Datenschutz | 17.1 Allgemein (optional) wird konfiguriert ($Wert)"
#Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

# Apps auf anderen Geräten das Öffnen von Apps verbieten
$Wert="EnableCdp"
$DWord="0"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
Write-Output "17. Einstellungen > Datenschutz | 17.1 Allgemein konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force


# 17.2 Position

# Zugriff auf standortspezifische Sensoren verbieten nicht moeglich
# nach MDM-Richtlinie angewendet aber ungecheckt
# 0. Deaktiviert und vom Mitarbeiter nicht aktivierbar.
# 1. Aktiviert, aber der Mitarbeiter kann wählen, ob er sie verwendet. (Standard)
# 2. Aktiviert und vom Mitarbeiter nicht deaktivierbar.
# Datenschutzbestimmungen für die App' existiert in Windows 10 Pro Version 1703 nicht in den GPOs
# und Policies darf in HKLM: nicht angelegt werden (alternativ unter DaRT anlegen)
$Wert="LetAppsAccessLocation"
$DWord="0"
$Key="Policies"
$Path="HKLM:"
Write-Output "17. Einstellungen > Datenschutz | 17.2 Position ist gesperrt ($Key)"
Write-Output "Das Schreiben im Root Verzeichnis $Path ist gesperrt."
Write-Output "Der Wert $Wert konnte nicht angelegt werden."

# Speicherort
$Wert="DisableLocation"
$DWord="1"
$Key="Policies"
$Path="HKLM:"
Write-Output "17. Einstellungen > Datenschutz | Speicherort ist gesperrt ($Key)"
Write-Output "Das Schreiben im Root Verzeichnis $Path ist gesperrt."
Write-Output "Der Wert $Wert konnte nicht angelegt werden."


# 17.3 Kamera

# Apps die Verwendung meiner Kamera verbieten nicht moeglich
# Datenschutzbestimmungen für die App existiert in Windows 10 Pro Version 1703 nicht in den GPOs
# und Policies darf in HKLM: nicht angelegt werden
$Wert="LetAppsAccessCamera"
$DWord="2"
$Key="Policies"
$Path="HKLM:"
Write-Output "17. Einstellungen > Datenschutz | 17.3 Kamera ist gesperrt ($Key)"
Write-Output "Das Schreiben im Root Verzeichnis $Path ist gesperrt."
Write-Output "Der Wert $Wert konnte nicht angelegt werden."


# 17.4 Mikrofon

# Apps die Verwendung meines Mikrofons verbieten nicht moeglich
# Datenschutzbestimmungen für die App existiert in Windows 10 Pro Version 1703 nicht in den GPOs
# und Policies darf in HKLM: nicht angelegt werden
$Wert="LetAppsAccessMicrophone"
$DWord="2"
$Key="Policies"
$Path="HKLM:"
Write-Output "17. Einstellungen > Datenschutz | 17.4 Mikrofon ist gesperrt ($Key)"
Write-Output "Das Schreiben im Root Verzeichnis $Path ist gesperrt."
Write-Output "Der Wert $Wert konnte nicht angelegt werden."


# 17.5 Benachrichtigungen

# Apps den Zugriff auf meine Benachrichtigungen verbieten nicht moeglich
# Datenschutzbestimmungen für die App existiert in Windows 10 Pro Version 1703 nicht in den GPOs
# und Policies darf in HKLM: nicht angelegt werden
$Wert="LetAppsAccessNotifications"
$DWord="2"
$Key="Policies"
$Path="HKLM:"
Write-Output "17. Einstellungen > Datenschutz | 17.5 Benachrichtigungen ist gesperrt ($Key)"
Write-Output "Das Schreiben im Root Verzeichnis $Path ist gesperrt."
Write-Output "Der Wert $Wert konnte nicht angelegt werden."
Write-Output "GPO Computerkonfiguration > Administrative Vorlagen > Windows-Komponenten > App-Datenschutz > Windows-App-Zugriff auf Benachrichtigungen zulassen"
# siehe eigene Hacks

# 17.6 Spracherkennung, Freihand und Eingabe

# Spracherkennung, Freihand und Eingabe verbieten nicht moeglich
# Datenschutzbestimmungen für die App existiert in Windows 10 Pro Version 1703 nicht in den GPOs
# und Policies darf in HKLM: nicht angelegt werden
$Wert="RestrictImplicitInkCollection"
$DWord="1"
$Key="Policies"
$Path="HKLM:"
Write-Output "17. Einstellungen > Datenschutz | 17.6 Spracherkennung, Freihand und Eingabe ist gesperrt ($Key)"
Write-Output "Das Schreiben im Root Verzeichnis $Path ist gesperrt."
Write-Output "Der Wert $Wert konnte nicht angelegt werden."
### Computerkonfiguration > Administrative Vorlagen > Windows-Komponenten > Spracherkennung > Automatisches Update fuer Sprachdaten zulassen (ab Version 1703)

# oder...Wert in Windows 10 Pro Version 1703 bereits mit korrekt vorhanden
$Wert="AcceptedPrivacyPolicy"
$DWord="0"
$Path="HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
Write-Output "17. Einstellungen > Datenschutz | 17.6 Spracherkennung, Freihand und Eingabe wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

# und...Wert in Windows 10 Pro Version 1703 bereits mit korrekt vorhanden
$Wert="HarvestContacts"
$DWord="0"
$Key="InputPersonalization"
$SubKey="TrainedDataStore"
$Path="HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
Write-Output "17. Einstellungen > Datenschutz | 17.6 Spracherkennung, Freihand und Eingabe wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
   	New-Item -Path $Path\$Key -Name $SubKey -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key\$SubKey" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

# Ab Windows 10 Version 1703 kann man mit dem folgenden Registrierungsschlüssel Updates für das Spracherkennungs- und Sprachsynthesemodell deaktivieren.
$Wert="ModelDownloadAllowed"
$DWord="0"
$Path="HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences"
Write-Output "17. Einstellungen > Datenschutz | 17.6 Spracherkennung, Freihand und Eingabe wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force


# 17.7 Kontoinformationen

# Apps den Zugriff auf meinen Namen, mein Bild und andere Kontoinfos verbieten
# Der Key 'AppPrivacy' wird in der Home Edition nicht durch das Script angelegt
$Wert="LetAppsAccessContacts"
$DWord="2"
$Key="AppPrivacy"
$Path="HKLM:\SOFTWARE\Microsoft\Windows"
Write-Output "17. Einstellungen > Datenschutz | 17.7 Kontoinformationen wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Key")) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force


# 17.8 Kontakte

# Apps den Zugriff auf Kontakte verbieten
### Computerkonfiguration > Administrative Vorlagen > Windows-Komponenten > App-Datenschutz > Windows-App-Zugriff auf Kontakte zulassen
Write-Output "17. Einstellungen > Datenschutz | 17.8 Kontakte (nur via GPO)"
Write-Output "MANUELL: 'Windows-App-Zugriff auf Kontakte zulassen' via GPO manuell deaktiveren!"


# 17.9 Kalender

# Apps den Zugriff auf Kalender verbieten
$Wert="LetAppsAccessCalendar"
$DWord="2"
$Key=""
$Path="HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy"
Write-Output "17. Einstellungen > Datenschutz | 17.9 Kalender wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force


# 17.10 Anrufliste

# Apps den Zugriff auf meine Anrufliste verbieten
$Wert="LetAppsAccessCallHistory"
$DWord="2"
$Key=""
$Path="HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy"
Write-Output "17. Einstellungen > Datenschutz | 17.10 Anrufliste wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force


# 17.11 E-Mail

# Apps den Zugriff und das Senden von E-Mails verbieten
$Wert="LetAppsAccessEmail"
$DWord="2"
$Key=""
$Path="HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy"
Write-Output "17. Einstellungen > Datenschutz | 17.11 E-Mail wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force


# 17.12 Nachrichten

# Apps das Lesen oder Senden von Nachrichten (SMS oder MMS) verbieten
$Wert="LetAppsAccessMessaging"
$DWord="2"
$Key=""
$Path="HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy"
Write-Output "17. Einstellungen > Datenschutz | 17.12 Nachrichten wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force


# 17.13 Anrufe

# Apps Anrufe verbieten
$Wert="LetAppsAccessPhone"
$DWord="2"
$Key=""
$Path="HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy"
Write-Output "17. Einstellungen > Datenschutz | 17.13 Anrufe wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force


# 17.14 Funkempfang

# Funksteuerung durch Apps verbieten
$Wert="LetAppsAccessRadios"
$DWord="2"
$Key=""
$Path="HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy"
Write-Output "17. Einstellungen > Datenschutz | 17.14 Funkempfang wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force


# 17.15 Weitere Geräte

# verbieten Sie Apps, automatisch Informationen mit Drahtlosgeräten auszutauschen und zu synchronisieren, die nicht explizit mit Ihrem PC, Tablet oder Handy gekoppelt sind
$Wert="LetAppsSyncWithDevices"
$DWord="2"
$Key=""
$Path="HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy"
Write-Output "17. Einstellungen > Datenschutz | 17.15 Weitere Geräte wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

# verbieten Sie Apps die Verwendung vertrauenswürdiger Geräte (bereits angeschlossene oder mit dem PC, Tablet oder Handy gelieferte Hardware)
### Computerkonfiguration > Administrative Vorlagen > Windows-Komponenten > App-Datenschutz > Windows-App-Zugriff auf vertrauenswürdige Geräte zulassen
Write-Output "17. Einstellungen > Datenschutz | 17.15 Verwendung vertrauenswürdiger Geräte (nur via GPO)"
Write-Output "MANUELL: 'Windows-App-Zugriff auf vertrauenswürdige Geräte zulassen' via GPO manuell deaktiveren!"


# 17.16 Feedback und Diagnose

# Feedbackbenachrichtigungen nicht mehr anzeigen
$Wert="DoNotShowFeedbackNotifications"
$DWord="1"
$Key="Policies"
$Path="HKLM:"
Write-Output "17. Einstellungen > Datenschutz | 17.16 Feedback und Diagnose Feedbackbenachrichtigungen ist gesperrt ($Key)"
Write-Output "Das Schreiben im Root Verzeichnis $Path ist gesperrt."
Write-Output "Der Wert $Wert konnte nicht angelegt werden."
### Computerkonfiguration > Administrative Vorlagen > Windows-Komponenten > Datensammlung und Vorabversionen > Feedbackbenachrichtigungen nicht mehr anzeigen
$Wert="PeriodInNanoSeconds"
$DWord="0"
$Key="Siuf"
$SubKey="Rules"
$Path="HKCU:\Software\Microsoft"
Write-Output "17. Einstellungen > Datenschutz | 17.16 Feedback und Diagnose Feedbackbenachrichtigungen wird in HKCU konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
   	New-Item -Path $Path\$Key -Name $SubKey -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key\$SubKey" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path\$Key\$SubKey" -Name $Wert -Type DWord -Value $DWord -Force
$Wert="NumberOfSIUFInPeriod"
$DWord="0"
$Key=""
$Path="HKCU:\Software\Microsoft\Siuf\Rules"
Write-Output "17. Einstellungen > Datenschutz | 17.16 Feedback und Diagnose Feedbackbenachrichtigungen wird in HKCU wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

# Telemetriestufe mit Registrierungs-Editor (Wert vorhanden und aktiviert) deaktiveren
$Wert="AllowTelemetry"
$DWord="0"
$Key=""
$Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
Write-Output "17. Einstellungen > Datenschutz | 17.16 Feedback und Diagnose wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

# Telemetrie deaktiveren
$Wert="AllowTelemetry"
$DWord="0"
$Key=""
$Path="HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
Write-Output "17. Einstellungen > Datenschutz | 17.16 Feedback und Diagnose wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force 
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

# Microsoft verbieten, Diagnosedaten zu verwenden
### GPO Benutzerkonfiguration > Administrative Vorlagen > Windows-Komponenten > Cloud-Inhalte > keine Diagnosedaten zur Personalisierte der Benutzererfahrungen verwenden
Write-Output "17. Einstellungen > Datenschutz | 17.16 Feedback und Diagnose keine Diagnosedaten zur Personalisierte der Benutzererfahrungen verwenden (nur via GPO)"
Write-Output "MANUELL: 'keine Diagnosedaten zur Personalisierte der Benutzererfahrungen verwenden' via GPO manuell deaktiveren!"


# 17.17 Hintergrund-Apps den Start verbieten

# Ausführung von Apps im Hintergrund verbieten (Nur ab Windows10 Version 1703)
### GPO Computerkonfiguration > Administrative Vorlagen > Windows-Komponenten > App-Datenschutz > Ausführung von Windows-Apps im Hintergrund zulassen
Write-Output "17. Einstellungen > Datenschutz | 17.16 Feedback und Diagnose Ausführung von Windows-Apps im Hintergrund verbieten (nur via GPO)"
Write-Output "MANUELL: 'Ausführung von Windows-Apps im Hintergrund zulassen' via GPO manuell deaktiveren!"


# 17.18 Bewegung verbieten

# Windows und den Apps die Verwendung meiner Positionsdaten und meines Positionsverlaufs verbieten
$Wert="LetAppsAccessMotion"
$DWord="2"
$Key="Policies"
$Path="HKLM:\Policies\Microsoft\Windows\AppPrivacy"
Write-Output "17. Einstellungen > Datenschutz | 17.18 Bewegung ist gesperrt ($Key)"
Write-Output "Das Schreiben im Root Verzeichnis $Path ist gesperrt."
Write-Output "Der Wert $Wert konnte nicht angelegt werden."
### Computerkonfiguration > Administrative Vorlagen > Windows-Komponenten > App-Datenschutz > Windows-App-Zugriff auf Bewegungsdaten zulassen
Write-Output "MANUELL: 'Windows-App-Zugriff auf Bewegungsdaten zulassen' via GPO manuell deaktiveren!"


# 17.19 Aufgaben verbieten

# Windows-App-Zugriff auf Aufgaben verbieten
Write-Output "17. Einstellungen > Datenschutz | 17.19 Aufgaben ist gesperrt"
### GPO Computerkonfiguration > Administrative Vorlagen > Windows-Komponenten > App-Datenschutz > Windows-App-Zugriff auf Aufgaben
Write-Output "MANUELL: 'Windows-App-Zugriff auf Aufgaben' via GPO manuell deaktiveren!"


# 17.20 App-Diagnose verbieten

# Windows-App-Zugriff auf Diagnoseinformationen anderer Apps verbieten
Write-Output "17. Einstellungen > Datenschutz | 17.20 App-Diagnose ist gesperrt"
### Computerkonfiguration > Administrative Vorlagen > Windows-Komponenten > App-Datenschutz > Windows-App-Zugriff auf Diagnoseinformationen anderer Apps zulassen
Write-Output "MANUELL: 'Windows-App-Zugriff auf Diagnoseinformationen anderer Apps zulassen' via GPO manuell deaktiveren!"


# 18. Softwareschutz-Plattform

# Keine Schlüsselverwaltungsservers (Key Management Server, KMS) verwalten
$Wert="LetAppsAccessContacts"
$DWord="2"
$Key=""
$Path="HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy"
Write-Output "17. Einstellungen > Datenschutz | 18. Softwareschutz-Plattform (siehe Punkt 17.1)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force


# 19. Synchronisieren von Einstellungen verbieten

# Nicht synchronisieren
$Wert="DisableSettingSync"
$DWord="2"
$Key="Policies"
$Path="HKLM:\Policies\Microsoft\Windows\SettingSync"
Write-Output "17. Einstellungen > Datenschutz | 19. Synchronisieren von Einstellungen ist gesperrt ($Key)"
Write-Output "Es werden keine Anpassungen vorgenommen!"

$Wert="DisableSettingSyncUserOverride"
$DWord="1"
$Key="Policies"
$Path="HKLM:\Policies\Microsoft\Windows\SettingSync"
Write-Output "17. Einstellungen > Datenschutz | 19. Synchronisieren von Einstellungen ist gesperrt ($Key)"
Write-Output "Es werden keine Anpassungen vorgenommen!"

# Cloudsynchronisierung von Nachrichten verbieten
$Wert="CloudServiceSyncEnabled"
$DWord="0"
$Key=""
$Path="HKCU:\SOFTWARE\Microsoft\Messaging"
Write-Output "17. Einstellungen > Datenschutz | 19. Synchronisieren von Einstellungen wird deaktiviert"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

# 20. Teredo und IPv6 abschalten

Write-Output "Aktuelle Netzwerkkarteneinstellungen:"
ipconfig
Write-Output "ipv6 6to4 wird deaktiviert"
netsh interface ipv6 6to4 set state disabled default
Write-Output "ipv6 isatap wird deaktiviert"
netsh interface ipv6 isatap set state disabled
Write-Output "ipv6 teredo wird deaktiviert"
netsh interface ipv6 set teredo disabled
Write-Output "teredo wird deaktiviert"
netsh interface teredo set state disabled

netsh interface ipv6 6to4 show state

netsh interface ipv6 isatap show state

netsh interface ipv6 show teredo
Write-Output "Adapterbindung 'Eigenschaften von Ethernet' zu Protokollen aufheben"
# IPv6 den Haken in den Eigenschaften von Ethernet entfernen und insgesamt anschalten
Set-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6 -Enabled $false
# QoS wird nur auf PCs mit mehr als einer NIC verwendet oder macht anders wenig Sinn >> abschalten
Set-NetAdapterBinding -Name Ethernet -ComponentID ms_pacer -Enabled $false
# Datei- und Druckerfreigabe für Microsoft-Netzwerke den Haken in den Eigenschaften von Ethernet entfernen (Deiteifreigabe und UNC Pfade offline)
#Set-NetAdapterBinding -Name Ethernet -ComponentID ms_server -Enabled $false
# Antwort für Verbindungsschicht-Topologieerkennung abhaken (experimentell)
#Set-NetAdapterBinding -Name Ethernet -ComponentID ms_rspndr -Enabled $false

# Toredo (Xbox-Gaming-Features und Windows Update-Übermittlungsoptimierung) abschalten
$Wert="Teredo_State"
$String="Disabled"
$Key="TCPIP"
$SubKey="v6Transition"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows"
Write-Output "17. Einstellungen > Datenschutz | 20. Teredo und IPv6 wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-Item -Path $Path\$Key -Name $SubKey -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key\$SubKey" -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path "$Path\$Key\$SubKey" -Name $Wert -Type String -Value $String -Force

# TIPPs
# WoL deaktivieren
#Get-NetAdapter -Physical -Name Eth* | Get-NetAdapterPowerManagement | select Name, WakeOnMagicPacket
#Set-NetAdapterPowerManagement -Name Ethernet -WakeOnMagicPacket Disabled


# 21. WLAN-Optimierung verhinern

# Geräte nicht automatisch mit bekannten Hotspots und den WLAN-Netzwerken verbinden
$Wert="AutoConnectAllowedOEM"
$DWord="0"
$Key=""
$Path="HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
Write-Output "17. Einstellungen > Datenschutz | 21. WLAN-Optimierung wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force


# 22. Windows Defender konfigurieren

# Beitritt zu Microsoft MAPS verhindern
# Verbindung mit dem Microsoft-Antischadsoftware-Schutzdienst trennen
$Wert="SpyNetReporting"
$DWord="0"
$Key="Spynet"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
Write-Output "17. Einstellungen > Datenschutz | 22. Windows Defender wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force

# Dateibeispiele senden, wenn eine weitere Analyse erforderlich ist, verhindern
$Wert="SubmitSamplesConsent"
$DWord="2"
$Key="Spynet"
$Path="HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet"
Write-Output "17. Einstellungen > Datenschutz | 22. Windows Defender wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force

# Herunterladen von Definitionsupdates beenden
# FallbackOrder = FileShares checken!!
$Wert="FallbackOrder"
$String="FileShares"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Updates"
Write-Output "17. Einstellungen > Datenschutz | 22. Windows Defender wird nicht konfiguriert ($Wert = $String ergibt keinen Sinn)"
#If (-Not (Test-Path "$Path\$Wert")) {
#    New-ItemProperty -Path "$Path" -Name $Wert -Type String -Value $String -Force
#}
#Set-ItemProperty -Path "$Path" -Name $Wert -Type String -Value $String -Force

# Benutzeroberfläche wird angelegt (nur bei Bedarf auf 1 stellen)
$Wert="DontReportInfectionInformation"
$DWord="0"
$Key="MRT"
$Path="HKLM:\Software\Policies\Microsoft"
Write-Output "17. Einstellungen > Datenschutz | 22. Windows Defender Benutzeroberfläche wird angelegt ($Wert nur bei Bedarf auf 1 stellen)"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force


# 23. Windows Media Player deinstallieren

# Windows Media Player unter Windows 10 entfernen
Write-Output "17. Einstellungen > Datenschutz | 23. Windows Media Player wird deinstalliert"
dism /online /Disable-Feature /FeatureName:WindowsMediaPlayer

# 24. Windows-Blickpunkt

# Features von Windows-Blickpunkt deaktivieren
# Windows-Blickpunkt stellt verschiedene Hintergrundbilder und Text auf dem Sperrbildschirm bereit und zeigt App-Vorschläge, Microsoft-Kontobenachrichtigungen und Windows-Tipps an.
$Wert="DisableWindowsSpotlightFeatures"
$DWord="1"
$Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Write-Output "17. Einstellungen > Datenschutz | 24. Windows-Blickpunkt wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force

#  Windows-Tipps nicht anzeigen
$Wert="DisableWindowsConsumerFeatures"
$DWord="1"
$Key="CloudContent"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows"
Write-Output "17. Einstellungen > Datenschutz | 24. Windows-Blickpunkt Windows-Tipps nicht anzeigen wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force


# 25. Microsoft Store deaktivieren

#  Windows-Tipps nicht anzeigen
$Wert="DisableStoreApps"
$DWord="1"
$Key="WindowsStore"
$Path="HKLM:\SOFTWARE\Policies\Microsoft"
Write-Output "17. Einstellungen > Datenschutz | 25. Microsoft Store wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force

# Oder...
$Wert="AutoDownloads"
$DWord="2"
$Key="WindowsStore"
$Path="HKLM:\SOFTWARE\Policies\Microsoft"
Write-Output "17. Einstellungen > Datenschutz | 25. Microsoft Store wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force


# 26. Windows Update-Übermittlungsoptimierung konfigurieren
# 26.1 Einstellungen > Update und Sicherheit
# 26.2 Gruppenrichtlinien für Übermittlungsoptimierung konfigurieren
# 26.3 MDM-Richtlinien für Übermittlungsoptimierung
# 26.4 Windows-Bereitstellung der Übermittlungsoptimierung

# Verwende BITS anstelle der Windows Update-Übermittlungsoptimierung
# Mithilfe der Windows Update-Übermittlungsoptimierung können Sie Windows-Updates und Microsoft Store-Apps neben Microsoft auch von anderen Quellen beziehen.
$Wert="DODownloadMode"
$DWord="100"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
Write-Output "17. Einstellungen > Datenschutz | 26. Windows Update-Übermittlungsoptimierung wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force


# 27. Windows Update knofigurieren

# Windows Update deaktivieren
$Wert="DoNotConnectToWindowsUpdateInternetLocations"
$DWord="1"
$Key="WindowsUpdate"
$Path="HKLM:\Software\Policies\Microsoft\Windows"
Write-Output "17. Einstellungen > Datenschutz | 25. Microsoft Store wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Key")) {
   	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force

$Wert="DisableWindowsUpdateAccess"
$DWord="1"
$Key="WindowsUpdate"
$Path="HKLM:\Software\Policies\Microsoft\Windows"
Write-Output "17. Einstellungen > Datenschutz | 25. Microsoft Store wird nicht konfiguriert ($Wert)"
#If (-Not (Test-Path "$Path\$Key")) {
#   	New-Item -Path $Path -Name $Key -Force | Out-Null
#    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force
#}
#Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force

$Wert="AU"
$DWord="1"
$Key="WindowsUpdate"
$Path="HKLM:\Software\Policies\Microsoft\Windows"
Write-Output "17. Einstellungen > Datenschutz | 25. Microsoft Store wird nicht konfiguriert ($Wert)"
#If (-Not (Test-Path "$Path\$Key")) {
#   	New-Item -Path $Path -Name $Key -Force | Out-Null
#    New-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force
#}
#Set-ItemProperty -Path "$Path\$Key" -Name $Wert -Type DWord -Value $DWord -Force

# Automatische Updates konfigurieren
$Wert="AutoDownload"
$DWord="5"
$Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate"
Write-Output "17. Einstellungen > Datenschutz | 25. Microsoft Store wird konfiguriert ($Wert)"
If (-Not (Test-Path "$Path\$Wert")) {
    New-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path "$Path" -Name $Wert -Type DWord -Value $DWord -Force



#-----------------------------------------------------------------------------
# Eigene Hacks
#-----------------------------------------------------------------------------

# NetBIOS abhaken und WINS deaktieren (experimentell)
$Wert="NetbiosOptions"
$DWord="2"
$NIC="Ethernet"
$Iface=Get-NetAdapter -Name $NIC | Select-Object -Property InterfaceGuid | grep -I '\{'
$Key="Tcpip_$Iface"
$Path="HKLM:\SYSTEM\ControlSet001\Services\NetBT\Parameters\Interfaces"
Write-Output "Der Key $Key wird konfiguriert"
If (-Not (Test-Path $Path\$Key)) {
	New-Item -Path $Path -Name $Key -Force | Out-Null
    New-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path\$Key -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# Firewall konfigurieren
$Wert="DisableNotifications"
$DWord="1"
$Key="Tcpip_$Iface"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\$Key"
Write-Output "Windows Firewall wird konfiguriert ($Wert)"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="EnableFirewall"
$DWord="1"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Tcpip_$Iface"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="DoNotAllowExceptions"
$DWord="1"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Tcpip_$Iface"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# Spieleleiste Button deaktivieren
$Wert="AppCaptureEnabled"
$DWord="0"
$Key="GameDVR"
$Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
Write-Output "Der 'Spieleleiste' Button wird deaktiviert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="GameDVR_FSEBehaviorMode"
$DWord="2"
$Key="GameConfigStore"
$Path="HKCU:\System\GameConfigStore"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
#    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
#Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="GameDVR_Enabled"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="GameDVR_FSEBehavior"
$DWord="2"
If (-Not (Test-Path $Path\$Wert)) {
#    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
#Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# Spielmodus Button deaktivieren
$Wert="AllowAutoGameMode"
$DWord="0"
$Path="HKCU:\Software\Microsoft\GameBar"
Write-Output "Der 'Spielmodus' Button wird deaktiviert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="UseNexusForGameBarEnabled"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

# Stift & Windows lnk Button deaktivieren
$Wert="PenWorkspaceAppSuggestionsEnabled"
$DWord="0"
$Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace"
Write-Output "Der 'Stift & Windows lnk' Button wird deaktiviert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# Remoteunterstützungsverbindungen nicht gestatten
$Wert="fAllowFullControl"
$DWord="0"
$Path="HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
Write-Output "Der 'Remoteunterstützungsverbindungen' wird konfiguriert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="fAllowToGetHelp"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="fEnableChatControl"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# Gemeinsame Nutzung (APPs auf anderen Geraeten Oeffnen) deaktivieren >> Reboot erforderlich
$Wert="RomeSdkChannelUserAuthzPolicy"
$DWord="0"
$Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP"
Write-Output "'APPs auf anderen Geraeten Oeffnen' wird konfiguriert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# Content Delivery Manager abschalten
$Wert="FeatureManagementEnabled"
$DWord="0"
$Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
Write-Output "'Content Delivery Manager' wird abgeschaltet"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="OemPreInstalledAppsEnabled"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="PreInstalledAppsEnabled"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="RotatingLockScreenEnabled"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="RotatingLockScreenOverlayEnabled"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="SilentInstalledAppsEnabled"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="SilentInstalledAppsEnabled"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="SubscribedContent-310093Enabled"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# Keine Windows Tipps, Tricks und Vorschlaege erhalten >> Reboot erforderlich
$Wert="SoftLandingEnabled"
$DWord="0"
$Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
Write-Output "'Keine Windows Tipps, Tricks und Vorschlaege erhalten' wird konfiguriert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="SystemPaneSuggestionsEnabled"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="ContentDeliveryAllowed"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="PreInstalledAppsEverEnabled"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

# AllowAnonymousCallback konfiguroeren
$Wert="AllowAnonymousCallback"
$DWord="0"
$Path="HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM"
Write-Output "'$Wert' wird deaktiviert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# APP Installer & Setup Settings konfigurieren
$Wert="ActiveSetupDisabled"
$DWord="1"
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
Write-Output "'$Wert' wird deaktiviert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="ActiveSetupTaskOverride"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="DisableAppInstallsOnFirstLogon"
$DWord="1"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="DisableResolveStoreCategories"
$DWord="1"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="DisableUpgradeCleanup"
$DWord="1"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="EarlyAppResolverStart"
$DWord="0"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# Nur aus Microsoft Quellen APPs installieren, wenn nicht ohnehin deaktiviert/deinstalliert
$Wert="AicEnabled"
$String="StoreOnly"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

#-----------------------------------------------------------------------------
# Standby/suspend deaktivieren
$Wert="HiberbootEnabled"
$DWord="0"
$Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
Write-Output "'$Wert' wird deaktiviert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# Windows Standardfreigaben deaktivieren
$Wert="AutoShareWks"
$DWord="0"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Write-Output "'$Wert' wird deaktiviert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# APP-Datenschutz Button deaktivieren (Einbau 2_fix-privacy-settings.ps1)
#$Wert="LetAppsAccessContacts"
#$DWord="2"
#$Path="HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy"
#Write-Output "Der 'APP-Datenschutz' wird konfiguriert"
#$Wert2 = @(
#	"LetAppsAccessContacts"
#	"LetAppsAccessCalendar"
#	"LetAppsAccessCallHistory"
#	"LetAppsAccessEmail"
#	"LetAppsAccessMessaging"
#	"LetAppsAccessPhone"
#	"LetAppsAccessRadios"
#	"LetAppsSyncWithDevices"
#)
#foreach ($Wert in $Werte) {
#    mkdirpath-force $Path
#    If (-Not (Test-Path $Path\$Wert)) {
#		New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
#	}
#	Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
#}

# Script Alex Hirsch <https://github.com/W4RH4WK/Debloat-Windows-10>
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Defuse Windows search settings"
Set-WindowsSearchSetting -EnableWebResultsSetting $false

Write-Output "Set general privacy options"
Set-ItemProperty "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1
force-mkdir "HKCU:\Printers\Defaults"
Set-ItemProperty "HKCU:\Printers\Defaults" "NetID" "{00000000-0000-0000-0000-000000000000}"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Input\TIPC"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Input\TIPC" "Enabled" 0
force-mkdir "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0

Write-Output "Disable synchronisation of settings"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" 0x3c
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "DeviceMetadataUploaded" 0
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "PriorLogons" 1
$groups = @(
    "Accessibility"
    "AppSync"
    "BrowserSettings"
    "Credentials"
    "DesktopTheme"
    "Language"
    "PackageState"
    "Personalization"
    "StartLayout"
    "Windows"
)
foreach ($group in $groups) {
    force-mkdir "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group"
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group" "Enabled" 0
}

Write-Output "Set privacy policy accepted state to 0"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0

Write-Output "Do not scan contact informations"
force-mkdir "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0

Write-Output "Inking and typing settings"
force-mkdir "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1

Write-Output "Microsoft Edge settings"
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" "DoNotTrack" 1
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" "ShowSearchSuggestionsGlobal" 0
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" "FPEnabled" 0
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
Set-ItemProperty "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" "EnabledV9" 0

Write-Output "Disable background access of default apps"
foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
}

Write-Output "Denying device access"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Type" "LooselyCoupled"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Value" "Deny"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "InitialAppValue" "Unspecified"
foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global")) {
    if ($key.PSChildName -EQ "LooselyCoupled") {
        continue
    }
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Type" "InterfaceClass"
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Value" "Deny"
    Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "InitialAppValue" "Unspecified"
}

Write-Output "Disable location sensor"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0
# Script Ende

#Write-Output "Disable submission of Windows Defender findings (w/ elevated privileges)"
#Takeown-Registry ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet")
#Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpyNetReporting" 0       # write-protected even after takeown ?!
#Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" 0

Write-Output "Do not share wifi networks"
$user = New-Object System.Security.Principal.NTAccount($env:UserName)
$sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).value
force-mkdir ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid)
Set-ItemProperty ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid) "FeatureStates" 0x33c
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseCredShared" 0
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseOpen" 0

#-----------------------------------------------------------------------------
# Hintergrund-Apps Button deaktivieren
$Wert="GlobalUserDisabled"
$DWord="1"
$Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
Write-Output "Hintergrund-Apps Button wird konfiguriert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

#-----------------------------------------------------------------------------
# AppBroadcast (Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App) Plugin deaktivieren
$Wert="DefaultPlugInEventId"
$ExpandString=""
$Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\AppBroadcast"
Write-Output "Der 'AppBroadcast' wird konfiguriert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type ExpandString -Value $ExpandString -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type ExpandString -Value $ExpandString -Force

#-----------------------------------------------------------------------------
# TCP/IP Parameter setzen
$Wert="SearchList"
$String=""
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
Write-Output "TCP/IP Parameter werden gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="UseDomainNameDevolution"
$DWord="1"
Write-Output "$Wert wird konfiguriert"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="EnableICMPRedirect"
Write-Output "$Wert wird konfiguriert"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="DeadGWDetectDefault"
Write-Output "$Wert wird konfiguriert"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

$Wert="DontAddDefaultGatewayDefault"
$DWord="0"
Write-Output "$Wert wird konfiguriert"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force


# Benachrichtigungen Button deaktivieren
# Datenschutzbestimmungen für die App existiert in Windows 10 Pro Version 1703 nicht in den GPOs
# und Policies darf in HKLM: nicht angelegt werden
$Wert="NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK"
$DWord="0"
$Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"
Write-Output "Button 'Benachrichtigungen auf dem Sperrbildschirm anzeigen' deaktivieren ($Wert)"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
$Wert="NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK"
Write-Output "Button 'eingehende VoIP-Anrufe auf dem Sperrbildschirm anzeigen' deaktivieren ($Wert)"
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

# Willkommenseite Button konfigurieren
# ContentDeliveryManagerwird weiter unten komplett abgeschaltet
$Wert="SubscribedContent-310093Enabled"
$DWord="0"
$Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
Write-Output "Willkommensseite ($Wert) wird konfiguriert"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

# Microsoft.SkyDrive Benachrichtungen Button abschalten
$Wert="Enabled"
$DWord="0"
$Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop"
Write-Output "Microsoft.SkyDrive Benachrichtungen Button abschalten"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

# Microsoft Diagnosedaten Button abschalten
$Wert="TailoredExperiencesWithDiagnosticDataEnabled"
$DWord="0"
$Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"
Write-Output "Microsoft Diagnosedaten Button abschalten ($Wert)"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

# C:\Windows\System32\IoTSettings.exe aus Smartscreen EmbeddedMode löschen
$Wert="DefaultAllowedExecutableFilesList"
$String=""
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EmbeddedMode\ProcessLauncher"
Write-Output "IoTSettings.exe aus Smartscreen EmbeddedMode löschen ($Wert)"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

# LLMNR deaktivieren
$Wert="EnableMulticast"
$DWord="0"
$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
Write-Output "LLMNR deaktivieren ($Wert)"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

# WSDPrintDevice (WS-Discovery) Port 3702 UDP deaktivieren (experimentell)
$Wert="Type"
$DWord="1"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\WSDPrintDevice"
Write-Output "WSDPrintDevice (WS-Discovery) Port 3702 UDP deaktivieren nicht machbar >> FIREWALL!!"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
#    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
#Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
$Wert="Start"
$DWord="4"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
#    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
#Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
$Wert="ErrorControl"
$DWord="1"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
#    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
$Wert="Tag"
$DWord="28"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
#Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
$Wert="ImagePath"
$String="hex(2):00,00"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
#    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
#Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

# WCN abschalten??? HKEY_LOCAL_MACHINE\SOFTWARE\Classes\FunctionDiscovery.WCNProvider

# Personalisation nicht gestatten (fehlende Berechtigung)
$Wert="AllowPersonalization"
$DWord="0"
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Personalization"
Write-Output "Personalisation kann nicht bearbeitet werden ($Wert)"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
#    New-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force
}
#Set-ItemProperty -Path $Path -Name $Wert -Type DWord -Value $DWord -Force

# OEM Information
$Wert="Logo"
$String="C:\\Windows\\System32\\admin.bmp"
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
Write-Output "OEM Information ($Wert) wird gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Manufacturer"
$String="Schenker XMG U706 | Marco Hinz | Fuck you Billyboy"
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
Write-Output "OEM Information ($Wert) wird gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SupportHours"
$String="!24x7"
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
Write-Output "OEM Information ($Wert) wird gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SupportPhone"
$String="+49 30 18 200-2117"
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
Write-Output "OEM Information ($Wert) wird gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SupportURL"
$String="http://matrixhacker.de/"
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
Write-Output "OEM Information ($Wert) wird gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Model"
$String="Windows 10 Pro Version 1703 (PrivacyPack)"
$Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
Write-Output "OEM Information ($Wert) wird gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force


# Firewall Regeln neu konfigurieren
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
#LocalSubnet, DNS, DHCP, WINS, DefaultGateway, Internet, Intranet, IntranetRemoteAccess, PlayToDevice.

Write-Output "FirewallRules werden entfernt und neu gesetzt"
Remove-Item $Path
mkdirpath-force $Path
New-NetFirewallRule -DisplayName "BlockWSD_3702udp_out" -Direction Outbound -Action Block -RemotePort 3702 -Protocol UDP
New-NetFirewallRule -DisplayName "BlockPNRP_3540udp_out" -Direction Outbound -Action Block -RemotePort 3540 -Protocol UDP
New-NetFirewallRule -DisplayName "Block_mDNS_5353udp_out" -Direction Outbound -Action Block -LocalPort 5353 -Protocol UDP
New-NetFirewallRule -DisplayName "Block_mDNS_5353udp_in" -Direction Inbound -Action Block -LocalPort 5353 -Protocol UDP
New-NetFirewallRule -DisplayName "BlockLLMNR_5355udp_out" -Direction Outbound -Action Block -RemotePort 5355 -Protocol UDP
New-NetFirewallRule -DisplayName "BlockWSD" -Direction Outbound -Action Block -RemotePort 3587 -Protocol UDP
New-NetFirewallRule -DisplayName "Block_2869udp" -Direction Outbound -Action Block -RemotePort 2869 -Protocol UDP
New-NetFirewallRule -DisplayName "BlockWSD_5358tcp_out" -Direction Outbound -Action Block -RemotePort 5358 -Protocol TCP

New-NetFirewallRule -DisplayName "BlockDHCPV6_547udp_out" -Direction Outbound -Action Block -LocalPort 546 -RemotePort 547 -Protocol UDP
New-NetFirewallRule -DisplayName "BlockDHCPV6_547udp_in" -Direction Inbound -Action Block -LocalPort 546 -RemotePort 547 -Protocol UDP
New-NetFirewallRule -DisplayName "Block_7250tcp_in" -Direction Inbound -Action Block -RemotePort 7250 -Protocol TCP
New-NetFirewallRule -DisplayName "BlockWFD-ASP_7235udp_out" -Direction Outbound -Action Block -LocalPort 7235 -RemotePort 7235 -Protocol UDP
New-NetFirewallRule -DisplayName "BlockWFD-ASP_7235udp_in" -Direction Inbound -Action Block -LocalPort 7235 -RemotePort 7235 -Protocol UDP
New-NetFirewallRule -DisplayName "BlockAllJoyn-Router_9955tcp_in" -Direction Inbound -Action Block -RemotePort 9955 -Protocol TCP
New-NetFirewallRule -DisplayName "BlockÜbermittlungsoptimierung_7680tcp_in" -Direction Inbound -Action Block -LocalPort 7680 -Protocol TCP
New-NetFirewallRule -DisplayName "BlockÜbermittlungsoptimierung_7680udp_in" -Direction Inbound -Action Block -LocalPort 7680 -Protocol UDP
New-NetFirewallRule -DisplayName "BlockDIAL-Protokollserver_10247tcp_in" -Direction Inbound -Action Block -LocalPort 10247 -Protocol TCP
New-NetFirewallRule -DisplayName "BlockNetBIOS-RPC_tcp_in" -Direction Inbound -Action Block -LocalPort 135, 137, 138, 139 -Protocol TCP

New-NetFirewallRule -DisplayName "BlockRTSP-RTP-Streaming_2355xtcp_in" -Direction Inbound -Action Block -LocalPort 23554, 23555, 23556 -Protocol TCP
New-NetFirewallRule -DisplayName "BlockHTTP-Streaming_10246tcp_in" -Direction Inbound -Action Block -LocalPort 10246 -Protocol TCP

New-NetFirewallRule -DisplayName "BLOCK-ALL-IN-enable-disable-here" -Direction Inbound -Action Block -Enabled False -Description "Das ist quasi eine ALLDrop Regel, die aber bei MS alles blockiert (auch die aktive AllowRules), was so dumm ist, wie nur irgendwas. Zum Abschotten diese Regel einfach aktivieren (dann jedoch wird alles von aussen geblockt!!!)"
#New-NetFirewallRule -DisplayName "BlockALL_TCP_in" -Direction Inbound -Action Block -Protocol TCP

#Inbound
#New-NetFirewallRule -DisplayName "AllowSMB_192.168.228.44_in" -Direction Inbound -Action Allow -Protocol 6 -LocalPort 445 -RemotePort 49600-49700 -LocalAddress $LANIP  -RemoteAddress 192.168.228.44 -Encryption Required -Authentication Required -LocalUser "O:LSD:(A;;CC;;;$SID)" -Owner $SID
New-NetFirewallRule -DisplayName "AllowSMB_TRUSTIPs_in" -Direction Inbound -Action Allow -Protocol 6 -LocalPort 445 -RemotePort 49600-49700 -LocalAddress $LANIP -RemoteAddress ([string[]]$trustips) -Description "Verschlüsselung nicht möglich!!! Siehe Script."
#New-NetFirewallRule -DisplayName "AllowSMB_192.168.228.60_in" -Direction Inbound -Action Allow -Protocol 6 -LocalPort 445 -RemotePort 50000-65535 -LocalAddress $LANIP -RemoteAddress 192.168.228.60 -Description "Linux/UNIX Zugriffe"
New-NetFirewallRule -DisplayName "BlockSMB_inet_in" -Direction Inbound -Action Block -Protocol 6 -LocalPort 445 -LocalAddress $LANIP -RemoteAddress Internet, DefaultGateway, DNS, ([string[]]$untrustips) -Description "SMB Defense"
#New-NetFirewallRule -DisplayName "BlockSSDP/UPnP_in" -Direction Inbound -Action Block -Protocol 6 -LocalPort 5357 -LocalAddress $LANIP -Description "Microsoft HTTPAPI (webserver) httpd 2.0 (SSDP/UPnP) eingehend blockieren!"

# Outbound
New-NetFirewallRule -DisplayName "AllowSMB_out" -Direction Outbound -Action Allow -Protocol 6 -LocalAddress $LANIP -RemotePort 445
New-NetFirewallRule -DisplayName "AllowDNS_tcp_out" -Direction Outbound -Action Allow -RemotePort 53 -LocalAddress $LANIP -RemoteAddress DNS -Protocol TCP
New-NetFirewallRule -DisplayName "AllowDNS_udp_out" -Direction Outbound -Action Allow -RemotePort 53 -LocalAddress $LANIP -RemoteAddress DNS -Protocol UDP
New-NetFirewallRule -DisplayName "AllowDHCP_udp_out" -Direction Outbound -Action Allow -LocalPort 68 -RemotePort 67 -LocalAddress $LANIP -RemoteAddress DHCP -Protocol UDP
New-NetFirewallRule -DisplayName "AllowNTP_udp_out" -Direction Outbound -Action Allow -RemotePort 123 -LocalAddress $LANIP -Protocol UDP
New-NetFirewallRule -DisplayName "AllowLAN_udp_out" -Direction Outbound -Action Allow -RemotePort 1-52, 54-66, 69-122, 124-65535 -RemoteAddress LocalSubnet -Protocol UDP
New-NetFirewallRule -DisplayName "BlockLAN_udp_out" -Direction Outbound -Action Block -Enabled False -RemotePort 1-52, 54-66, 69-122, 124-65535 -Protocol UDP -Description "Wenn diese Regel aktiviert wird, wird UDP bis auf die Ausnahmen vollständig deaktiviert (auch die Regel AllowLAN_udp_out wird damit 'überschrieben')."
New-NetFirewallRule -DisplayName "BlockSSDP/UPnP_out" -Direction Outbound -Action Block -Protocol 6 -LocalPort 5357 -Description "Microsoft HTTPAPI (webserver) httpd 2.0 (SSDP/UPnP) ausgehend blockieren!"


New-NetFirewallRule -DisplayName "BlockIPv6_out" -Direction Outbound -Action Block -Protocol 41
New-NetFirewallRule -DisplayName "BlockIPv6_Frag_out" -Direction Outbound -Action Block -Protocol 44
New-NetFirewallRule -DisplayName "BlockICMPv6_out" -Direction Outbound -Action Block -Protocol 58
New-NetFirewallRule -DisplayName "BlockIGMP_out" -Direction Outbound -Action Block -Protocol 2
New-NetFirewallRule -DisplayName "BlockIPv6_NoNxt_out" -Direction Outbound -Action Block -Protocol 59
New-NetFirewallRule -DisplayName "BlockGRE_out" -Direction Outbound -Action Block -Protocol 47
New-NetFirewallRule -DisplayName "BlockIPv6_Opts_out" -Direction Outbound -Action Block -Protocol 60
New-NetFirewallRule -DisplayName "BlockIPv6_Route" -Direction Outbound -Action Block -Protocol 43

# Windows FirewallRules Standard wieder einpflegen (SharedAccess)
$Wert="vm-monitoring-dcom"
$String="v2.0|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=RpcSs|Name=@icsvc.dll,-709|Desc=@icsvc.dll,-710|EmbedCtxt=@icsvc.dll,-700|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="vm-monitoring-icmpv4"
$String="v2.0|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Name=@icsvc.dll,-701|Desc=@icsvc.dll,-702|EmbedCtxt=@icsvc.dll,-700|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="vm-monitoring-icmpv6"
$String="v2.0|Action=Allow|Active=FALSE|Dir=In|Protocol=58|Name=@icsvc.dll,-703|Desc=@icsvc.dll,-704|EmbedCtxt=@icsvc.dll,-700|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="vm-monitoring-nb-session"
$String="v2.0|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=139|Name=@icsvc.dll,-705|Desc=@icsvc.dll,-706|EmbedCtxt=@icsvc.dll,-700|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="vm-monitoring-rpc"
$String="v2.0|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=Schedule|Name=@icsvc.dll,-707|Desc=@icsvc.dll,-708|EmbedCtxt=@icsvc.dll,-700|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SNMPTRAP-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=162|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\snmptrap.exe|Svc=SNMPTRAP|Name=@snmptrap.exe,-7|Desc=@snmptrap.exe,-8|EmbedCtxt=@snmptrap.exe,-3|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SNMPTRAP-In-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=162|App=%SystemRoot%\\system32\\snmptrap.exe|Svc=SNMPTRAP|Name=@snmptrap.exe,-7|Desc=@snmptrap.exe,-8|EmbedCtxt=@snmptrap.exe,-3|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Wininit-Shutdown-In-Rule-TCP-RPC"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%systemroot%\\system32\\wininit.exe|Name=@firewallapi.dll,-36753|Desc=@firewallapi.dll,-36754|EmbedCtxt=@firewallapi.dll,-36751|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Wininit-Shutdown-In-Rule-TCP-RPC-EPMapper"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC-EPMap|App=%systemroot%\\system32\\wininit.exe|Name=@firewallapi.dll,-36755|Desc=@firewallapi.dll,-36756|EmbedCtxt=@firewallapi.dll,-36751|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WiFiDirect-KM-Driver-In-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|App=System|Name=@wlansvc.dll,-37378|Desc=@wlansvc.dll,-37890|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WiFiDirect-KM-Driver-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|App=System|Name=@wlansvc.dll,-37379|Desc=@wlansvc.dll,-37891|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WiFiDirect-KM-Driver-In-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|App=System|Name=@wlansvc.dll,-37380|Desc=@wlansvc.dll,-37892|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WiFiDirect-KM-Driver-Out-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|App=System|Name=@wlansvc.dll,-37381|Desc=@wlansvc.dll,-37893|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-Unified-Telemetry-Client"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Svc=DiagTrack|Name=@%windir%\\system32\\diagtrack.dll,-3001|Desc=@%windir%\\system32\\diagtrack.dll,-3003|EmbedCtxt=DiagTrack|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PNRPMNRS-PNRP-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-34003|Desc=@FirewallAPI.dll,-34004|EmbedCtxt=@FirewallAPI.dll,-34002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PNRPMNRS-PNRP-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-34005|Desc=@FirewallAPI.dll,-34006|EmbedCtxt=@FirewallAPI.dll,-34002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PNRPMNRS-SSDPSrv-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-34007|Desc=@FirewallAPI.dll,-34008|EmbedCtxt=@FirewallAPI.dll,-34002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PNRPMNRS-SSDPSrv-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-34009|Desc=@FirewallAPI.dll,-34010|EmbedCtxt=@FirewallAPI.dll,-34002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="DeliveryOptimization-TCP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|LPort=7680|App=%SystemRoot%\\system32\\svchost.exe|Svc=dosvc|Name=@%systemroot%\\system32\\dosvc.dll,-102|Desc=@%systemroot%\\system32\\dosvc.dll,-104|EmbedCtxt=@%systemroot%\\system32\\dosvc.dll,-100|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="DeliveryOptimization-UDP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|LPort=7680|App=%SystemRoot%\\system32\\svchost.exe|Svc=dosvc|Name=@%systemroot%\\system32\\dosvc.dll,-103|Desc=@%systemroot%\\system32\\dosvc.dll,-104|EmbedCtxt=@%systemroot%\\system32\\dosvc.dll,-100|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="EventForwarder-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\system32\\NetEvtFwdr.exe|Name=@FirewallAPI.dll,-36802|Desc=@FirewallAPI.dll,-36803|EmbedCtxt=@FirewallAPI.dll,-36801|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="EventForwarder-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-36804|Desc=@FirewallAPI.dll,-36805|EmbedCtxt=@FirewallAPI.dll,-36801|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MsiScsi-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29003|Desc=@FirewallAPI.dll,-29006|EmbedCtxt=@FirewallAPI.dll,-29002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MsiScsi-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29007|Desc=@FirewallAPI.dll,-29010|EmbedCtxt=@FirewallAPI.dll,-29002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MsiScsi-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29003|Desc=@FirewallAPI.dll,-29006|EmbedCtxt=@FirewallAPI.dll,-29002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MsiScsi-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29007|Desc=@FirewallAPI.dll,-29010|EmbedCtxt=@FirewallAPI.dll,-29002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteFwAdmin-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=policyagent|Name=@FirewallAPI.dll,-30003|Desc=@FirewallAPI.dll,-30006|EmbedCtxt=@FirewallAPI.dll,-30002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteFwAdmin-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-30007|Desc=@FirewallAPI.dll,-30010|EmbedCtxt=@FirewallAPI.dll,-30002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteFwAdmin-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=policyagent|Name=@FirewallAPI.dll,-30003|Desc=@FirewallAPI.dll,-30006|EmbedCtxt=@FirewallAPI.dll,-30002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteFwAdmin-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-30007|Desc=@FirewallAPI.dll,-30010|EmbedCtxt=@FirewallAPI.dll,-30002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="AllJoyn-Router-In-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=9955|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37003|Desc=@FirewallAPI.dll,-37004|EmbedCtxt=@FirewallAPI.dll,-37002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="AllJoyn-Router-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37005|Desc=@FirewallAPI.dll,-37006|EmbedCtxt=@FirewallAPI.dll,-37002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="AllJoyn-Router-In-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37007|Desc=@FirewallAPI.dll,-37008|EmbedCtxt=@FirewallAPI.dll,-37002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="AllJoyn-Router-Out-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37009|Desc=@FirewallAPI.dll,-37010|EmbedCtxt=@FirewallAPI.dll,-37002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Netlogon-NamedPipe-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=445|App=System|Name=@netlogon.dll,-1003|Desc=@netlogon.dll,-1006|EmbedCtxt=@netlogon.dll,-1010|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Netlogon-TCP-RPC-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\System32\\lsass.exe|Name=@netlogon.dll,-1008|Desc=@netlogon.dll,-1009|EmbedCtxt=@netlogon.dll,-1010|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="ProximityUxHost-Sharing-In-TCP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\proximityuxhost.exe|Name=@FirewallAPI.dll,-36252|Desc=@FirewallAPI.dll,-36253|EmbedCtxt=@FirewallAPI.dll,-36251|TTK=ProxSharing|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="ProximityUxHost-Sharing-Out-TCP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\system32\\proximityuxhost.exe|Name=@FirewallAPI.dll,-36254|Desc=@FirewallAPI.dll,-36255|EmbedCtxt=@FirewallAPI.dll,-36251|TTK=ProxSharing|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=2869|App=System|Name=@FirewallAPI.dll,-32761|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=2869|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-In-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=137|App=System|Name=@FirewallAPI.dll,-32769|Desc=@FirewallAPI.dll,-32772|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-Out-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=137|App=System|Name=@FirewallAPI.dll,-32773|Desc=@FirewallAPI.dll,-32776|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-In-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=138|App=System|Name=@FirewallAPI.dll,-32777|Desc=@FirewallAPI.dll,-32780|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-Out-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=138|App=System|Name=@FirewallAPI.dll,-32781|Desc=@FirewallAPI.dll,-32784|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=5358|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=5358|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32815|Desc=@FirewallAPI.dll,-32816|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=5357|App=System|Name=@FirewallAPI.dll,-32817|Desc=@FirewallAPI.dll,-32818|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=5357|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32819|Desc=@FirewallAPI.dll,-32820|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-SSDPSrv-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32753|Desc=@FirewallAPI.dll,-32756|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-SSDPSrv-Out-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32757|Desc=@FirewallAPI.dll,-32760|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-In-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32761|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnP-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-32821|Desc=@FirewallAPI.dll,-32822|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32769|Desc=@FirewallAPI.dll,-32772|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-Out-UDP-Active"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32773|Desc=@FirewallAPI.dll,-32776|EmbedCtxt=@FirewallAPI.dll,-32752|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32777|Desc=@FirewallAPI.dll,-32780|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-Out-UDP-Active"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32781|Desc=@FirewallAPI.dll,-32784|EmbedCtxt=@FirewallAPI.dll,-32752|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDPHOST-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32785|Desc=@FirewallAPI.dll,-32788|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-DAS-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-32825|Desc=@FirewallAPI.dll,-32826|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PNRPMNRS-PNRP-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-34003|Desc=@FirewallAPI.dll,-34004|EmbedCtxt=@FirewallAPI.dll,-34002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDPHOST-Out-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32789|Desc=@FirewallAPI.dll,-32792|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-LLMNR-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32801|Desc=@FirewallAPI.dll,-32804|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-LLMNR-Out-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32805|Desc=@FirewallAPI.dll,-32808|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDRESPUB-WSD-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32809|Desc=@FirewallAPI.dll,-32810|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDRESPUB-WSD-Out-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32811|Desc=@FirewallAPI.dll,-32812|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-In-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|RPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32815|Desc=@FirewallAPI.dll,-32816|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-In-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32817|Desc=@FirewallAPI.dll,-32818|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|RPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32819|Desc=@FirewallAPI.dll,-32820|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-SSDPSrv-In-UDP-Teredo"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32754|Desc=@FirewallAPI.dll,-32756|EmbedCtxt=@FirewallAPI.dll,-32752|TTK2_27=UPnP|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-SSDPSrv-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32757|Desc=@FirewallAPI.dll,-32760|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnP-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|Profile=Public|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-32821|Desc=@FirewallAPI.dll,-32822|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32761|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-In-TCP-Teredo"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Public|App=System|Name=@FirewallAPI.dll,-32762|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|TTK2_27=UPnP|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32769|Desc=@FirewallAPI.dll,-32772|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32773|Desc=@FirewallAPI.dll,-32776|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32777|Desc=@FirewallAPI.dll,-32780|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32781|Desc=@FirewallAPI.dll,-32784|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDPHOST-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32785|Desc=@FirewallAPI.dll,-32788|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-DAS-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-32825|Desc=@FirewallAPI.dll,-32826|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDPHOST-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32789|Desc=@FirewallAPI.dll,-32792|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-LLMNR-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32801|Desc=@FirewallAPI.dll,-32804|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-LLMNR-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32805|Desc=@FirewallAPI.dll,-32808|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDRESPUB-WSD-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32809|Desc=@FirewallAPI.dll,-32810|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDRESPUB-WSD-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32811|Desc=@FirewallAPI.dll,-32812|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32815|Desc=@FirewallAPI.dll,-32816|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32817|Desc=@FirewallAPI.dll,-32818|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32819|Desc=@FirewallAPI.dll,-32820|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WirelessDisplay-In-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|App=%systemroot%\\system32\\WUDFHost.exe|Name=@wifidisplay.dll,-10200|Desc=@wifidisplay.dll,-10201|LUAuth=O:LSD:(A;;CC;;;UD)|EmbedCtxt=@wifidisplay.dll,-100|TTK2_22=WFDDisplay|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WirelessDisplay-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%systemroot%\\system32\\WUDFHost.exe|Name=@wifidisplay.dll,-10202|Desc=@wifidisplay.dll,-10203|LUAuth=O:LSD:(A;;CC;;;S-1-5-84-0-0-0-0-0)|EmbedCtxt=@wifidisplay.dll,-100|TTK2_22=WFDDisplay|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WirelessDisplay-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|App=%systemroot%\\system32\\WUDFHost.exe|Name=@wifidisplay.dll,-10204|Desc=@wifidisplay.dll,-10205|LUAuth=O:LSD:(A;;CC;;;S-1-5-84-0-0-0-0-0)|EmbedCtxt=@wifidisplay.dll,-100|TTK2_22=WFDDisplay|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WirelessDisplay-Infra-In-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|LPort=7250|App=%systemroot%\\system32\\CastSrv.exe|Name=@wifidisplay.dll,-10206|Desc=@wifidisplay.dll,-10207|EmbedCtxt=@wifidisplay.dll,-100|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34252|Desc=@FirewallAPI.dll,-34253|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-WINMGMT-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34254|Desc=@FirewallAPI.dll,-34255|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-WINMGMT-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34258|Desc=@FirewallAPI.dll,-34259|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-ASYNC-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%systemroot%\\system32\\wbem\\unsecapp.exe|Name=@FirewallAPI.dll,-34256|Desc=@FirewallAPI.dll,-34257|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=135|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34252|Desc=@FirewallAPI.dll,-34253|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-WINMGMT-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34254|Desc=@FirewallAPI.dll,-34255|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-WINMGMT-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34258|Desc=@FirewallAPI.dll,-34259|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-ASYNC-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\wbem\\unsecapp.exe|Name=@FirewallAPI.dll,-34256|Desc=@FirewallAPI.dll,-34257|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Session-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=139|App=System|Name=@FirewallAPI.dll,-28503|Desc=@FirewallAPI.dll,-28506|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Session-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=139|App=System|Name=@FirewallAPI.dll,-28507|Desc=@FirewallAPI.dll,-28510|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SMB-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-28511|Desc=@FirewallAPI.dll,-28514|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SMB-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=445|App=System|Name=@FirewallAPI.dll,-28515|Desc=@FirewallAPI.dll,-28518|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Name-In-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=137|App=System|Name=@FirewallAPI.dll,-28519|Desc=@FirewallAPI.dll,-28522|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Name-Out-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=137|App=System|Name=@FirewallAPI.dll,-28523|Desc=@FirewallAPI.dll,-28526|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Datagram-In-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=138|App=System|Name=@FirewallAPI.dll,-28527|Desc=@FirewallAPI.dll,-28530|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Datagram-Out-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=138|App=System|Name=@FirewallAPI.dll,-28531|Desc=@FirewallAPI.dll,-28534|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SpoolSvc-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-28535|Desc=@FirewallAPI.dll,-28538|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|Svc=Rpcss|Name=@FirewallAPI.dll,-28539|Desc=@FirewallAPI.dll,-28542|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP4-ERQ-In-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Domain|ICMP4=8:*|Name=@FirewallAPI.dll,-28543|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP4-ERQ-Out-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=1|Profile=Domain|ICMP4=8:*|Name=@FirewallAPI.dll,-28544|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP6-ERQ-In-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=58|Profile=Domain|ICMP6=128:*|Name=@FirewallAPI.dll,-28545|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP6-ERQ-Out-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=58|Profile=Domain|ICMP6=128:*|Name=@FirewallAPI.dll,-28546|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Session-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=139|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28503|Desc=@FirewallAPI.dll,-28506|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Session-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=139|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28507|Desc=@FirewallAPI.dll,-28510|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SMB-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28511|Desc=@FirewallAPI.dll,-28514|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SMB-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28515|Desc=@FirewallAPI.dll,-28518|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Name-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28519|Desc=@FirewallAPI.dll,-28522|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Name-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28523|Desc=@FirewallAPI.dll,-28526|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Datagram-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28527|Desc=@FirewallAPI.dll,-28530|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Datagram-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28531|Desc=@FirewallAPI.dll,-28534|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WiFiDirect-KM-Driver-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|App=System|Name=@wlansvc.dll,-37379|Desc=@wlansvc.dll,-37891|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SpoolSvc-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-28535|Desc=@FirewallAPI.dll,-28538|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|Svc=Rpcss|Name=@FirewallAPI.dll,-28539|Desc=@FirewallAPI.dll,-28542|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP4-ERQ-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Public|ICMP4=8:*|RA4=LocalSubnet|Name=@FirewallAPI.dll,-28543|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP4-ERQ-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=1|Profile=Public|ICMP4=8:*|RA4=LocalSubnet|Name=@FirewallAPI.dll,-28544|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP6-ERQ-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=58|Profile=Public|ICMP6=128:*|RA6=LocalSubnet|Name=@FirewallAPI.dll,-28545|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP6-ERQ-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=58|Profile=Public|ICMP6=128:*|RA6=LocalSubnet|Name=@FirewallAPI.dll,-28546|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-LLMNR-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-28548|Desc=@FirewallAPI.dll,-28549|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-LLMNR-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-28550|Desc=@FirewallAPI.dll,-28551|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SSTP-IN-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=443|App=System|Name=@sstpsvc.dll,-35002|Desc=@sstpsvc.dll,-35003|EmbedCtxt=@sstpsvc.dll,-35001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-36502|Desc=@FirewallAPI.dll,-36503|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-Server-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36504|Desc=@FirewallAPI.dll,-36505|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-Server-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36506|Desc=@FirewallAPI.dll,-36507|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=135|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-36502|Desc=@FirewallAPI.dll,-36503|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-Server-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36504|Desc=@FirewallAPI.dll,-36505|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-Server-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36506|Desc=@FirewallAPI.dll,-36507|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-HomeGroup-ProvSvc-TCP3587-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=3587|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=p2psvc|Name=@%systemroot%\\system32\\provsvc.dll,-200|Desc=@%systemroot%\\system32\\provsvc.dll,-201|EmbedCtxt=@%systemroot%\\system32\\provsvc.dll,-202|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-HomeGroup-ProvSvc-TCP3587-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|RPort=3587|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=p2psvc|Name=@%systemroot%\\system32\\provsvc.dll,-203|Desc=@%systemroot%\\system32\\provsvc.dll,-204|EmbedCtxt=@%systemroot%\\system32\\provsvc.dll,-202|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-HomeGroup-ProvSvc-UDP3540-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=3540|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@%systemroot%\\system32\\provsvc.dll,-205|Desc=@%systemroot%\\system32\\provsvc.dll,-206|EmbedCtxt=@%systemroot%\\system32\\provsvc.dll,-202|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-HomeGroup-ProvSvc-UDP3540-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=3540|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@%systemroot%\\system32\\provsvc.dll,-207|Desc=@%systemroot%\\system32\\provsvc.dll,-208|EmbedCtxt=@%systemroot%\\system32\\provsvc.dll,-202|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-In-TCP-EdgeScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33003|Desc=@FirewallAPI.dll,-33006|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33007|Desc=@FirewallAPI.dll,-33010|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-PnrpSvc-UDP-In-EdgeScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=3540|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33039|Desc=@FirewallAPI.dll,-33040|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-PnrpSvc-UDP-OUT"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33037|Desc=@FirewallAPI.dll,-33038|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-RAServer-In-TCP-NoScope-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\raserver.exe|Name=@FirewallAPI.dll,-33011|Desc=@FirewallAPI.dll,-33014|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-RAServer-Out-TCP-NoScope-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\raserver.exe|Name=@FirewallAPI.dll,-33015|Desc=@FirewallAPI.dll,-33018|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-DCOM-In-TCP-NoScope-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-33035|Desc=@FirewallAPI.dll,-33036|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-In-TCP-EdgeScope-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33003|Desc=@FirewallAPI.dll,-33006|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33007|Desc=@FirewallAPI.dll,-33010|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-SSDPSrv-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-33019|Desc=@FirewallAPI.dll,-33022|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-SSDPSrv-Out-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Private|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-33023|Desc=@FirewallAPI.dll,-33026|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-Out-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=137|App=System|Name=@FirewallAPI.dll,-32773|Desc=@FirewallAPI.dll,-32776|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-SSDPSrv-In-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-33027|Desc=@FirewallAPI.dll,-33030|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-SSDPSrv-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-33031|Desc=@FirewallAPI.dll,-33034|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-PnrpSvc-UDP-In-EdgeScope-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|LPort=3540|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33039|Desc=@FirewallAPI.dll,-33040|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-PnrpSvc-UDP-OUT-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Private|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33037|Desc=@FirewallAPI.dll,-33038|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33503|Desc=@FirewallAPI.dll,-33506|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33507|Desc=@FirewallAPI.dll,-33510|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-KTMRM-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=ktmrm|Name=@FirewallAPI.dll,-33511|Desc=@FirewallAPI.dll,-33512|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33513|Desc=@FirewallAPI.dll,-33514|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33503|Desc=@FirewallAPI.dll,-33506|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33507|Desc=@FirewallAPI.dll,-33510|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-KTMRM-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=ktmrm|Name=@FirewallAPI.dll,-33511|Desc=@FirewallAPI.dll,-33512|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33513|Desc=@FirewallAPI.dll,-33514|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-P2PHost-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32003|Desc=@FirewallAPI.dll,-32006|EmbedCtxt=@FirewallAPI.dll,-32002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-P2PHost-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32007|Desc=@FirewallAPI.dll,-32010|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-P2PHost-WSD-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32011|Desc=@FirewallAPI.dll,-32014|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-P2PHost-WSD-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32015|Desc=@FirewallAPI.dll,-32018|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-PNRP-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-32019|Desc=@FirewallAPI.dll,-32022|EmbedCtxt=@FirewallAPI.dll,-32002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-PNRP-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-32023|Desc=@FirewallAPI.dll,-32026|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-PNRP-SSDPSrv-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32027|Desc=@FirewallAPI.dll,-32030|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-PNRP-SSDPSrv-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32031|Desc=@FirewallAPI.dll,-32034|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="DIAL-Protocol-Server-In-TCP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=10247|App=System|Name=@FirewallAPI.dll,-37102|Desc=@FirewallAPI.dll,-37103|EmbedCtxt=@FirewallAPI.dll,-37101|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="DIAL-Protocol-Server-HTTPSTR-In-TCP-LocalSubnetScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=10247|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-37102|Desc=@FirewallAPI.dll,-37103|EmbedCtxt=@FirewallAPI.dll,-37101|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=Eventlog|Name=@FirewallAPI.dll,-29253|Desc=@FirewallAPI.dll,-29256|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-NP-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-29257|Desc=@FirewallAPI.dll,-29260|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29265|Desc=@FirewallAPI.dll,-29268|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Eventlog|Name=@FirewallAPI.dll,-29253|Desc=@FirewallAPI.dll,-29256|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-NP-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-29257|Desc=@FirewallAPI.dll,-29260|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29265|Desc=@FirewallAPI.dll,-29268|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-HTTPSTR-In-TCP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=10246|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-HTTPSTR-In-TCP-LocalSubnetScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=10246|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-HTTPSTR-In-TCP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=10246|RA42=Ply2Renders|RA62=Ply2Renders|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-UDP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-UDP-LocalSubnetScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-UDP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Public|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-Out-UDP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36006|Desc=@FirewallAPI.dll,-36007|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-Out-UDP-LocalSubnetScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36006|Desc=@FirewallAPI.dll,-36007|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-Out-UDP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36006|Desc=@FirewallAPI.dll,-36007|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-RTSP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=23554|LPort=23555|LPort=23556|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36008|Desc=@FirewallAPI.dll,-36009|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-RTSP-LocalSubnetScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=23554|LPort=23555|LPort=23556|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36008|Desc=@FirewallAPI.dll,-36009|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-RTSP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=23554|LPort=23555|LPort=23556|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36008|Desc=@FirewallAPI.dll,-36009|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-SSDP-Discovery-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort2_20=Ply2Disc|App=%SystemRoot%\\system32\\svchost.exe|Svc=ssdpsrv|Name=@FirewallAPI.dll,-36104|Desc=@FirewallAPI.dll,-36105|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-UPnP-Events-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=2869|RA42=Ply2Renders|RA62=Ply2Renders|App=System|Name=@FirewallAPI.dll,-36106|Desc=@FirewallAPI.dll,-36107|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-QWave-In-UDP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36010|Desc=@FirewallAPI.dll,-36011|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-QWave-Out-UDP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|Profile=Public|RPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36012|Desc=@FirewallAPI.dll,-36013|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-QWave-In-TCP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36014|Desc=@FirewallAPI.dll,-36015|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-QWave-Out-TCP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36016|Desc=@FirewallAPI.dll,-36017|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-DAFWSD-In-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Profile=Public|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-36852|Desc=@FirewallAPI.dll,-36853|LUAuth=O:LSD:(A;;CC;;;S-1-5-92-3339056971-1291069075-3798698925-2882100687-0)|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-DAFWSD-Out-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Profile=Public|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-36854|Desc=@FirewallAPI.dll,-36855|LUAuth=O:LSD:(A;;CC;;;S-1-5-92-3339056971-1291069075-3798698925-2882100687-0)|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-SPOOL-In-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Profile=Public|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-36856|Desc=@FirewallAPI.dll,-36857|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-SPOOL-Out-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Profile=Public|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-36858|Desc=@FirewallAPI.dll,-36859|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-SCAN-In-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=stisvc|Name=@FirewallAPI.dll,-36860|Desc=@FirewallAPI.dll,-36861|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-SCAN-Out-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=stisvc|Name=@FirewallAPI.dll,-36862|Desc=@FirewallAPI.dll,-36863|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-GRE-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=47|App=System|Name=@FirewallAPI.dll,-33769|Desc=@FirewallAPI.dll,-33772|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-GRE-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=47|App=System|Name=@FirewallAPI.dll,-33773|Desc=@FirewallAPI.dll,-33776|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-L2TP-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1701|App=System|Name=@FirewallAPI.dll,-33753|Desc=@FirewallAPI.dll,-33756|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-L2TP-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1701|App=System|Name=@FirewallAPI.dll,-33757|Desc=@FirewallAPI.dll,-33760|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-PPTP-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=1723|App=System|Name=@FirewallAPI.dll,-33765|Desc=@FirewallAPI.dll,-33768|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-PPTP-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=1723|App=System|Name=@FirewallAPI.dll,-33761|Desc=@FirewallAPI.dll,-33764|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-WLANSvc-ASP-CP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|LPort=7235|RPort=7235|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=WlanSvc|Name=@wlansvc.dll,-37376|Desc=@wlansvc.dll,-37888|EmbedCtxt=@wlansvc.dll,-36864|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-WLANSvc-ASP-CP-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|LPort=7235|RPort=7235|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=WlanSvc|Name=@wlansvc.dll,-37377|Desc=@wlansvc.dll,-37889|EmbedCtxt=@wlansvc.dll,-36864|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\services.exe|Name=@FirewallAPI.dll,-29503|Desc=@FirewallAPI.dll,-29506|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-NP-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-29507|Desc=@FirewallAPI.dll,-29510|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29515|Desc=@FirewallAPI.dll,-29518|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\services.exe|Name=@FirewallAPI.dll,-29503|Desc=@FirewallAPI.dll,-29506|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-NP-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-29507|Desc=@FirewallAPI.dll,-29510|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29515|Desc=@FirewallAPI.dll,-29518|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PerfLogsAlerts-PLASrv-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\plasrv.exe|Name=@FirewallAPI.dll,-34753|Desc=@FirewallAPI.dll,-34754|EmbedCtxt=@FirewallAPI.dll,-34752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PerfLogsAlerts-DCOM-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=135|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34755|Desc=@FirewallAPI.dll,-34756|EmbedCtxt=@FirewallAPI.dll,-34752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PerfLogsAlerts-PLASrv-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%systemroot%\\system32\\plasrv.exe|Name=@FirewallAPI.dll,-34753|Desc=@FirewallAPI.dll,-34754|EmbedCtxt=@FirewallAPI.dll,-34752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PerfLogsAlerts-DCOM-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%systemroot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34755|Desc=@FirewallAPI.dll,-34756|EmbedCtxt=@FirewallAPI.dll,-34752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-DU-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=1:*|App=System|Name=@FirewallAPI.dll,-25110|Desc=@FirewallAPI.dll,-25112|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-PTB-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=2:*|Name=@FirewallAPI.dll,-25001|Desc=@FirewallAPI.dll,-25007|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-PTB-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=2:*|Name=@FirewallAPI.dll,-25002|Desc=@FirewallAPI.dll,-25007|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-TE-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=3:*|App=System|Name=@FirewallAPI.dll,-25113|Desc=@FirewallAPI.dll,-25115|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-TE-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=3:*|Name=@FirewallAPI.dll,-25114|Desc=@FirewallAPI.dll,-25115|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-PP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=4:*|App=System|Name=@FirewallAPI.dll,-25116|Desc=@FirewallAPI.dll,-25118|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-PP-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=4:*|Name=@FirewallAPI.dll,-25117|Desc=@FirewallAPI.dll,-25118|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-NDS-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=135:*|App=System|Name=@FirewallAPI.dll,-25019|Desc=@FirewallAPI.dll,-25025|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-NDS-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=135:*|Name=@FirewallAPI.dll,-25020|Desc=@FirewallAPI.dll,-25025|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-NDA-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=136:*|App=System|Name=@FirewallAPI.dll,-25026|Desc=@FirewallAPI.dll,-25032|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-NDA-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=136:*|Name=@FirewallAPI.dll,-25027|Desc=@FirewallAPI.dll,-25032|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-RA-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=134:*|RA6=fe80::/64|App=System|Name=@FirewallAPI.dll,-25012|Desc=@FirewallAPI.dll,-25018|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-RA-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=134:*|LA6=fe80::/64|RA4=LocalSubnet|RA6=LocalSubnet|RA6=ff02::1|RA6=fe80::/64|Name=@FirewallAPI.dll,-25013|Desc=@FirewallAPI.dll,-25018|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-RS-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=133:*|App=System|Name=@FirewallAPI.dll,-25009|Desc=@FirewallAPI.dll,-25011|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-RS-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=133:*|RA4=LocalSubnet|RA6=LocalSubnet|RA6=ff02::2|RA6=fe80::/64|Name=@FirewallAPI.dll,-25008|Desc=@FirewallAPI.dll,-25011|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LQ-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=130:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25061|Desc=@FirewallAPI.dll,-25067|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LQ-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=130:*|RA4=LocalSubnet|RA6=LocalSubnet|Name=@FirewallAPI.dll,-25062|Desc=@FirewallAPI.dll,-25067|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LR-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=131:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25068|Desc=@FirewallAPI.dll,-25074|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LR-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=131:*|RA4=LocalSubnet|RA6=LocalSubnet|Name=@FirewallAPI.dll,-25069|Desc=@FirewallAPI.dll,-25074|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LR2-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=143:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25075|Desc=@FirewallAPI.dll,-25081|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LR2-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=143:*|RA4=LocalSubnet|RA6=LocalSubnet|Name=@FirewallAPI.dll,-25076|Desc=@FirewallAPI.dll,-25081|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LD-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=132:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25082|Desc=@FirewallAPI.dll,-25088|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LD-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=132:*|RA4=LocalSubnet|RA6=LocalSubnet|Name=@FirewallAPI.dll,-25083|Desc=@FirewallAPI.dll,-25088|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP4-DUFRAG-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=1|ICMP4=3:4|App=System|Name=@FirewallAPI.dll,-25251|Desc=@FirewallAPI.dll,-25257|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IGMP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=2|App=System|Name=@FirewallAPI.dll,-25376|Desc=@FirewallAPI.dll,-25382|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IGMP-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=2|App=System|Name=@FirewallAPI.dll,-25377|Desc=@FirewallAPI.dll,-25382|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-DHCP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|LPort=68|RPort=67|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25301|Desc=@FirewallAPI.dll,-25303|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-DHCP-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|LPort=68|RPort=67|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25302|Desc=@FirewallAPI.dll,-25303|EmbedCtxt=@FirewallAPI.dll,-25000|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-DHCPV6-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|LPort=546|RPort=547|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25304|Desc=@FirewallAPI.dll,-25306|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-DHCPV6-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|LPort=546|RPort=547|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25305|Desc=@FirewallAPI.dll,-25306|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-Teredo-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|LPort=Teredo|App=%SystemRoot%\\system32\\svchost.exe|Svc=iphlpsvc|Name=@FirewallAPI.dll,-25326|Desc=@FirewallAPI.dll,-25332|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-Teredo-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|App=%SystemRoot%\\system32\\svchost.exe|Svc=iphlpsvc|Name=@FirewallAPI.dll,-25327|Desc=@FirewallAPI.dll,-25333|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IPHTTPS-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|LPort2_10=IPTLSIn|LPort2_10=IPHTTPSIn|App=System|Name=@FirewallAPI.dll,-25426|Desc=@FirewallAPI.dll,-25428|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IPHTTPS-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|RPort2_10=IPTLSOut|RPort2_10=IPHTTPSOut|App=%SystemRoot%\\system32\\svchost.exe|Svc=iphlpsvc|Name=@FirewallAPI.dll,-25427|Desc=@FirewallAPI.dll,-25429|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IPv6-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=41|App=System|Name=@FirewallAPI.dll,-25351|Desc=@FirewallAPI.dll,-25357|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IPv6-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=41|App=System|Name=@FirewallAPI.dll,-25352|Desc=@FirewallAPI.dll,-25358|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-GP-NP-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=445|App=System|Name=@FirewallAPI.dll,-25401|Desc=@FirewallAPI.dll,-25401|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-GP-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Name=@FirewallAPI.dll,-25403|Desc=@FirewallAPI.dll,-25404|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-DNS-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=53|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-25405|Desc=@FirewallAPI.dll,-25406|EmbedCtxt=@FirewallAPI.dll,-25000|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-GP-LSASS-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\lsass.exe|Name=@FirewallAPI.dll,-25407|Desc=@FirewallAPI.dll,-25408|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CDPSvc-In-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=CDPSvc|Name=@FirewallAPI.dll,-37007|Desc=@FirewallAPI.dll,-37008|EmbedCtxt=@FirewallAPI.dll,-37002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WINRM-HTTP-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=5985|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WINRM-HTTP-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5985|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WINRM-HTTP-Compat-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=80|App=System|Name=@FirewallAPI.dll,-35001|Desc=@FirewallAPI.dll,-35002|EmbedCtxt=@FirewallAPI.dll,-30252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WINRM-HTTP-Compat-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=80|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-35001|Desc=@FirewallAPI.dll,-35002|EmbedCtxt=@FirewallAPI.dll,-30252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-VDS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\vds.exe|Svc=vds|Name=@FirewallAPI.dll,-34502|Desc=@FirewallAPI.dll,-34503|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-VDSLDR-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\vdsldr.exe|Name=@FirewallAPI.dll,-34504|Desc=@FirewallAPI.dll,-34505|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-34506|Desc=@FirewallAPI.dll,-34507|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-VDS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\vds.exe|Svc=vds|Name=@FirewallAPI.dll,-34502|Desc=@FirewallAPI.dll,-34503|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-VDSLDR-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\vdsldr.exe|Name=@FirewallAPI.dll,-34504|Desc=@FirewallAPI.dll,-34505|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-34506|Desc=@FirewallAPI.dll,-34507|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteTask-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=schedule|Name=@FirewallAPI.dll,-33253|Desc=@FirewallAPI.dll,-33256|EmbedCtxt=@FirewallAPI.dll,-33252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteTask-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33257|Desc=@FirewallAPI.dll,-33260|EmbedCtxt=@FirewallAPI.dll,-33252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteTask-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=schedule|Name=@FirewallAPI.dll,-33253|Desc=@FirewallAPI.dll,-33256|EmbedCtxt=@FirewallAPI.dll,-33252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteTask-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33257|Desc=@FirewallAPI.dll,-33260|EmbedCtxt=@FirewallAPI.dll,-33252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MDNS-In-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37303|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37304|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MDNS-Out-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|LPort=5353|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37305|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37306|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-HttpTrans-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=80|App=SYSTEM|Name=@peerdistsh.dll,-10000|Desc=@peerdistsh.dll,-11000|EmbedCtxt=@peerdistsh.dll,-9000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-HttpTrans-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=80|App=SYSTEM|Name=@peerdistsh.dll,-10001|Desc=@peerdistsh.dll,-11001|EmbedCtxt=@peerdistsh.dll,-9000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-WSD-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=PeerDistSvc|Name=@peerdistsh.dll,-10002|Desc=@peerdistsh.dll,-11002|EmbedCtxt=@peerdistsh.dll,-9001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-WSD-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=PeerDistSvc|Name=@peerdistsh.dll,-10003|Desc=@peerdistsh.dll,-11003|EmbedCtxt=@peerdistsh.dll,-9001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-HostedServer-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=80|LPort=443|App=SYSTEM|Name=@peerdistsh.dll,-10004|Desc=@peerdistsh.dll,-11004|EmbedCtxt=@peerdistsh.dll,-9002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-HostedServer-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|LPort=80|LPort=443|App=SYSTEM|Name=@peerdistsh.dll,-10005|Desc=@peerdistsh.dll,-11005|EmbedCtxt=@peerdistsh.dll,-9002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-HostedClient-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=80|RPort=443|App=SYSTEM|Name=@peerdistsh.dll,-10006|Desc=@peerdistsh.dll,-11006|EmbedCtxt=@peerdistsh.dll,-9003|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-SSDPSrv-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30753|Desc=@FirewallAPI.dll,-30756|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-SSDPSrv-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30757|Desc=@FirewallAPI.dll,-30760|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=554|LPort=8554|LPort=8555|LPort=8556|LPort=8557|LPort=8558|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30761|Desc=@FirewallAPI.dll,-30764|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30765|Desc=@FirewallAPI.dll,-30768|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-QWave-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30769|Desc=@FirewallAPI.dll,-30772|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-QWave-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30773|Desc=@FirewallAPI.dll,-30776|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-QWave-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30777|Desc=@FirewallAPI.dll,-30780|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-QWave-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30781|Desc=@FirewallAPI.dll,-30784|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-HTTPSTR-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=10244|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30785|Desc=@FirewallAPI.dll,-30788|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-TERMSRV-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=3390|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-30793|Desc=@FirewallAPI.dll,-30796|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=7777|LPort=7778|LPort=7779|LPort=7780|LPort=7781|LPort=5004|LPort=5005|LPort=50004|LPort=50005|LPort=50006|LPort=50007|LPort=50008|LPort=50009|LPort=50010|LPort=50011|LPort=50012|LPort=50013|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30801|Desc=@FirewallAPI.dll,-30804|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30805|Desc=@FirewallAPI.dll,-30808|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-MCX2SVC-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=mcx2svc|Name=@FirewallAPI.dll,-30810|Desc=@FirewallAPI.dll,-30811|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-Prov-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\ehome\\mcx2prov.exe|Name=@FirewallAPI.dll,-30812|Desc=@FirewallAPI.dll,-30813|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-PlayTo-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30814|Desc=@FirewallAPI.dll,-30815|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-PlayTo-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-30816|Desc=@FirewallAPI.dll,-30817|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-McrMgr-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\ehome\\mcrmgr.exe|Name=@FirewallAPI.dll,-30818|Desc=@FirewallAPI.dll,-30819|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-PlayTo-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30820|Desc=@FirewallAPI.dll,-30821|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-FDPHost-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-30822|Desc=@FirewallAPI.dll,-30823|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SPPSVC-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=1688|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\sppextcomobj.exe|Svc=sppsvc|Name=@FirewallAPI.dll,-28003|Desc=@FirewallAPI.dll,-28006|EmbedCtxt=@FirewallAPI.dll,-28002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SPPSVC-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=1688|App=%SystemRoot%\\system32\\sppextcomobj.exe|Svc=sppsvc|Name=@FirewallAPI.dll,-28003|Desc=@FirewallAPI.dll,-28006|EmbedCtxt=@FirewallAPI.dll,-28002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=15740|App=%SystemRoot%\\system32\\wudfhost.exe|Name=@FirewallAPI.dll,-30503|Desc=@FirewallAPI.dll,-30506|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=15740|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\wudfhost.exe|Name=@FirewallAPI.dll,-30503|Desc=@FirewallAPI.dll,-30506|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-SSDPSrv-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30507|Desc=@FirewallAPI.dll,-30510|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-SSDPSrv-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30511|Desc=@FirewallAPI.dll,-30514|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-UPnPHost-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30515|Desc=@FirewallAPI.dll,-30518|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-UPnPHost-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-30519|Desc=@FirewallAPI.dll,-30522|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-UPnP-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-30523|Desc=@FirewallAPI.dll,-30524|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteDesktop-UserMode-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=3389|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteDesktop-UserMode-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3389|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28776|Desc=@FirewallAPI.dll,-28777|EmbedCtxt=@FirewallAPI.dll,-28752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteDesktop-Shadow-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\RdpSa.exe|Name=@FirewallAPI.dll,-28778|Desc=@FirewallAPI.dll,-28779|EmbedCtxt=@FirewallAPI.dll,-28752|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Output "SharedAccess ($Wert) wird NEU gesetzt"
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

Write-Output "FirewallRules erfolgreich entfernt, CustomRules und die alten Windows Standardregeln als deaktivierte Restriktivregeln neu angelegt. Reboot sinnvoll!"
