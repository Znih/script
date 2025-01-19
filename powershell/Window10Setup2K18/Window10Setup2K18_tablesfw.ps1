#=============================================================================
# HELP:           https://technet.microsoft.com/en-us/library/hh849827.aspx
# FILE:           2018_Windows10-Setup.ps1
# USAGE:          powershell.exe C:\Windows\System32\WindowsPowerShell\v1.0\2018_Windows10-Setup.ps1
# DESCRIPTION:    Verwalten von Verbindungen zwischen Windows-Betriebssystemkomponenten und Microsoft-Diensten regeln
#                 Compiling with C:\Users\ich\Desktop\logon\ps2exe.ps1 -inputFile C:\Users\ich\Desktop\logon\7_2018_Windows10-Setup.ps1 -outputFile C:\Users\ich\Desktop\logon\2018_Windows10-Setup.exe -runtime50
# OPTION:         (see USAGE) privacyscript
# REQUIREMENTS:   dotnet 4.5.2 & powershell 4.0
# TEST:           .\7_2018_Windows10-Setup.ps1 | of -FilePath ".\test.txt" -Encoding ascii
# BUGS:
# NOTES:          powershell default profile file copy to C:\Windows\System32\WindowsPowerShell\v1.0
#                 check Get-ExecutionPolicy (switch Restricted to Set-ExecutionPolicy RemoteSigned or Unrestricted)
#                 update get-help > Update-Help
# AUTHOR:         Marco Hinz <https://github.com/hinzigers>
# COMPANY:        matrixhacker.de
# VERSION:        1.0.6
# CREATED:        06.12.2017
# REVISION:       07.12.2017, 10.12.2017, 12.12.2017, 25.12.2017, 01.01.2018, 13.01.2018
# EDITOR:         Marco Hinz <https://github.com/hinzigers>
# SOURCE:         Microsoft <https://docs.microsoft.com/de-de/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services>
#=============================================================================

...

#-----------------------------------------------------------------------------
# Firewall konfigurieren
#-----------------------------------------------------------------------------
echo "#-----------------------------------------------------------------------------" >> $install\FuckYouBillyBoy.log
echo "# Firewall konfigurieren" >> $install\FuckYouBillyBoy.log
echo "#-----------------------------------------------------------------------------" >> $install\FuckYouBillyBoy.log

$Wert="DisableNotifications"
$DWord="1"
$Key="Tcpip_$Iface"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\$Key"
Write-Host "Windows Firewall wird konfiguriert ($Wert)" -f Green
echo "Windows Firewall wird konfiguriert ($Wert)" >> $install\FuckYouBillyBoy.log
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

# Firewall Regeln neu konfigurieren
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
#LocalSubnet, DNS, DHCP, WINS, DefaultGateway, Internet, Intranet, IntranetRemoteAccess, PlayToDevice.

Write-Host "FirewallRules werden komplett entfernt und entwaffnet neu gesetzt" -f Green
echo "FirewallRules werden entfernt und entwaffnet neu gesetzt" >> $install\FuckYouBillyBoy.log
Remove-Item $Path
mkdirpath-force $Path
New-NetFirewallRule -DisplayName "BlockWSD_3702udp_out" -Direction Outbound -Action Block -RemotePort 3702 -Protocol UDP
echo "BlockWSD_3702udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockPNRP_3540udp_out" -Direction Outbound -Action Block -RemotePort 3540 -Protocol UDP
echo "BlockPNRP_3540udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "Block_mDNS_5353udp_out" -Direction Outbound -Action Block -LocalPort 5353 -Protocol UDP
echo "Block_mDNS_5353udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "Block_mDNS_5353udp_in" -Direction Inbound -Action Block -LocalPort 5353 -Protocol UDP
echo "Block_mDNS_5353udp_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockLLMNR_5355udp_out" -Direction Outbound -Action Block -RemotePort 5355 -Protocol UDP
echo "BlockLLMNR_5355udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockWSD" -Direction Outbound -Action Block -RemotePort 3587 -Protocol UDP
echo "BlockWSD Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "Block_2869udp" -Direction Outbound -Action Block -RemotePort 2869 -Protocol UDP
echo "Block_2869udp Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockWSD_5358tcp_out" -Direction Outbound -Action Block -RemotePort 5358 -Protocol TCP
echo "BlockWSD_5358tcp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log

New-NetFirewallRule -DisplayName "BlockDHCPV6_547udp_out" -Direction Outbound -Action Block -LocalPort 546 -RemotePort 547 -Protocol UDP
echo "BlockDHCPV6_547udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockDHCPV6_547udp_in" -Direction Inbound -Action Block -LocalPort 546 -RemotePort 547 -Protocol UDP
echo "BlockDHCPV6_547udp_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "Block_7250tcp_in" -Direction Inbound -Action Block -RemotePort 7250 -Protocol TCP
echo "Block_7250tcp_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockWFD-ASP_7235udp_out" -Direction Outbound -Action Block -LocalPort 7235 -RemotePort 7235 -Protocol UDP
echo "BlockWFD-ASP_7235udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockWFD-ASP_7235udp_in" -Direction Inbound -Action Block -LocalPort 7235 -RemotePort 7235 -Protocol UDP
echo "BlockWFD-ASP_7235udp_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockAllJoyn-Router_9955tcp_in" -Direction Inbound -Action Block -RemotePort 9955 -Protocol TCP
echo "BlockAllJoyn-Router_9955tcp_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockÜbermittlungsoptimierung_7680tcp_in" -Direction Inbound -Action Block -LocalPort 7680 -Protocol TCP
echo "BlockÜbermittlungsoptimierung_7680tcp_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockÜbermittlungsoptimierung_7680udp_in" -Direction Inbound -Action Block -LocalPort 7680 -Protocol UDP
echo "BlockÜbermittlungsoptimierung_7680udp_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockDIAL-Protokollserver_10247tcp_in" -Direction Inbound -Action Block -LocalPort 10247 -Protocol TCP
echo "BlockDIAL-Protokollserver_10247tcp_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockNetBIOS-RPC_tcp_in" -Direction Inbound -Action Block -LocalPort 135, 139 -Protocol TCP
echo "BlockNetBIOS-RPC_tcp_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log

New-NetFirewallRule -DisplayName "BlockRTSP-RTP-Streaming_2355xtcp_in" -Direction Inbound -Action Block -LocalPort 23554, 23555, 23556 -Protocol TCP
echo "BlockRTSP-RTP-Streaming_2355xtcp_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockHTTP-Streaming_10246tcp_in" -Direction Inbound -Action Block -LocalPort 10246 -Protocol TCP
echo "BlockHTTP-Streaming_10246tcp_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log

New-NetFirewallRule -DisplayName "BLOCK-ALL-IN-enable-disable-here" -Direction Inbound -Action Block -Enabled False -Description "Das ist quasi eine ALLDrop Regel, die aber bei MS alles blockiert (auch die aktive AllowRules), was so dumm ist, wie nur irgendwas. Zum Abschotten diese Regel einfach aktivieren (dann jedoch wird alles von aussen geblockt!!!)"
echo "BLOCK-ALL-IN-enable-disable-here Regel neu erstellt" >> $install\FuckYouBillyBoy.log
#New-NetFirewallRule -DisplayName "BlockALL_TCP_in" -Direction Inbound -Action Block -Protocol TCP

#Inbound (Schalter  -ErrorAction SilentlyContinue beim Einlesen verwenden, um GhostError zu vermeiden)
#New-NetFirewallRule -DisplayName "AllowSMB_192.168.228.44_in" -Direction Inbound -Action Allow -Protocol 6 -LocalPort 445 -RemotePort 49600-49700 -LocalAddress $LANIP  -RemoteAddress 192.168.228.44 -Encryption Required -Authentication Required -LocalUser "O:LSD:(A;;CC;;;$SID)" -Owner $SID
New-NetFirewallRule -DisplayName "AllowSMB_TRUSTIPs_in" -ErrorAction SilentlyContinue -Direction Inbound -Action Allow -Protocol 6 -LocalPort 445 -RemotePort 32000-65000 -LocalAddress $LANIP -RemoteAddress ([string[]]$trustips) -Description "Verschlüsselung nicht möglich!!! Siehe Script. Datei- und Druckerfreigabe muss angehakt bleiben und zusätzlich muss die Policy auf Privat gestellt werden (GPO)"
echo "AllowSMB_TRUSTIPs_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log
#New-NetFirewallRule -DisplayName "AllowSMB_192.168.228.60_in" -Direction Inbound -Action Allow -Protocol 6 -LocalPort 445 -RemotePort 50000-65535 -LocalAddress $LANIP -RemoteAddress 192.168.228.60 -Description "Linux/UNIX Zugriffe"
New-NetFirewallRule -DisplayName "BlockSMB_inet_in" -ErrorAction SilentlyContinue -Direction Inbound -Action Block -Protocol 6 -LocalPort 445 -LocalAddress $LANIP -RemoteAddress ([string[]]$untrustips) -Description "SMB Defense"
echo "BlockSMB_inet_in Regel neu erstellt" >> $install\FuckYouBillyBoy.log
#New-NetFirewallRule -DisplayName "BlockSSDP/UPnP_in" -Direction Inbound -Action Block -Protocol 6 -LocalPort 5357 -LocalAddress $LANIP -Description "Microsoft HTTPAPI (webserver) httpd 2.0 (SSDP/UPnP) eingehend blockieren!"

# Outbound
New-NetFirewallRule -DisplayName "AllowSMB_out" -Direction Outbound -Action Allow -Protocol 6 -RemotePort 445 -LocalAddress $LANIP -RemoteAddress LocalSubnet -Program System
echo "AllowSMB_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "AllowDNS_tcp_out" -Direction Outbound -Action Allow -RemotePort 53 -LocalAddress $LANIP -RemoteAddress DNS -Protocol TCP
echo "AllowDNS_tcp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "AllowDNS_udp_out" -Direction Outbound -Action Allow -RemotePort 53 -LocalAddress $LANIP -RemoteAddress DNS -Protocol UDP
echo "AllowDNS_udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "AllowDHCP_udp_out" -Direction Outbound -Action Allow -LocalPort 68 -RemotePort 67 -LocalAddress $LANIP -RemoteAddress DHCP -Protocol UDP
echo "AllowDHCP_udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "AllowNTP_udp_out" -Direction Outbound -Action Allow -RemotePort 123 -LocalAddress $LANIP -Protocol UDP
echo "AllowNTP_udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "AllowLAN_udp_out" -Direction Outbound -Action Allow -RemotePort 1-52, 54-66, 69-122, 124-65535 -LocalAddress $LANIP -RemoteAddress LocalSubnet -Protocol UDP
echo "AllowLAN_udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockLAN_udp_out" -Direction Outbound -Action Block -Enabled False -RemotePort 1-52, 54-66, 69-122, 124-65535 -LocalAddress $LANIP -Protocol UDP -Description "Wenn diese Regel aktiviert wird, wird UDP bis auf die Ausnahmen vollständig deaktiviert (auch die Regel AllowLAN_udp_out wird damit 'überschrieben')."
echo "BlockLAN_udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockSSDP/UPnP_out" -Direction Outbound -Action Block -Protocol 6 -LocalPort 5357 -LocalAddress $LANIP -Description "Microsoft HTTPAPI (webserver) httpd 2.0 (SSDP/UPnP) ausgehend blockieren!"
echo "BlockSSDP/UPnP_out neu erstellt" >> $install\FuckYouBillyBoy.log

New-NetFirewallRule -DisplayName "AllowFPS-NB_Datagram_udp_out" -Direction Outbound -Action Allow -Protocol 17 -RemotePort 138 -LocalAddress $LANIP -RemoteAddress LocalSubnet -Program System -Description "SYSTEM UDP 138 ins LAN gestatten"
echo "AllowFPS-NB_Datagram_udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "AllowFPS-NB_Name_udp_out" -Direction Outbound -Action Allow -Protocol 17 -RemotePort 137 -LocalAddress $LANIP -RemoteAddress LocalSubnet -Program System -Description "SYSTEM UDP 137 ins LAN gestatten"
echo "AllowFPS-NB_Name_udp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "AllowFPS-NB_Session_tcp_out" -Direction Outbound -Action Allow -Protocol 6 -RemotePort 139 -LocalAddress $LANIP -RemoteAddress LocalSubnet -Program System -Description "SYSTEM TCP 139 ins LAN gestatten"
echo "AllowFPS-NB_Session_tcp_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log


New-NetFirewallRule -DisplayName "BlockIPv6_out" -Direction Outbound -Action Block -Protocol 41
echo "BlockIPv6_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockIPv6_Frag_out" -Direction Outbound -Action Block -Protocol 44
echo "BlockIPv6_Frag_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockICMPv6_out" -Direction Outbound -Action Block -Protocol 58
echo "BlockICMPv6_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockIGMP_out" -Direction Outbound -Action Block -Protocol 2
echo "BlockIGMP_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockIPv6_NoNxt_out" -Direction Outbound -Action Block -Protocol 59
echo "BlockIPv6_NoNxt_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockGRE_out" -Direction Outbound -Action Block -Protocol 47
echo "BlockGRE_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockIPv6_Opts_out" -Direction Outbound -Action Block -Protocol 60
echo "BlockIPv6_Opts_out Regel neu erstellt" >> $install\FuckYouBillyBoy.log
New-NetFirewallRule -DisplayName "BlockIPv6_Route" -Direction Outbound -Action Block -Protocol 43
echo "BlockIPv6_Route Regel neu erstellt" >> $install\FuckYouBillyBoy.log

# Blockiere Telemetrie IPs
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
Remove-NetFirewallRule -DisplayName "BLOCK-TELEMETRY-IPs" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "BLOCK-TELEMETRY-IPs" -Direction Outbound `
    -Action Block -RemoteAddress ([string[]]$ips)

# Windows FirewallRules Standard wieder einpflegen (SharedAccess)
$Wert="vm-monitoring-dcom"
$String="v2.0|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=RpcSs|Name=@icsvc.dll,-709|Desc=@icsvc.dll,-710|EmbedCtxt=@icsvc.dll,-700|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="vm-monitoring-icmpv4"
$String="v2.0|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Name=@icsvc.dll,-701|Desc=@icsvc.dll,-702|EmbedCtxt=@icsvc.dll,-700|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="vm-monitoring-icmpv6"
$String="v2.0|Action=Allow|Active=FALSE|Dir=In|Protocol=58|Name=@icsvc.dll,-703|Desc=@icsvc.dll,-704|EmbedCtxt=@icsvc.dll,-700|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="vm-monitoring-nb-session"
$String="v2.0|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=139|Name=@icsvc.dll,-705|Desc=@icsvc.dll,-706|EmbedCtxt=@icsvc.dll,-700|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="vm-monitoring-rpc"
$String="v2.0|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=Schedule|Name=@icsvc.dll,-707|Desc=@icsvc.dll,-708|EmbedCtxt=@icsvc.dll,-700|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SNMPTRAP-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=162|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\snmptrap.exe|Svc=SNMPTRAP|Name=@snmptrap.exe,-7|Desc=@snmptrap.exe,-8|EmbedCtxt=@snmptrap.exe,-3|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SNMPTRAP-In-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=162|App=%SystemRoot%\\system32\\snmptrap.exe|Svc=SNMPTRAP|Name=@snmptrap.exe,-7|Desc=@snmptrap.exe,-8|EmbedCtxt=@snmptrap.exe,-3|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Wininit-Shutdown-In-Rule-TCP-RPC"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%systemroot%\\system32\\wininit.exe|Name=@firewallapi.dll,-36753|Desc=@firewallapi.dll,-36754|EmbedCtxt=@firewallapi.dll,-36751|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Wininit-Shutdown-In-Rule-TCP-RPC-EPMapper"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC-EPMap|App=%systemroot%\\system32\\wininit.exe|Name=@firewallapi.dll,-36755|Desc=@firewallapi.dll,-36756|EmbedCtxt=@firewallapi.dll,-36751|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WiFiDirect-KM-Driver-In-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|App=System|Name=@wlansvc.dll,-37378|Desc=@wlansvc.dll,-37890|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WiFiDirect-KM-Driver-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|App=System|Name=@wlansvc.dll,-37379|Desc=@wlansvc.dll,-37891|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WiFiDirect-KM-Driver-In-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|App=System|Name=@wlansvc.dll,-37380|Desc=@wlansvc.dll,-37892|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WiFiDirect-KM-Driver-Out-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|App=System|Name=@wlansvc.dll,-37381|Desc=@wlansvc.dll,-37893|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-Unified-Telemetry-Client"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Svc=DiagTrack|Name=@%windir%\\system32\\diagtrack.dll,-3001|Desc=@%windir%\\system32\\diagtrack.dll,-3003|EmbedCtxt=DiagTrack|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PNRPMNRS-PNRP-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-34003|Desc=@FirewallAPI.dll,-34004|EmbedCtxt=@FirewallAPI.dll,-34002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PNRPMNRS-PNRP-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-34005|Desc=@FirewallAPI.dll,-34006|EmbedCtxt=@FirewallAPI.dll,-34002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PNRPMNRS-SSDPSrv-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-34007|Desc=@FirewallAPI.dll,-34008|EmbedCtxt=@FirewallAPI.dll,-34002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PNRPMNRS-SSDPSrv-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-34009|Desc=@FirewallAPI.dll,-34010|EmbedCtxt=@FirewallAPI.dll,-34002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="DeliveryOptimization-TCP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|LPort=7680|App=%SystemRoot%\\system32\\svchost.exe|Svc=dosvc|Name=@%systemroot%\\system32\\dosvc.dll,-102|Desc=@%systemroot%\\system32\\dosvc.dll,-104|EmbedCtxt=@%systemroot%\\system32\\dosvc.dll,-100|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="DeliveryOptimization-UDP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|LPort=7680|App=%SystemRoot%\\system32\\svchost.exe|Svc=dosvc|Name=@%systemroot%\\system32\\dosvc.dll,-103|Desc=@%systemroot%\\system32\\dosvc.dll,-104|EmbedCtxt=@%systemroot%\\system32\\dosvc.dll,-100|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="EventForwarder-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\system32\\NetEvtFwdr.exe|Name=@FirewallAPI.dll,-36802|Desc=@FirewallAPI.dll,-36803|EmbedCtxt=@FirewallAPI.dll,-36801|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="EventForwarder-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-36804|Desc=@FirewallAPI.dll,-36805|EmbedCtxt=@FirewallAPI.dll,-36801|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MsiScsi-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29003|Desc=@FirewallAPI.dll,-29006|EmbedCtxt=@FirewallAPI.dll,-29002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MsiScsi-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29007|Desc=@FirewallAPI.dll,-29010|EmbedCtxt=@FirewallAPI.dll,-29002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MsiScsi-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29003|Desc=@FirewallAPI.dll,-29006|EmbedCtxt=@FirewallAPI.dll,-29002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MsiScsi-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29007|Desc=@FirewallAPI.dll,-29010|EmbedCtxt=@FirewallAPI.dll,-29002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteFwAdmin-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=policyagent|Name=@FirewallAPI.dll,-30003|Desc=@FirewallAPI.dll,-30006|EmbedCtxt=@FirewallAPI.dll,-30002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteFwAdmin-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-30007|Desc=@FirewallAPI.dll,-30010|EmbedCtxt=@FirewallAPI.dll,-30002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteFwAdmin-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=policyagent|Name=@FirewallAPI.dll,-30003|Desc=@FirewallAPI.dll,-30006|EmbedCtxt=@FirewallAPI.dll,-30002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteFwAdmin-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-30007|Desc=@FirewallAPI.dll,-30010|EmbedCtxt=@FirewallAPI.dll,-30002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="AllJoyn-Router-In-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=9955|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37003|Desc=@FirewallAPI.dll,-37004|EmbedCtxt=@FirewallAPI.dll,-37002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="AllJoyn-Router-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37005|Desc=@FirewallAPI.dll,-37006|EmbedCtxt=@FirewallAPI.dll,-37002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="AllJoyn-Router-In-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37007|Desc=@FirewallAPI.dll,-37008|EmbedCtxt=@FirewallAPI.dll,-37002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="AllJoyn-Router-Out-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37009|Desc=@FirewallAPI.dll,-37010|EmbedCtxt=@FirewallAPI.dll,-37002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Netlogon-NamedPipe-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=445|App=System|Name=@netlogon.dll,-1003|Desc=@netlogon.dll,-1006|EmbedCtxt=@netlogon.dll,-1010|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Netlogon-TCP-RPC-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\System32\\lsass.exe|Name=@netlogon.dll,-1008|Desc=@netlogon.dll,-1009|EmbedCtxt=@netlogon.dll,-1010|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="ProximityUxHost-Sharing-In-TCP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\proximityuxhost.exe|Name=@FirewallAPI.dll,-36252|Desc=@FirewallAPI.dll,-36253|EmbedCtxt=@FirewallAPI.dll,-36251|TTK=ProxSharing|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="ProximityUxHost-Sharing-Out-TCP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\system32\\proximityuxhost.exe|Name=@FirewallAPI.dll,-36254|Desc=@FirewallAPI.dll,-36255|EmbedCtxt=@FirewallAPI.dll,-36251|TTK=ProxSharing|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=2869|App=System|Name=@FirewallAPI.dll,-32761|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=2869|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-In-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=137|App=System|Name=@FirewallAPI.dll,-32769|Desc=@FirewallAPI.dll,-32772|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-Out-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=137|App=System|Name=@FirewallAPI.dll,-32773|Desc=@FirewallAPI.dll,-32776|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-In-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=138|App=System|Name=@FirewallAPI.dll,-32777|Desc=@FirewallAPI.dll,-32780|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-Out-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=138|App=System|Name=@FirewallAPI.dll,-32781|Desc=@FirewallAPI.dll,-32784|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=5358|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=5358|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32815|Desc=@FirewallAPI.dll,-32816|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=5357|App=System|Name=@FirewallAPI.dll,-32817|Desc=@FirewallAPI.dll,-32818|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=5357|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32819|Desc=@FirewallAPI.dll,-32820|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-SSDPSrv-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32753|Desc=@FirewallAPI.dll,-32756|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-SSDPSrv-Out-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32757|Desc=@FirewallAPI.dll,-32760|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-In-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32761|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnP-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-32821|Desc=@FirewallAPI.dll,-32822|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32769|Desc=@FirewallAPI.dll,-32772|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-Out-UDP-Active"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32773|Desc=@FirewallAPI.dll,-32776|EmbedCtxt=@FirewallAPI.dll,-32752|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32777|Desc=@FirewallAPI.dll,-32780|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-Out-UDP-Active"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32781|Desc=@FirewallAPI.dll,-32784|EmbedCtxt=@FirewallAPI.dll,-32752|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDPHOST-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32785|Desc=@FirewallAPI.dll,-32788|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-DAS-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-32825|Desc=@FirewallAPI.dll,-32826|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PNRPMNRS-PNRP-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-34003|Desc=@FirewallAPI.dll,-34004|EmbedCtxt=@FirewallAPI.dll,-34002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDPHOST-Out-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32789|Desc=@FirewallAPI.dll,-32792|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-LLMNR-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32801|Desc=@FirewallAPI.dll,-32804|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-LLMNR-Out-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32805|Desc=@FirewallAPI.dll,-32808|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDRESPUB-WSD-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32809|Desc=@FirewallAPI.dll,-32810|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDRESPUB-WSD-Out-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32811|Desc=@FirewallAPI.dll,-32812|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-In-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|RPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32815|Desc=@FirewallAPI.dll,-32816|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-In-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32817|Desc=@FirewallAPI.dll,-32818|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|RPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32819|Desc=@FirewallAPI.dll,-32820|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-SSDPSrv-In-UDP-Teredo"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32754|Desc=@FirewallAPI.dll,-32756|EmbedCtxt=@FirewallAPI.dll,-32752|TTK2_27=UPnP|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-SSDPSrv-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32757|Desc=@FirewallAPI.dll,-32760|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnP-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|Profile=Public|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-32821|Desc=@FirewallAPI.dll,-32822|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32761|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-In-TCP-Teredo"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Public|App=System|Name=@FirewallAPI.dll,-32762|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|TTK2_27=UPnP|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-UPnPHost-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32769|Desc=@FirewallAPI.dll,-32772|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32773|Desc=@FirewallAPI.dll,-32776|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32777|Desc=@FirewallAPI.dll,-32780|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Datagram-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32781|Desc=@FirewallAPI.dll,-32784|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDPHOST-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32785|Desc=@FirewallAPI.dll,-32788|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-DAS-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-32825|Desc=@FirewallAPI.dll,-32826|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDPHOST-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32789|Desc=@FirewallAPI.dll,-32792|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-LLMNR-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32801|Desc=@FirewallAPI.dll,-32804|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-LLMNR-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32805|Desc=@FirewallAPI.dll,-32808|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDRESPUB-WSD-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32809|Desc=@FirewallAPI.dll,-32810|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-FDRESPUB-WSD-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32811|Desc=@FirewallAPI.dll,-32812|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32815|Desc=@FirewallAPI.dll,-32816|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32817|Desc=@FirewallAPI.dll,-32818|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNT-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32819|Desc=@FirewallAPI.dll,-32820|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WirelessDisplay-In-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|App=%systemroot%\\system32\\WUDFHost.exe|Name=@wifidisplay.dll,-10200|Desc=@wifidisplay.dll,-10201|LUAuth=O:LSD:(A;;CC;;;UD)|EmbedCtxt=@wifidisplay.dll,-100|TTK2_22=WFDDisplay|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WirelessDisplay-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%systemroot%\\system32\\WUDFHost.exe|Name=@wifidisplay.dll,-10202|Desc=@wifidisplay.dll,-10203|LUAuth=O:LSD:(A;;CC;;;S-1-5-84-0-0-0-0-0)|EmbedCtxt=@wifidisplay.dll,-100|TTK2_22=WFDDisplay|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WirelessDisplay-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|App=%systemroot%\\system32\\WUDFHost.exe|Name=@wifidisplay.dll,-10204|Desc=@wifidisplay.dll,-10205|LUAuth=O:LSD:(A;;CC;;;S-1-5-84-0-0-0-0-0)|EmbedCtxt=@wifidisplay.dll,-100|TTK2_22=WFDDisplay|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WirelessDisplay-Infra-In-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|LPort=7250|App=%systemroot%\\system32\\CastSrv.exe|Name=@wifidisplay.dll,-10206|Desc=@wifidisplay.dll,-10207|EmbedCtxt=@wifidisplay.dll,-100|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34252|Desc=@FirewallAPI.dll,-34253|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-WINMGMT-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34254|Desc=@FirewallAPI.dll,-34255|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-WINMGMT-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34258|Desc=@FirewallAPI.dll,-34259|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-ASYNC-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%systemroot%\\system32\\wbem\\unsecapp.exe|Name=@FirewallAPI.dll,-34256|Desc=@FirewallAPI.dll,-34257|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=135|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34252|Desc=@FirewallAPI.dll,-34253|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-WINMGMT-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34254|Desc=@FirewallAPI.dll,-34255|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-WINMGMT-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34258|Desc=@FirewallAPI.dll,-34259|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WMI-ASYNC-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\wbem\\unsecapp.exe|Name=@FirewallAPI.dll,-34256|Desc=@FirewallAPI.dll,-34257|EmbedCtxt=@FirewallAPI.dll,-34251|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Session-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=139|App=System|Name=@FirewallAPI.dll,-28503|Desc=@FirewallAPI.dll,-28506|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Session-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=139|App=System|Name=@FirewallAPI.dll,-28507|Desc=@FirewallAPI.dll,-28510|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SMB-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-28511|Desc=@FirewallAPI.dll,-28514|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SMB-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=445|App=System|Name=@FirewallAPI.dll,-28515|Desc=@FirewallAPI.dll,-28518|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Name-In-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=137|App=System|Name=@FirewallAPI.dll,-28519|Desc=@FirewallAPI.dll,-28522|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Name-Out-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=137|App=System|Name=@FirewallAPI.dll,-28523|Desc=@FirewallAPI.dll,-28526|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Datagram-In-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=138|App=System|Name=@FirewallAPI.dll,-28527|Desc=@FirewallAPI.dll,-28530|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Datagram-Out-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=138|App=System|Name=@FirewallAPI.dll,-28531|Desc=@FirewallAPI.dll,-28534|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SpoolSvc-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-28535|Desc=@FirewallAPI.dll,-28538|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-WSDEVNTS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|Svc=Rpcss|Name=@FirewallAPI.dll,-28539|Desc=@FirewallAPI.dll,-28542|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP4-ERQ-In-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Domain|ICMP4=8:*|Name=@FirewallAPI.dll,-28543|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP4-ERQ-Out-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=1|Profile=Domain|ICMP4=8:*|Name=@FirewallAPI.dll,-28544|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP6-ERQ-In-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=58|Profile=Domain|ICMP6=128:*|Name=@FirewallAPI.dll,-28545|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP6-ERQ-Out-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=58|Profile=Domain|ICMP6=128:*|Name=@FirewallAPI.dll,-28546|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Session-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=139|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28503|Desc=@FirewallAPI.dll,-28506|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Session-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=139|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28507|Desc=@FirewallAPI.dll,-28510|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SMB-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28511|Desc=@FirewallAPI.dll,-28514|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SMB-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28515|Desc=@FirewallAPI.dll,-28518|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Name-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28519|Desc=@FirewallAPI.dll,-28522|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Name-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28523|Desc=@FirewallAPI.dll,-28526|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Datagram-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28527|Desc=@FirewallAPI.dll,-28530|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-NB_Datagram-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28531|Desc=@FirewallAPI.dll,-28534|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WiFiDirect-KM-Driver-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|App=System|Name=@wlansvc.dll,-37379|Desc=@wlansvc.dll,-37891|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-SpoolSvc-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-28535|Desc=@FirewallAPI.dll,-28538|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|Svc=Rpcss|Name=@FirewallAPI.dll,-28539|Desc=@FirewallAPI.dll,-28542|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP4-ERQ-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Public|ICMP4=8:*|RA4=LocalSubnet|Name=@FirewallAPI.dll,-28543|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP4-ERQ-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=1|Profile=Public|ICMP4=8:*|RA4=LocalSubnet|Name=@FirewallAPI.dll,-28544|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP6-ERQ-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=58|Profile=Public|ICMP6=128:*|RA6=LocalSubnet|Name=@FirewallAPI.dll,-28545|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-ICMP6-ERQ-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=58|Profile=Public|ICMP6=128:*|RA6=LocalSubnet|Name=@FirewallAPI.dll,-28546|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-LLMNR-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-28548|Desc=@FirewallAPI.dll,-28549|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="FPS-LLMNR-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-28550|Desc=@FirewallAPI.dll,-28551|EmbedCtxt=@FirewallAPI.dll,-28502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SSTP-IN-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=443|App=System|Name=@sstpsvc.dll,-35002|Desc=@sstpsvc.dll,-35003|EmbedCtxt=@sstpsvc.dll,-35001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-36502|Desc=@FirewallAPI.dll,-36503|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-Server-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36504|Desc=@FirewallAPI.dll,-36505|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-Server-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36506|Desc=@FirewallAPI.dll,-36507|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=135|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-36502|Desc=@FirewallAPI.dll,-36503|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-Server-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36504|Desc=@FirewallAPI.dll,-36505|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="TPMVSCMGR-Server-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36506|Desc=@FirewallAPI.dll,-36507|EmbedCtxt=@FirewallAPI.dll,-36501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-HomeGroup-ProvSvc-TCP3587-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=3587|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=p2psvc|Name=@%systemroot%\\system32\\provsvc.dll,-200|Desc=@%systemroot%\\system32\\provsvc.dll,-201|EmbedCtxt=@%systemroot%\\system32\\provsvc.dll,-202|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-HomeGroup-ProvSvc-TCP3587-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|RPort=3587|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=p2psvc|Name=@%systemroot%\\system32\\provsvc.dll,-203|Desc=@%systemroot%\\system32\\provsvc.dll,-204|EmbedCtxt=@%systemroot%\\system32\\provsvc.dll,-202|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-HomeGroup-ProvSvc-UDP3540-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|LPort=3540|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@%systemroot%\\system32\\provsvc.dll,-205|Desc=@%systemroot%\\system32\\provsvc.dll,-206|EmbedCtxt=@%systemroot%\\system32\\provsvc.dll,-202|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-HomeGroup-ProvSvc-UDP3540-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RPort=3540|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@%systemroot%\\system32\\provsvc.dll,-207|Desc=@%systemroot%\\system32\\provsvc.dll,-208|EmbedCtxt=@%systemroot%\\system32\\provsvc.dll,-202|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-In-TCP-EdgeScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33003|Desc=@FirewallAPI.dll,-33006|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33007|Desc=@FirewallAPI.dll,-33010|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-PnrpSvc-UDP-In-EdgeScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=3540|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33039|Desc=@FirewallAPI.dll,-33040|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-PnrpSvc-UDP-OUT"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33037|Desc=@FirewallAPI.dll,-33038|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-RAServer-In-TCP-NoScope-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\raserver.exe|Name=@FirewallAPI.dll,-33011|Desc=@FirewallAPI.dll,-33014|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-RAServer-Out-TCP-NoScope-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\raserver.exe|Name=@FirewallAPI.dll,-33015|Desc=@FirewallAPI.dll,-33018|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-DCOM-In-TCP-NoScope-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-33035|Desc=@FirewallAPI.dll,-33036|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-In-TCP-EdgeScope-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33003|Desc=@FirewallAPI.dll,-33006|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33007|Desc=@FirewallAPI.dll,-33010|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-SSDPSrv-In-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-33019|Desc=@FirewallAPI.dll,-33022|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-SSDPSrv-Out-UDP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Private|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-33023|Desc=@FirewallAPI.dll,-33026|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="NETDIS-NB_Name-Out-UDP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=137|App=System|Name=@FirewallAPI.dll,-32773|Desc=@FirewallAPI.dll,-32776|EmbedCtxt=@FirewallAPI.dll,-32752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-SSDPSrv-In-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-33027|Desc=@FirewallAPI.dll,-33030|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-SSDPSrv-Out-TCP-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-33031|Desc=@FirewallAPI.dll,-33034|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-PnrpSvc-UDP-In-EdgeScope-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|LPort=3540|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33039|Desc=@FirewallAPI.dll,-33040|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteAssistance-PnrpSvc-UDP-OUT-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Private|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33037|Desc=@FirewallAPI.dll,-33038|EmbedCtxt=@FirewallAPI.dll,-33002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33503|Desc=@FirewallAPI.dll,-33506|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33507|Desc=@FirewallAPI.dll,-33510|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-KTMRM-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=ktmrm|Name=@FirewallAPI.dll,-33511|Desc=@FirewallAPI.dll,-33512|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33513|Desc=@FirewallAPI.dll,-33514|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33503|Desc=@FirewallAPI.dll,-33506|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33507|Desc=@FirewallAPI.dll,-33510|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-KTMRM-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=ktmrm|Name=@FirewallAPI.dll,-33511|Desc=@FirewallAPI.dll,-33512|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MSDTC-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33513|Desc=@FirewallAPI.dll,-33514|EmbedCtxt=@FirewallAPI.dll,-33502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-P2PHost-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32003|Desc=@FirewallAPI.dll,-32006|EmbedCtxt=@FirewallAPI.dll,-32002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-P2PHost-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32007|Desc=@FirewallAPI.dll,-32010|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-P2PHost-WSD-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32011|Desc=@FirewallAPI.dll,-32014|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-P2PHost-WSD-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32015|Desc=@FirewallAPI.dll,-32018|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-PNRP-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-32019|Desc=@FirewallAPI.dll,-32022|EmbedCtxt=@FirewallAPI.dll,-32002|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-PNRP-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-32023|Desc=@FirewallAPI.dll,-32026|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-PNRP-SSDPSrv-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32027|Desc=@FirewallAPI.dll,-32030|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Collab-PNRP-SSDPSrv-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32031|Desc=@FirewallAPI.dll,-32034|EmbedCtxt=@FirewallAPI.dll,-32002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="DIAL-Protocol-Server-In-TCP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=10247|App=System|Name=@FirewallAPI.dll,-37102|Desc=@FirewallAPI.dll,-37103|EmbedCtxt=@FirewallAPI.dll,-37101|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="DIAL-Protocol-Server-HTTPSTR-In-TCP-LocalSubnetScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=10247|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-37102|Desc=@FirewallAPI.dll,-37103|EmbedCtxt=@FirewallAPI.dll,-37101|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=Eventlog|Name=@FirewallAPI.dll,-29253|Desc=@FirewallAPI.dll,-29256|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-NP-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-29257|Desc=@FirewallAPI.dll,-29260|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29265|Desc=@FirewallAPI.dll,-29268|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Eventlog|Name=@FirewallAPI.dll,-29253|Desc=@FirewallAPI.dll,-29256|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-NP-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-29257|Desc=@FirewallAPI.dll,-29260|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteEventLogSvc-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29265|Desc=@FirewallAPI.dll,-29268|EmbedCtxt=@FirewallAPI.dll,-29252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-HTTPSTR-In-TCP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=10246|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-HTTPSTR-In-TCP-LocalSubnetScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=10246|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-HTTPSTR-In-TCP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=10246|RA42=Ply2Renders|RA62=Ply2Renders|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-UDP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-UDP-LocalSubnetScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-UDP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Public|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-Out-UDP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36006|Desc=@FirewallAPI.dll,-36007|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-Out-UDP-LocalSubnetScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36006|Desc=@FirewallAPI.dll,-36007|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-Out-UDP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36006|Desc=@FirewallAPI.dll,-36007|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-RTSP-NoScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=23554|LPort=23555|LPort=23556|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36008|Desc=@FirewallAPI.dll,-36009|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-RTSP-LocalSubnetScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|LPort=23554|LPort=23555|LPort=23556|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36008|Desc=@FirewallAPI.dll,-36009|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-In-RTSP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=23554|LPort=23555|LPort=23556|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36008|Desc=@FirewallAPI.dll,-36009|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-SSDP-Discovery-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort2_20=Ply2Disc|App=%SystemRoot%\\system32\\svchost.exe|Svc=ssdpsrv|Name=@FirewallAPI.dll,-36104|Desc=@FirewallAPI.dll,-36105|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-UPnP-Events-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=2869|RA42=Ply2Renders|RA62=Ply2Renders|App=System|Name=@FirewallAPI.dll,-36106|Desc=@FirewallAPI.dll,-36107|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-QWave-In-UDP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36010|Desc=@FirewallAPI.dll,-36011|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-QWave-Out-UDP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|Profile=Public|RPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36012|Desc=@FirewallAPI.dll,-36013|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-QWave-In-TCP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36014|Desc=@FirewallAPI.dll,-36015|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PlayTo-QWave-Out-TCP-PlayToScope"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36016|Desc=@FirewallAPI.dll,-36017|EmbedCtxt=@FirewallAPI.dll,-36001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-DAFWSD-In-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Profile=Public|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-36852|Desc=@FirewallAPI.dll,-36853|LUAuth=O:LSD:(A;;CC;;;S-1-5-92-3339056971-1291069075-3798698925-2882100687-0)|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-DAFWSD-Out-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Profile=Public|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-36854|Desc=@FirewallAPI.dll,-36855|LUAuth=O:LSD:(A;;CC;;;S-1-5-92-3339056971-1291069075-3798698925-2882100687-0)|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-SPOOL-In-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Profile=Public|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-36856|Desc=@FirewallAPI.dll,-36857|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-SPOOL-Out-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Profile=Public|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-36858|Desc=@FirewallAPI.dll,-36859|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-SCAN-In-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=stisvc|Name=@FirewallAPI.dll,-36860|Desc=@FirewallAPI.dll,-36861|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WFDPRINT-SCAN-Out-Active"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=stisvc|Name=@FirewallAPI.dll,-36862|Desc=@FirewallAPI.dll,-36863|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-GRE-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=47|App=System|Name=@FirewallAPI.dll,-33769|Desc=@FirewallAPI.dll,-33772|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-GRE-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=47|App=System|Name=@FirewallAPI.dll,-33773|Desc=@FirewallAPI.dll,-33776|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-L2TP-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1701|App=System|Name=@FirewallAPI.dll,-33753|Desc=@FirewallAPI.dll,-33756|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-L2TP-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1701|App=System|Name=@FirewallAPI.dll,-33757|Desc=@FirewallAPI.dll,-33760|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-PPTP-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=1723|App=System|Name=@FirewallAPI.dll,-33765|Desc=@FirewallAPI.dll,-33768|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RRAS-PPTP-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=1723|App=System|Name=@FirewallAPI.dll,-33761|Desc=@FirewallAPI.dll,-33764|EmbedCtxt=@FirewallAPI.dll,-33752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-WLANSvc-ASP-CP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|LPort=7235|RPort=7235|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=WlanSvc|Name=@wlansvc.dll,-37376|Desc=@wlansvc.dll,-37888|EmbedCtxt=@wlansvc.dll,-36864|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-WLANSvc-ASP-CP-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|LPort=7235|RPort=7235|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=WlanSvc|Name=@wlansvc.dll,-37377|Desc=@wlansvc.dll,-37889|EmbedCtxt=@wlansvc.dll,-36864|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\services.exe|Name=@FirewallAPI.dll,-29503|Desc=@FirewallAPI.dll,-29506|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-NP-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-29507|Desc=@FirewallAPI.dll,-29510|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29515|Desc=@FirewallAPI.dll,-29518|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\services.exe|Name=@FirewallAPI.dll,-29503|Desc=@FirewallAPI.dll,-29506|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-NP-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-29507|Desc=@FirewallAPI.dll,-29510|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteSvcAdmin-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29515|Desc=@FirewallAPI.dll,-29518|EmbedCtxt=@FirewallAPI.dll,-29502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PerfLogsAlerts-PLASrv-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\plasrv.exe|Name=@FirewallAPI.dll,-34753|Desc=@FirewallAPI.dll,-34754|EmbedCtxt=@FirewallAPI.dll,-34752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PerfLogsAlerts-DCOM-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=135|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34755|Desc=@FirewallAPI.dll,-34756|EmbedCtxt=@FirewallAPI.dll,-34752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PerfLogsAlerts-PLASrv-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%systemroot%\\system32\\plasrv.exe|Name=@FirewallAPI.dll,-34753|Desc=@FirewallAPI.dll,-34754|EmbedCtxt=@FirewallAPI.dll,-34752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="PerfLogsAlerts-DCOM-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%systemroot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34755|Desc=@FirewallAPI.dll,-34756|EmbedCtxt=@FirewallAPI.dll,-34752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-DU-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=1:*|App=System|Name=@FirewallAPI.dll,-25110|Desc=@FirewallAPI.dll,-25112|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-PTB-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=2:*|Name=@FirewallAPI.dll,-25001|Desc=@FirewallAPI.dll,-25007|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-PTB-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=2:*|Name=@FirewallAPI.dll,-25002|Desc=@FirewallAPI.dll,-25007|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-TE-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=3:*|App=System|Name=@FirewallAPI.dll,-25113|Desc=@FirewallAPI.dll,-25115|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-TE-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=3:*|Name=@FirewallAPI.dll,-25114|Desc=@FirewallAPI.dll,-25115|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-PP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=4:*|App=System|Name=@FirewallAPI.dll,-25116|Desc=@FirewallAPI.dll,-25118|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-PP-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=4:*|Name=@FirewallAPI.dll,-25117|Desc=@FirewallAPI.dll,-25118|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-NDS-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=135:*|App=System|Name=@FirewallAPI.dll,-25019|Desc=@FirewallAPI.dll,-25025|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-NDS-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=135:*|Name=@FirewallAPI.dll,-25020|Desc=@FirewallAPI.dll,-25025|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-NDA-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=136:*|App=System|Name=@FirewallAPI.dll,-25026|Desc=@FirewallAPI.dll,-25032|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-NDA-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=136:*|Name=@FirewallAPI.dll,-25027|Desc=@FirewallAPI.dll,-25032|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-RA-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=134:*|RA6=fe80::/64|App=System|Name=@FirewallAPI.dll,-25012|Desc=@FirewallAPI.dll,-25018|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-RA-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=134:*|LA6=fe80::/64|RA4=LocalSubnet|RA6=LocalSubnet|RA6=ff02::1|RA6=fe80::/64|Name=@FirewallAPI.dll,-25013|Desc=@FirewallAPI.dll,-25018|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-RS-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=133:*|App=System|Name=@FirewallAPI.dll,-25009|Desc=@FirewallAPI.dll,-25011|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-RS-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=133:*|RA4=LocalSubnet|RA6=LocalSubnet|RA6=ff02::2|RA6=fe80::/64|Name=@FirewallAPI.dll,-25008|Desc=@FirewallAPI.dll,-25011|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LQ-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=130:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25061|Desc=@FirewallAPI.dll,-25067|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LQ-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=130:*|RA4=LocalSubnet|RA6=LocalSubnet|Name=@FirewallAPI.dll,-25062|Desc=@FirewallAPI.dll,-25067|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LR-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=131:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25068|Desc=@FirewallAPI.dll,-25074|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LR-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=131:*|RA4=LocalSubnet|RA6=LocalSubnet|Name=@FirewallAPI.dll,-25069|Desc=@FirewallAPI.dll,-25074|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LR2-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=143:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25075|Desc=@FirewallAPI.dll,-25081|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LR2-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=143:*|RA4=LocalSubnet|RA6=LocalSubnet|Name=@FirewallAPI.dll,-25076|Desc=@FirewallAPI.dll,-25081|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LD-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=58|ICMP6=132:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25082|Desc=@FirewallAPI.dll,-25088|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP6-LD-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=58|ICMP6=132:*|RA4=LocalSubnet|RA6=LocalSubnet|Name=@FirewallAPI.dll,-25083|Desc=@FirewallAPI.dll,-25088|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-ICMP4-DUFRAG-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=1|ICMP4=3:4|App=System|Name=@FirewallAPI.dll,-25251|Desc=@FirewallAPI.dll,-25257|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IGMP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=2|App=System|Name=@FirewallAPI.dll,-25376|Desc=@FirewallAPI.dll,-25382|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IGMP-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=2|App=System|Name=@FirewallAPI.dll,-25377|Desc=@FirewallAPI.dll,-25382|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-DHCP-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|LPort=68|RPort=67|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25301|Desc=@FirewallAPI.dll,-25303|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-DHCP-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|LPort=68|RPort=67|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25302|Desc=@FirewallAPI.dll,-25303|EmbedCtxt=@FirewallAPI.dll,-25000|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-DHCPV6-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|LPort=546|RPort=547|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25304|Desc=@FirewallAPI.dll,-25306|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-DHCPV6-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|LPort=546|RPort=547|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25305|Desc=@FirewallAPI.dll,-25306|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-Teredo-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|LPort=Teredo|App=%SystemRoot%\\system32\\svchost.exe|Svc=iphlpsvc|Name=@FirewallAPI.dll,-25326|Desc=@FirewallAPI.dll,-25332|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-Teredo-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|App=%SystemRoot%\\system32\\svchost.exe|Svc=iphlpsvc|Name=@FirewallAPI.dll,-25327|Desc=@FirewallAPI.dll,-25333|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IPHTTPS-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=6|LPort2_10=IPTLSIn|LPort2_10=IPHTTPSIn|App=System|Name=@FirewallAPI.dll,-25426|Desc=@FirewallAPI.dll,-25428|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IPHTTPS-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|RPort2_10=IPTLSOut|RPort2_10=IPHTTPSOut|App=%SystemRoot%\\system32\\svchost.exe|Svc=iphlpsvc|Name=@FirewallAPI.dll,-25427|Desc=@FirewallAPI.dll,-25429|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IPv6-In"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=41|App=System|Name=@FirewallAPI.dll,-25351|Desc=@FirewallAPI.dll,-25357|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-IPv6-Out"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=41|App=System|Name=@FirewallAPI.dll,-25352|Desc=@FirewallAPI.dll,-25358|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-GP-NP-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=445|App=System|Name=@FirewallAPI.dll,-25401|Desc=@FirewallAPI.dll,-25401|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-GP-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Name=@FirewallAPI.dll,-25403|Desc=@FirewallAPI.dll,-25404|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-DNS-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=53|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-25405|Desc=@FirewallAPI.dll,-25406|EmbedCtxt=@FirewallAPI.dll,-25000|Security=AuthenticateEncrypt|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CoreNet-GP-LSASS-Out-TCP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\lsass.exe|Name=@FirewallAPI.dll,-25407|Desc=@FirewallAPI.dll,-25408|EmbedCtxt=@FirewallAPI.dll,-25000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="CDPSvc-In-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=CDPSvc|Name=@FirewallAPI.dll,-37007|Desc=@FirewallAPI.dll,-37008|EmbedCtxt=@FirewallAPI.dll,-37002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WINRM-HTTP-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=5985|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WINRM-HTTP-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5985|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WINRM-HTTP-Compat-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=80|App=System|Name=@FirewallAPI.dll,-35001|Desc=@FirewallAPI.dll,-35002|EmbedCtxt=@FirewallAPI.dll,-30252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WINRM-HTTP-Compat-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=80|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-35001|Desc=@FirewallAPI.dll,-35002|EmbedCtxt=@FirewallAPI.dll,-30252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-VDS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\vds.exe|Svc=vds|Name=@FirewallAPI.dll,-34502|Desc=@FirewallAPI.dll,-34503|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-VDSLDR-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\vdsldr.exe|Name=@FirewallAPI.dll,-34504|Desc=@FirewallAPI.dll,-34505|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-34506|Desc=@FirewallAPI.dll,-34507|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-VDS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\vds.exe|Svc=vds|Name=@FirewallAPI.dll,-34502|Desc=@FirewallAPI.dll,-34503|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-VDSLDR-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\vdsldr.exe|Name=@FirewallAPI.dll,-34504|Desc=@FirewallAPI.dll,-34505|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RVM-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-34506|Desc=@FirewallAPI.dll,-34507|EmbedCtxt=@FirewallAPI.dll,-34501|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteTask-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=schedule|Name=@FirewallAPI.dll,-33253|Desc=@FirewallAPI.dll,-33256|EmbedCtxt=@FirewallAPI.dll,-33252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteTask-RPCSS-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33257|Desc=@FirewallAPI.dll,-33260|EmbedCtxt=@FirewallAPI.dll,-33252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteTask-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=schedule|Name=@FirewallAPI.dll,-33253|Desc=@FirewallAPI.dll,-33256|EmbedCtxt=@FirewallAPI.dll,-33252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteTask-RPCSS-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33257|Desc=@FirewallAPI.dll,-33260|EmbedCtxt=@FirewallAPI.dll,-33252|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MDNS-In-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=In|Protocol=17|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37303|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37304|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MDNS-Out-UDP"
$String="v2.27|Action=Block|Active=FALSE|Dir=Out|Protocol=17|LPort=5353|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37305|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37306|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-HttpTrans-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=80|App=SYSTEM|Name=@peerdistsh.dll,-10000|Desc=@peerdistsh.dll,-11000|EmbedCtxt=@peerdistsh.dll,-9000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-HttpTrans-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=80|App=SYSTEM|Name=@peerdistsh.dll,-10001|Desc=@peerdistsh.dll,-11001|EmbedCtxt=@peerdistsh.dll,-9000|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-WSD-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=PeerDistSvc|Name=@peerdistsh.dll,-10002|Desc=@peerdistsh.dll,-11002|EmbedCtxt=@peerdistsh.dll,-9001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-WSD-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=PeerDistSvc|Name=@peerdistsh.dll,-10003|Desc=@peerdistsh.dll,-11003|EmbedCtxt=@peerdistsh.dll,-9001|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-HostedServer-In"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=80|LPort=443|App=SYSTEM|Name=@peerdistsh.dll,-10004|Desc=@peerdistsh.dll,-11004|EmbedCtxt=@peerdistsh.dll,-9002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-HostedServer-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|LPort=80|LPort=443|App=SYSTEM|Name=@peerdistsh.dll,-10005|Desc=@peerdistsh.dll,-11005|EmbedCtxt=@peerdistsh.dll,-9002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="Microsoft-Windows-PeerDist-HostedClient-Out"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=80|RPort=443|App=SYSTEM|Name=@peerdistsh.dll,-10006|Desc=@peerdistsh.dll,-11006|EmbedCtxt=@peerdistsh.dll,-9003|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-SSDPSrv-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30753|Desc=@FirewallAPI.dll,-30756|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-SSDPSrv-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30757|Desc=@FirewallAPI.dll,-30760|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=554|LPort=8554|LPort=8555|LPort=8556|LPort=8557|LPort=8558|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30761|Desc=@FirewallAPI.dll,-30764|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30765|Desc=@FirewallAPI.dll,-30768|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-QWave-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30769|Desc=@FirewallAPI.dll,-30772|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-QWave-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30773|Desc=@FirewallAPI.dll,-30776|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-QWave-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30777|Desc=@FirewallAPI.dll,-30780|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-QWave-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30781|Desc=@FirewallAPI.dll,-30784|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-HTTPSTR-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=10244|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30785|Desc=@FirewallAPI.dll,-30788|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-TERMSRV-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=3390|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-30793|Desc=@FirewallAPI.dll,-30796|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=7777|LPort=7778|LPort=7779|LPort=7780|LPort=7781|LPort=5004|LPort=5005|LPort=50004|LPort=50005|LPort=50006|LPort=50007|LPort=50008|LPort=50009|LPort=50010|LPort=50011|LPort=50012|LPort=50013|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30801|Desc=@FirewallAPI.dll,-30804|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30805|Desc=@FirewallAPI.dll,-30808|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-MCX2SVC-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=mcx2svc|Name=@FirewallAPI.dll,-30810|Desc=@FirewallAPI.dll,-30811|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-Prov-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\ehome\\mcx2prov.exe|Name=@FirewallAPI.dll,-30812|Desc=@FirewallAPI.dll,-30813|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-PlayTo-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30814|Desc=@FirewallAPI.dll,-30815|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-PlayTo-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-30816|Desc=@FirewallAPI.dll,-30817|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-McrMgr-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\ehome\\mcrmgr.exe|Name=@FirewallAPI.dll,-30818|Desc=@FirewallAPI.dll,-30819|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-PlayTo-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30820|Desc=@FirewallAPI.dll,-30821|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="MCX-FDPHost-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-30822|Desc=@FirewallAPI.dll,-30823|EmbedCtxt=@FirewallAPI.dll,-30752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SPPSVC-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=1688|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\sppextcomobj.exe|Svc=sppsvc|Name=@FirewallAPI.dll,-28003|Desc=@FirewallAPI.dll,-28006|EmbedCtxt=@FirewallAPI.dll,-28002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="SPPSVC-In-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=1688|App=%SystemRoot%\\system32\\sppextcomobj.exe|Svc=sppsvc|Name=@FirewallAPI.dll,-28003|Desc=@FirewallAPI.dll,-28006|EmbedCtxt=@FirewallAPI.dll,-28002|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-Out-TCP-NoScope"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=15740|App=%SystemRoot%\\system32\\wudfhost.exe|Name=@FirewallAPI.dll,-30503|Desc=@FirewallAPI.dll,-30506|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=15740|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\wudfhost.exe|Name=@FirewallAPI.dll,-30503|Desc=@FirewallAPI.dll,-30506|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-SSDPSrv-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30507|Desc=@FirewallAPI.dll,-30510|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-SSDPSrv-Out-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30511|Desc=@FirewallAPI.dll,-30514|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-UPnPHost-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30515|Desc=@FirewallAPI.dll,-30518|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-UPnPHost-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-30519|Desc=@FirewallAPI.dll,-30522|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="WPDMTP-UPnP-Out-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-30523|Desc=@FirewallAPI.dll,-30524|EmbedCtxt=@FirewallAPI.dll,-30502|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteDesktop-UserMode-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=3389|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteDesktop-UserMode-In-UDP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3389|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28776|Desc=@FirewallAPI.dll,-28777|EmbedCtxt=@FirewallAPI.dll,-28752|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

$Wert="RemoteDesktop-Shadow-In-TCP"
$String="v2.27|Action=Allow|Active=FALSE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\RdpSa.exe|Name=@FirewallAPI.dll,-28778|Desc=@FirewallAPI.dll,-28779|EmbedCtxt=@FirewallAPI.dll,-28752|Edge=TRUE|Defer=App|"
$Path="HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
Write-Host "SharedAccess ($Wert) wird NEU gesetzt" -f Green
echo "SharedAccess ($Wert) wird NEU gesetzt" >> $install\FuckYouBillyBoy.log
mkdirpath-force $Path
If (-Not (Test-Path $Path\$Wert)) {
    New-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force
}
Set-ItemProperty -Path $Path -Name $Wert -Type String -Value $String -Force

Write-Host "FirewallRules erfolgreich entfernt, CustomRules und die alten Windows Standardregeln als deaktivierte Restriktivregeln neu angelegt. Reboot sinnvoll!" -f Green

echo "FirewallRules erfolgreich entfernt, CustomRules und die alten Windows Standardregeln als deaktivierte Restriktivregeln neu angelegt. Reboot sinnvoll!" >> $install\FuckYouBillyBoy.log

...