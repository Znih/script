#!/bin/bash -x

### BEGIN INIT INFO
# Provides:           firewall
# Required-Start:     $network $remote_fs $syslog
# Required-Stop:      $network $remote_fs $syslog
# Default-Start:      2 3 4 5
# Default-Stop:
# Short-Description:  Start firewall daemon
### END INIT INFO

#=============================================================================
#
#         FILE: firewall
#        USAGE: firewall [start] [stop] [restart] [reload] [force-reload]
#  DESCRIPTION: EBTables / IPTables Basis-Rules
#
#       OPTION: START/STOP/RESTART/RELOAD/FORCE-RELOAD (see USAGE)
# REQUIREMENTS: ---
#         BUGS: 
#        NOTES: insserv firewall und insserv -r firewall (res. update-rc.d)
#       AUTHOR: Marco Hinz
#      COMPANY: Justice
#      VERSION: 1.5
#      CREATED: 25.09.2009 - 22:10
#     REVISION: 27.06.2013, 19.09.2014, 10.10.2014, 21.02.2015, 21.03.2015
#=============================================================================

# Load necessary kernel modules
modprobe ip_tables
modprobe iptable_filter
modprobe ipt_REJECT
modprobe ipt_state
modprobe ip_conntrack

# Enable IP forwarding and other kernel settings
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

#=============================================================================
# Declaration
#=============================================================================
IPT=/sbin/iptables
EBT=/sbin/ebtables
IFC=/sbin/ifconfig
BRCTL=/usr/sbin/brctl
ROUTE=/sbin/route
echo ""

#=============================================================================
# NICs
#=============================================================================
int_if="eth0"
ext_if="eth1"
#dmz_if="eth2"

bridge_if="br0"
bridge_if_2="br1"

#=============================================================================
# IPs
#=============================================================================
lan=""
remote_ip=""
gateway_ip=""
SERVER="$(cat /etc/pfad-to-list/liste | grep -v -E "^#")"
echo "Server reading...OK"

#=============================================================================
# Firewall Start...
#=============================================================================
case "$1" in
start|restart|reload|force-reload)
echo "Firewallstart..."
echo ""

#=============================================================================
# Establish chains
#=============================================================================
$IPT -N logdrop
$IPT -N notsyndrop
$IPT -N syn-flood
$IPT -N portscan
$IPT -N suspect
$IPT -N xmas
$IPT -N null
echo "Chains established"
echo "--------------------------------"

#=============================================================================
# Flush chains
#=============================================================================
$IPT -F INPUT
$IPT -F OUTPUT
$IPT -F FORWARD
$IPT -t nat -F PREROUTING
$IPT -t nat -F POSTROUTING
$IPT -t nat -F OUTPUT
$IPT -F logdrop
$IPT -F notsyndrop
$IPT -F syn-flood
$IPT -F portscan
$IPT -F suspect
$IPT -F xmas
$IPT -F null
echo "Chains flushed"
echo "--------------------------------"

#=============================================================================
# Charge chains
#=============================================================================
$IPT -A logdrop -j LOG -m limit --limit 6/minute --log-prefix "LOGDROP: "
$IPT -A logdrop -j DROP
$IPT -A notsyndrop -j LOG -m limit --limit 6/minute --log-prefix "!SYNDROP: "
$IPT -A notsyndrop -j DROP
$IPT -A syn-flood -m limit --limit 1/s --limit-burst 4 -j RETURN
$IPT -A syn-flood -j LOG -m limit --limit 6/minute --log-prefix "SYN-FLOOD DROP: "
$IPT -A syn-flood -j DROP
$IPT -A portscan -m limit --limit 1/s --limit-burst 2 -j RETURN
$IPT -A portscan -j LOG -m limit --limit 6/minute --log-prefix "Portscan DROP: "
$IPT -A portscan -j DROP
$IPT -A suspect -j LOG -m limit --limit 6/minute --log-prefix "Suspect-Frame DROP: "
$IPT -A suspect -j DROP
$IPT -A xmas -j LOG -m limit --limit 6/minute --log-prefix "XMAS-Frame DROP: "
$IPT -A xmas -j DROP
$IPT -A null -j LOG -m limit --limit 6/minute --log-prefix "NULL-Frame DROP: "
$IPT -A null -j DROP
echo "Chains charged"
echo "--------------------------------"

#=============================================================================
# Default-Policy IPTables Rules
#=============================================================================
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP
$IPT -A FORWARD -s 0.0.0.0/0.0.0.0 -d 0.0.0.0/0.0.0.0 -m state --state INVALID -j DROP
$IPT -t nat -P PREROUTING ACCEPT
$IPT -t nat -P POSTROUTING ACCEPT
$IPT -t nat -P OUTPUT ACCEPT
echo "Default-Policy composed"

#=============================================================================
# Default-Policy EBTables Rules
#=============================================================================
$EBT -P FORWARD DROP
$EBT -A FORWARD -p IPv4 -j ACCEPT
$EBT -A FORWARD -p ARP -j ACCEPT
$EBT -A FORWARD -p LENGTH -j ACCEPT
$EBT -P INPUT DROP
$EBT -A INPUT -p IPv4 -j ACCEPT
$EBT -A INPUT -p ARP -j ACCEPT
$EBT -A INPUT -p LENGTH -j ACCEPT
$EBT -P OUTPUT DROP
$EBT -A OUTPUT -p IPv4 -j ACCEPT
$EBT -A OUTPUT -p ARP -j ACCEPT
$EBT -A OUTPUT -p LENGTH -j ACCEPT
echo "Default-Policy composed"

#=============================================================================
# Loopback-Device Rules
#=============================================================================
$IPT -A INPUT -i lo -s 127.0.0.1 -j ACCEPT
$IPT -A OUTPUT -o lo -s 127.0.0.1 -j ACCEPT
echo "Rule 1 composed"

#=============================================================================
# Connection-Tracking Rules
#=============================================================================
$IPT -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
echo "Rule 3 composed"

#=============================================================================
# ACK-Tunneling-DROP Rule
#=============================================================================
$IPT -A FORWARD -p tcp ! --syn -m state --state NEW -j notsyndrop
echo "Rule 6 composed"

#=============================================================================
# Simple Portscan Rules
#=============================================================================
$IPT -A FORWARD -p tcp --dport 21 --syn -j portscan
$IPT -A FORWARD -p tcp --dport 22 --syn -j portscan
$IPT -A FORWARD -p tcp --dport 23 --syn -j portscan
$IPT -A FORWARD -p tcp --dport 25 --syn -j portscan
echo "Rule 7 composed"

#=============================================================================
# Simple SYN-Flood Rules
#=============================================================================
$IPT -A FORWARD -p tcp --dport 21 --syn -j syn-flood
$IPT -A FORWARD -p tcp --dport 22 --syn -j syn-flood
$IPT -A FORWARD -p tcp --dport 23 --syn -j syn-flood
$IPT -A FORWARD -p tcp --dport 25 --syn -j syn-flood
echo "Rule 8 composed"

#=============================================================================
# Anti-Cast REJECT Rules
#=============================================================================
$IPT -A FORWARD -d 10.34.71.255 -j ACCEPT
$IPT -A INPUT -d 10.34.71.255 -j REJECT
# Ignoriere Limited Broadcast RFC 919 und RFC 922
$IPT -A FORWARD -d 255.255.255.255/32 -j REJECT
$IPT -A INPUT -d 255.255.255.255/32 -j REJECT
# Ignoriere Multicast RFC 3171
$IPT -A FORWARD -d 224.0.0.0/4 -j ACCEPT
$IPT -A INPUT -d 224.0.0.0/4 -j REJECT
# Ignoriere 240/4 RFC 1112
$IPT -A FORWARD -d 240.0.0.0/4 -j ACCEPT
$IPT -A INPUT -d 240.0.0.0/4 -j REJECT
echo "Rule 9 composed"

#=============================================================================
# Suspect-Frame-DROP Rules
#=============================================================================
$IPT -A FORWARD -p tcp --tcp-flags ALL FIN,URG,PSH -j suspect
$IPT -A FORWARD -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j suspect
$IPT -A FORWARD -p tcp --tcp-flags SYN,RST SYN,RST -j suspect
$IPT -A FORWARD -p tcp --tcp-flags FIN,RST FIN,RST -j suspect
$IPT -A FORWARD -p tcp --tcp-flags ACK,FIN FIN -j suspect
$IPT -A FORWARD -p tcp --tcp-flags ACK,PSH PSH -j suspect
$IPT -A FORWARD -p tcp --tcp-flags ACK,URG URG -j suspect
$IPT -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j suspect
echo "Rule 10 composed"

#=============================================================================
# XMAS-Frame-DROP Rule
#=============================================================================
$IPT -A FORWARD -p tcp --tcp-flags ALL ALL -j logdrop
echo "Rule 12 composed"

#=============================================================================
# NULL-Frame-DROP Rule
#=============================================================================
$IPT -A FORWARD -p tcp --tcp-flags ALL NONE -j logdrop
echo "Rule 13 composed"

#=============================================================================
# Telnet outbound accept (example)
#=============================================================================
if [ -n "$remote_ip" ]; then
    $IPT -A FORWARD -p tcp -s $remote_ip -d 0/0 --dport 23 -j ACCEPT
    echo "Rule 14 composed"
else
    echo "Remote IP not specified, skipping Rule 14"
fi

# Add your additional rules here

#=============================================================================
# ALL-DROP Rule
#=============================================================================
$IPT -A INPUT -j logdrop
$IPT -A FORWARD -j logdrop
$IPT -A OUTPUT -j LOG
$IPT -A OUTPUT -j REJECT

#=============================================================================
# Firewall Stop
#=============================================================================
exit 0
;;
stop)
$IPT -F logdrop
$IPT -F notsyndrop
$IPT -F syn-flood
$IPT -F portscan
$IPT -F suspect
$IPT -F xmas
$IPT -F null
$IPT -F INPUT
$IPT -F OUTPUT
$IPT -F FORWARD
$IPT -t nat -F PREROUTING
$IPT -t nat -F POSTROUTING
$IPT -t nat -F OUTPUT
$IPT -P INPUT ACCEPT
$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD ACCEPT
$IPT -X logdrop
$IPT -X notsyndrop
$IPT -X syn-flood
$IPT -X portscan
$IPT -X suspect
$IPT -X xmas
$IPT -X null
exit 0
;;
*)
echo "service firewall {start|stop|restart|reload|force-reload}"
echo ""
echo "~ start Firewall enabled, system safe ;-)"
echo "~ stop Firewall disabled, system unsafe :-(((("
echo ""
echo "Check Rules on PROMPT: iptables -vnL | less"
exit 1
;;
esac
