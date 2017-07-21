#!/usr/bin/env bash
# -*- coding: utf-8 -*-

if [[ "$(id -u)" != "0" ]]; then echo "Must be run with sudo." ; exit 1 ; fi

# Wireless interface is transproxied
# Wired interface normal

# The script has no real IPv6 support

# For this to work you need the following in /etc/tor/torrc
# VirtualAddrNetworkIPv4 10.192.0.0/10
# AutomapHostsOnResolve 1
# TransPort 9040
# DNSPort 53

# The location of the $_ipt4 binary file on your system.
_ipt4="/sbin/iptables"
_ipt6="/sbin/ip6tables"

# Network interfaces
_wlan_if="wlp2s0"
_lan_if="enp1s0"

# The UID that Tor runs as (varies from system to system)
_tor_uid="debian-tor"
_ntp_uid="systemd-timesync"

# Tor's TransPort
_trans_port="9040"

# Tor's DNSPort
_dns_port="53"

# Tor's VirtualAddrNetworkIPv4
_virt_addr="10.192.0.0/10"

# LAN destinations that shouldn't be routed through Tor
# Check reserved block.
_non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

# Other IANA reserved blocks (These are not processed by tor and dropped by default)
_resv_iana="0.0.0.0/8 100.64.0.0/10 169.254.0.0/16 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/3"

# Setting up the firewall

# The following rules will clear out any existing firewall rules,
# and any chains that might have been created.
$_ipt4 -F
$_ipt4 -F INPUT
$_ipt4 -F OUTPUT
$_ipt4 -F FORWARD
$_ipt4 -F -t mangle
$_ipt4 -F -t nat
$_ipt4 -X

$_ipt6 -F
$_ipt6 -F INPUT
$_ipt6 -F OUTPUT
$_ipt6 -F FORWARD
$_ipt6 -F -t mangle
$_ipt6 -F -t nat
$_ipt6 -X

# These will setup our policies.
$_ipt4 -P INPUT DROP
$_ipt4 -P OUTPUT DROP
$_ipt4 -P FORWARD DROP

$_ipt6 -P INPUT DROP
$_ipt6 -P OUTPUT DROP
$_ipt6 -P FORWARD DROP


# CHAINS

# If out transproxy leaks we want to know
$_ipt4 -N proxy_leak
$_ipt4 -A proxy_leak -m limit --limit 15/minute -j LOG --log-prefix "proxy_leak: "
$_ipt4 -A proxy_leak -p tcp -j DROP
$_ipt4 -A proxy_leak -p udp -j DROP
$_ipt4 -A proxy_leak -j DROP

# To study other traffic
$_ipt4 -N study
$_ipt4 -A study -m limit --limit 15/minute -j LOG --log-prefix "study: "
$_ipt4 -A study -p tcp -j DROP
$_ipt4 -A study -p udp -j DROP
$_ipt4 -A study -j DROP


# NAT

# Nat .onion addresses
$_ipt4 -t nat -A OUTPUT -d $_virt_addr -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $_trans_port

# Nat dns requests to Tor
#$_ipt4 -t nat -A OUTPUT -o $_wlan_if -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports $_dns_port

# Don't nat the Tor process, the loopback, or the local network
$_ipt4 -t nat -A OUTPUT -m owner --uid-owner $_tor_uid -j RETURN
$_ipt4 -t nat -A OUTPUT -o lo -j RETURN

for _lan in $_non_tor; do
 $_ipt4 -t nat -A OUTPUT -d $_lan -j RETURN
done

for _iana in $_resv_iana; do
 $_ipt4 -t nat -A OUTPUT -d $_iana -j RETURN
done

# Redirect whatever fell thru to Tor's TransPort
$_ipt4 -t nat -A OUTPUT -o $_wlan_if -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $_trans_port


# INPUT

# Drop those nasty packets!
$_ipt4 -A INPUT -m conntrack --ctstate INVALID -j DROP
$_ipt6 -A INPUT -m conntrack --ctstate INVALID -j DROP

# Allow presumably safe packets
$_ipt4 -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
$_ipt4 -A INPUT -i lo -j ACCEPT
$_ipt6 -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
$_ipt6 -A INPUT -i lo -j ACCEPT
$_ipt4 -A INPUT -i $_lan_if -p icmp -j ACCEPT
$_ipt6 -A INPUT -i $_lan_if -p icmpv6 -j ACCEPT
#$_ipt4 -A INPUT -j study


# Reject all packets that reach this point
$_ipt4 -A INPUT -j DROP


# OUTPUT

# Drop those nasty packets!
$_ipt4 -A OUTPUT -m conntrack --ctstate INVALID -j DROP
$_ipt6 -A OUTPUT -m conntrack --ctstate INVALID -j DROP

# Allow Tor output
$_ipt4 -A OUTPUT -m owner --uid-owner $_tor_uid -j ACCEPT
$_ipt6 -A OUTPUT -m owner --uid-owner $_tor_uid -j ACCEPT

# Allow loopback output
$_ipt4 -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT
$_ipt6 -A OUTPUT -d ::1 -o lo -j ACCEPT

# Tor transproxy magic
$_ipt4 -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport $_trans_port --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT

# Allow access to lan hosts in $_non_tor
for _lan in $_non_tor; do
 $_ipt4 -A OUTPUT -d $_lan -j ACCEPT
done

# Reject all wlan packets that reach this point
$_ipt4 -A OUTPUT -o $_wlan_if -j proxy_leak

# Accept all lan packetst that reach this point
$_ipt4 -A OUTPUT -o $_lan_if -j ACCEPT
$_ipt6 -A OUTPUT -o $_lan_if -j ACCEPT

# Saving shit for later
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
