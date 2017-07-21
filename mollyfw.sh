#!/usr/bin/env bash
# -*- coding: utf-8 -*-

if [[ "$(id -u)" != "0" ]]; then echo "Must be run with sudo." ; exit 1 ; fi

#EXIT_IPS=$(wget --no-check-certificate --force-html -qO- https://check.torproject.org/exit-addresses | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')

# Not playing nice: blocking most IPv6 traffic

# The location of the IPtables binary file on your system.
IPT="/sbin/iptables"
IPT6="/sbin/ip6tables"

# The following rules will clear out any existing firewall rules,
# and any chains that might have been created.
$IPT -P INPUT ACCEPT
$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD ACCEPT

$IPT6 -P INPUT ACCEPT
$IPT6 -P OUTPUT ACCEPT
$IPT6 -P FORWARD ACCEPT

$IPT -F
$IPT -F INPUT
$IPT -F OUTPUT
$IPT -F FORWARD
$IPT -F -t mangle
$IPT -F -t nat
$IPT -X

$IPT6 -F
$IPT6 -F INPUT
$IPT6 -F OUTPUT
$IPT6 -F FORWARD
$IPT6 -F -t mangle
$IPT6 -F -t nat
$IPT6 -X

# INPUT

# Now, our rejected chain, for the final catchall filter.
$IPT -N rejected
#$IPT -A rejected -p tcp -j REJECT --reject-with tcp-reset
#$IPT -A rejected -p udp -j REJECT --reject-with icmp-port-unreachable
$IPT -A rejected -m limit --limit 15/minute -j LOG --log-prefix "blocked_ipv4: "
$IPT -A rejected -j REJECT

# Drop those nasty packets!
$IPT -A INPUT -m conntrack --ctstate INVALID -j REJECT
$IPT6 -A INPUT -m conntrack --ctstate INVALID -j REJECT

# Lets do some basic state-matching. This allows us
# to accept related and established connections, so
# client-side things like ftp work properly, for example.
$IPT -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

$IPT6 -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# This rule will accept connections from local machines.
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A INPUT -s 80.101.137.223 -j ACCEPT
#$IPT -A INPUT -s 169.47.63.74 -j ACCEPT #WCG
$IPT6 -A INPUT -i lo -j ACCEPT

# Accept some icmp.
#for icmptype in 3 4 11 0 8 ; do
#  $IPT -A INPUT -p icmp -m limit --limit 5/second -m icmp --icmp-type $icmptype -j ACCEPT
#done
$IPT -A INPUT -p icmp -m limit --limit 10/second -j ACCEPT

#for icmptype in 1 3 128 129 ; do
#  $IPT6 -A INPUT -p icmpv6 -m icmp6 --icmpv6-type $icmptype -j ACCEPT
#done
#for ndptype in 134 135 136 138 ; do
#  $IPT6 -A INPUT -p icmpv6 -m icmp6 --icmpv6-type $ndptype -j ACCEPT
#done
#for sendtype in 148 149 ; do
#  $IPT6 -A INPUT -p icmpv6 -m icmp6 --icmpv6-type $sendtype -j ACCEPT
#done
$IPT6 -A INPUT -p icmpv6 -m limit --limit 10/second -j ACCEPT

# Accepting random traffic

# Tor
$IPT -A INPUT -m conntrack --ctstate NEW -m tcp -p tcp --dport 443 -j ACCEPT
$IPT -A INPUT -m conntrack --ctstate NEW -m tcp -p tcp --dport 80 -j ACCEPT

# Tor is not active over ipv6 these rules should do nothing
$IPT6 -A INPUT -m conntrack --ctstate NEW -m tcp -p tcp --dport 443 -j ACCEPT
$IPT6 -A INPUT -m conntrack --ctstate NEW -m tcp -p tcp --dport 80 -j ACCEPT

# Our final trap. Everything on INPUT goes to the rejected
# so we don't get silent drops.

$IPT -A INPUT -p tcp -j REJECT --reject-with tcp-reset
$IPT -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
$IPT -A INPUT -j rejected

$IPT6 -A INPUT -j REJECT

# OUTPUT
$IPT -A OUTPUT -m conntrack --ctstate INVALID -j REJECT
$IPT -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -m owner --uid-owner 108 -j ACCEPT
$IPT -A OUTPUT -m owner --uid-owner 109 -j ACCEPT
#$IPT -A OUTPUT -d 169.47.63.74 -j ACCEPT #WCG
#$IPT -A OUTPUT -m tcp -p tcp --tcp-flags ACK ACK -j ACCEPT
#$IPT -A OUTPUT -d 138.201.14.212 -j ACCEPT
#for exit_ip in $EXIT_IPS ; do
#    $IPT -A OUTPUT -d $exit_ip -j ACCEPT
#done


$IPT -A OUTPUT -p udp --dport 53 -j ACCEPT
$IPT -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT
#for icmptype in 3 4 11 0 8 ; do
# $IPT -A OUTPUT -p icmp -m limit --limit 5/second -m icmp --icmp-type $icmptype -j ACCEPT
#done
$IPT -A OUTPUT -p tcp -m limit --limit 5/second -j ACCEPT
$IPT -A OUTPUT -p udp -m limit --limit 5/second -j ACCEPT
$IPT -A OUTPUT -p icmp -m limit --limit 10/second -j ACCEPT
$IPT -A OUTPUT -j rejected

$IPT6 -A OUTPUT -m conntrack --ctstate INVALID -j REJECT
#for icmptype in 1 3 128 129 ; do
# $IPT6 -A OUTPUT -p icmpv6 -m icmp6 --icmpv6-type $icmptype -j ACCEPT
#done
#for ndptype in 134 135 136 138 ; do
#  $IPT6 -A OUTPUT -p icmpv6 -m icmp6 --icmpv6-type $ndptype -j ACCEPT
#done
#for sendtype in 148 149 ; do
#  $IPT6 -A OUTPUT -p icmpv6 -m icmp6 --icmpv6-type $sendtype -j ACCEPT
#done
$IPT6 -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$IPT6 -A OUTPUT -m owner --uid-owner 108 -j ACCEPT
$IPT6 -A OUTPUT -m owner --uid-owner 109 -j ACCEPT
$IPT6 -A OUTPUT -d ::1 -o lo -j ACCEPT
$IPT6 -A OUTPUT -p tcp -m limit --limit 5/second -j ACCEPT
$IPT6 -A OUTPUT -p udp -m limit --limit 5/second -j ACCEPT
$IPT6 -A OUTPUT -p icmpv6 -m limit --limit 10/second -j ACCEPT
$IPT6 -A OUTPUT -j REJECT

# These will setup our policies.
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

$IPT6 -P INPUT DROP
$IPT6 -P OUTPUT DROP
$IPT6 -P FORWARD DROP

# Make firewall rules persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
