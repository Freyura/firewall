#!/usr/bin/env bash
# -*- coding: utf-8 -*-

if [[ "$(id -u)" != "0" ]]; then echo "Must be run with sudo." ; exit 1 ; fi

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
$IPT6 -A INPUT -i lo -j ACCEPT

# Accept icmp.
$IPT -A INPUT -p icmp -m limit --limit 5/second -j ACCEPT

$IPT6 -A INPUT -p icmpv6 -m limit --limit 5/second -j ACCEPT

# Accepting random traffic

# Tor
$IPT -A INPUT -p tcp --dport 443 -j ACCEPT
$IPT -A INPUT -p tcp --dport 80 -j ACCEPT

# Tor is not active over ipv6 these rules should do nothing
$IPT6 -A INPUT -p tcp --dport 443 -j ACCEPT
$IPT6 -A INPUT -p tcp --dport 80 -j ACCEPT

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
$IPT -A OUTPUT -p udp --dport 53 -j ACCEPT
$IPT -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT
$IPT -A OUTPUT -p tcp -m limit --limit 5/second -j ACCEPT
$IPT -A OUTPUT -p udp -m limit --limit 5/second -j ACCEPT
$IPT -A OUTPUT -p icmp -m limit --limit 5/second -j ACCEPT
$IPT -A OUTPUT -j rejected

$IPT6 -A OUTPUT -m conntrack --ctstate INVALID -j REJECT
$IPT6 -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$IPT6 -A OUTPUT -m owner --uid-owner 108 -j ACCEPT
$IPT6 -A OUTPUT -m owner --uid-owner 109 -j ACCEPT
$IPT6 -A OUTPUT -d ::1 -o lo -j ACCEPT
$IPT6 -A OUTPUT -p tcp -m limit --limit 5/second -j ACCEPT
$IPT6 -A OUTPUT -p udp -m limit --limit 5/second -j ACCEPT
$IPT6 -A OUTPUT -p icmpv6 -m limit --limit 5/second -j ACCEPT
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
