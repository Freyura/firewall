#!/usr/bin/env bash
# -*- coding: utf-8 -*-

if [[ "$(id -u)" != "0" ]]; then echo "Must be run with sudo." ; exit 1 ; fi

# The location of the $_ipt4 binary file on your system.
_ipt4="/sbin/iptables"
_ipt6="/sbin/ip6tables"

# These will setup our policies.
$_ipt4 -P INPUT ACCEPT
$_ipt4 -P OUTPUT ACCEPT
$_ipt4 -P FORWARD ACCEPT

$_ipt6 -P INPUT ACCEPT
$_ipt6 -P OUTPUT ACCEPT
$_ipt6 -P FORWARD ACCEPT

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
