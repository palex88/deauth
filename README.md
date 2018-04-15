# deauth.py

Python    Version: 2.7
Purpose:  This script is used to search out local networks, then send deauth packets to the network from a spoofed mac address. Deauth packets will, in theory, tell the wireless base station to drop the connetion to the spoofed host.

Usage:    python deauth.py -i <network interface>

Notes:    The network interface need to be set to monitor mode before running. This can be done with airmon-ng.

Resources:
* http://www.bitforestinfo.com/2017/06/how-to-create-and-send-wireless-deauthentication-packets-using-python-and-scapy.html
* https://thepacketgeek.com/scapy-sniffing-with-custom-actions-part-1/
* https://raidersec.blogspot.com/2013/01/wireless-deauth-attack-using-aireplay.html
* https://github.com/veerendra2/wifi-deauth-attack
* https://en.wikipedia.org/wiki/IEEE_802.11w-2009
* https://www.androidauthority.com/capture-data-open-wi-fi-726356/