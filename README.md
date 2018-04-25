# Deauth and Man in the Middle (MitM) Logger

Python    Version: 2.7

Purpose: This program uses a wireless adapter to spoof a wireless network, then search the actual network for MAC 
addresses on the network. The user can then pick one of these MAC addresses, and send deauth packets to the network to 
kick the target off. Deauth packets will continually get sent until the target gets kicked off and reconnected through 
the spoofed network. Once the user connected to the spoofed network, all traffic will be logged by the attacker and 
network traffic will be routed through it.

Usage:    python deauth.py -i \<network interface>

Notes:    The network interface need to be set to monitor mode before running. This can be done with airmon-ng.

### Resources
* http://www.bitforestinfo.com/2017/06/how-to-create-and-send-wireless-deauthentication-packets-using-python-and-scapy.html
* https://thepacketgeek.com/scapy-sniffing-with-custom-actions-part-1/
* https://raidersec.blogspot.com/2013/01/wireless-deauth-attack-using-aireplay.html
* https://github.com/veerendra2/wifi-deauth-attack
* https://en.wikipedia.org/wiki/IEEE_802.11w-2009
* https://www.androidauthority.com/capture-data-open-wi-fi-726356/