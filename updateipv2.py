#! /usr/bin/env python
# Script is searching the Prefix, update the Prefix VRF and scanning, updating and set VRF from IP addresses in netbox
# We need install pip3 install ipcalc networkscan python-netbox

import ipcalc
import networkscan
from netbox import NetBox
import requests
import datetime
import nmap3
import socket

# Set log level to benefit from Scapy warnings
import logging
logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)

from scapy.all import ARP, IP, Ether, srp, sr, ICMP

# Netbox Settings
API_TOKEN = "42"
NB_HOST = "netbox.de"
NB_URL = "http://netbox.de"
NB_PORT = "80"
NB_USE_SSL = False

# Own Settings #####################
my_network = "192.168.17.0/23"
set_vrf_id = "4" # VRF ID
set_status = "d" # IP status when not found in the network i=inactive d=delete blank=unchanged
set_tag_id = "19" # tag ID
####################################

# Don't touch
netbox = NetBox(host=(NB_HOST), port=(NB_PORT), use_ssl=(NB_USE_SSL), auth_token=(API_TOKEN))
HEADERS = {'Authorization': f'Token {API_TOKEN}', 'Content-Type': 'application/json', 'Accept': 'application/json'}

if __name__ == '__main__':

#--------------------------------------------------------------------------------

# nmap scan to get DNS -----------------------------------------------------------
    #nmap = nmap3.NmapHostDiscovery()
    #scan_result = nmap.nmap_no_portscan("192.168.22.0/24", args="-PR --system-dns")
    #scan_result.pop("stats")
    #scan_result.pop("runtime")
    #for k,v in scan_result.items():
    #    print ("{:16}    {}".format(k,v['hostname'][0]['name']))

#---------------------------------------------------------------------------------

# networkscan to ping IPs -------------------------------------------------------
    my_scan = networkscan.Networkscan(my_network)

    # Run the scan of hosts using pings
    my_scan.run()

    # Here we define exists ip address in our network and write it to list    
    found_ip_in_network = []
    for address1 in my_scan.list_of_hosts_found:
        found_ip_in_network.append(str(address1))
    
    # Get all IPs
    for ipaddress in ipcalc.Network(my_network):
        # Doing get request to netbox
        request_url = f"{NB_URL}/api/ipam/ip-addresses/?q={ipaddress}/"
        ipaddress1 = requests.get(request_url, headers = HEADERS)
        netboxip = ipaddress1.json()
        # Show findings
        if netboxip['count'] == 0:
            print(ipaddress, "NOTFOUND in netbox")

        if netboxip['count'] > 0:
            print(ipaddress, "FOUND in netbox")
        else:
            pass

        # Debug will show the netbox API string
        #print(netboxip)

        # If IP is not in netbox
        if netboxip['count'] == 0:
            # Check if IP in network exists and not exist in netbox
            if ipaddress in found_ip_in_network:
                # Adding IP in netbox
                netbox.ipam.create_ip_address(str(ipaddress))
                print(str(ipaddress), "ADD IP")
            else:
                pass        
                print(str(ipaddress), "NOT ACTIVE IP")

# Set VRF ------------------------------------------------------------------------
        if ipaddress in found_ip_in_network:
            (netbox.ipam.update_ip(str(ipaddress),status="active") and netbox.ipam.update_ip(str(ipaddress), vrf=(set_vrf_id)))
            print(str(ipaddress), "SET VRF")
        #TODO check this function more deeply!
        # Set IP inactive when not in network
        elif (ipaddress in found_ip_in_network and (set_status) == 'i'):
            netbox.ipam.update_ip(str(ipaddress),status="deprecated")
            print(str(ipaddress), "SET IP INACTIVE")
        # Delete IP when not in network
        elif (ipaddress in found_ip_in_network and (set_status) == 'd'):
            netbox.ipam.delete_ip_address(str(ipaddress))
            print(str(ipaddress), "DELETE IP")
        else:
            (ipaddress in found_ip_in_network and (set_status) == '')
            #netbox.ipam.delete_ip_address(str(ipaddress))
            print(str(ipaddress), "REMOVE STATUS")
