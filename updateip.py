# Script which updating ip addresses in netbox
# We need install pip3 install ipcalc networkscan python-netbox
import ipcalc
import networkscan
from netbox import NetBox
import requests
from actionlogger import *
import datetime
API_TOKEN = "42"
HEADERS = {'Authorization': f'Token {API_TOKEN}', 'Content-Type': 'application/json', 'Accept': 'application/json'}
NB_URL = "https://netbox.de"
netbox = NetBox(host="netbox.de", port=443, use_ssl=True, auth_token="42")

if __name__ == '__main__':

    # Define the network to scan
    my_network = "192.168.17.0/24"
   
    # Create the object
    my_scan = networkscan.Networkscan(my_network)
    
    # Run the scan of hosts using pings
    my_scan.run()

    # Here we define exists ip address in our network and write it to list    
    found_ip_in_network = []
    for address1 in my_scan.list_of_hosts_found:
        found_ip_in_network.append(str(address1))
    
    # Get all ip from prefix
    for ipaddress in ipcalc.Network(my_network):
        # Doing get request to netbox
        request_url = f"{netbox}/api/ipam/ip-addresses/?q={ipaddress}/"
        ipaddress1 = requests.get(request_url, headers = HEADERS)
        netboxip = ipaddress1.json()
        print(ipaddress)
        print(netboxip['count'])
        # If not in netbox
        if netboxip['count'] == 0:
            # Check if in network exists and not exist in netbox
            if ipaddress in  found_ip_in_network:
                # Adding in IP netbox
                netbox.ipam.create_ip_address(str(ipaddress))
                today = datetime.datetime.today()
                print(today.strftime("%Y-%m-%d-%H.%M.%S"))
                datelog = today.strftime("%Y-%m-%d-%H.%M.%S")
                logstring = "IP address " + ipaddress + " was added\n"
                logging(logstring)
            else:
                pass          
        else:
            #If not exists in netbox and network
            if ipaddress in found_ip_in_network:
                pass
            else:
                # If not exists in network but exists in netbox then delete from netbox
                netbox.ipam.delete_ip_address(str(ipaddress))
                today = datetime.datetime.today()
                print(today.strftime("%Y-%m-%d-%H.%M.%S"))
                datelog = today.strftime("%Y-%m-%d-%H.%M.%S")
                logstring = "IP address " + ipaddress + " was deleted\n"
                logging(logstring)
