#you need install networkscan and python-netbox modules
import networkscan
from netbox import NetBox
netbox = NetBox(host='netbox.de', port=443, use_ssl=True, auth_token='42')

# Main function
if __name__ == '__main__':

    # Define the network to scan
    my_network = "192.168.22.0/24"

    # Create the object
    my_scan = networkscan.Networkscan(my_network)

    # Run the scan of hosts using pings
    my_scan.run()

    # Display the IP address of all the hosts found
    for address in my_scan.list_of_hosts_found:
        print(address)
        netbox.ipam.create_ip_address(address)
