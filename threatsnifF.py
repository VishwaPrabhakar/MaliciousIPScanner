import argparse
import json, urllib
from scapy.all import IP, sniff
from scapy.layers import http
import logging, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import requests
#'apikey': 'add your API key below'

def auto_fun(args):
    # And continue
    print("auto working")
    # Extracting URLs from network traffic in just 9 Python lines with Scapy-HTTP
    #sudo apt-get install python-scapy python-pip
    #sudo pip install scapy_http


    def process_tcp_packet(packet):
        #Processes a TCP packet, and if it contains an HTTP request, it prints it.
        if not packet.haslayer(http.HTTPRequest):
            # This packet doesn't contain an HTTP request so we skip it
            return
        http_layer = packet.getlayer(http.HTTPRequest)
        ip_layer = packet.getlayer(IP)
        print '\n{0[dst]} just requested a {1[Method]} {1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields)
        ipaddress='{0[dst]}'
        ipaddress = str(ipaddress)
        ip_check(ipaddress)

        # Start sniffing the network.
    sniff(filter='tcp', prn=process_tcp_packet)

    #sniffer code end here
#-------------------------------
#ipchcek code start here.
def ip_check(ipaddress):
    #ipaddress = input('Enter an IP address to scan: \n')
    print'ip_check-started'
    #Virus total API info

    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    parameters = {'ip': ipaddress, 'apikey': 'add your API key here'}
    response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
    response_dict = json.loads(response)
    print response_dict

	#harvest important info from JSON response
    positiveResults = 0
    totalResults = 0
    try:
		for x in response_dict.get("detected_referrer_samples"):
			positiveResults = positiveResults + x.get("positives")
	    		totalResults = totalResults + x.get("total") 
                print 'its inside for_loop'
    except TypeError: #if no results found program throws a TypeError
		print ("No results")
	
	    #convert results to string for output formatting
    positiveResults = str(positiveResults)
    totalResults = str(totalResults)
	
	#print results
    print(positiveResults + '/' + totalResults + ' total AV detection ratio')
	#Virustotal ip scan code end here--------------


#ipcheck code end here
 
def manual_fun(args):
    #param1 = args.param1
    # And continue
    print("manual working")
    #code here to scan the pcap file and fetch the destination ip address then use the function	ip_Scan to print result here.
    '''
    this code will read pcap file and print the target dest ip address and store in variable'''

    pcap = sys.argv[1]

    pkts = rdpcap(pcap)

    # Find the first packet and use that as the reference for source and destination IP address
    sip = pkts[0][IP].src
    dip = pkts[0][IP].dst

    print '[!] The address of ' + sip
    print '[!] The address of ' + dip

    ipaddress=dip
    print ipaddress 
    #ip printing from pcap file code end here.
    #calling ip_check function here on the stored ip address.
    ip_check(ipaddress)

p = argparse.ArgumentParser()
subparsers = p.add_subparsers()

option1_parser = subparsers.add_parser('auto')
# Add specific options for option1 here, but here's
# an example

option1_parser.set_defaults(func=auto_fun)

option2_parser = subparsers.add_parser('manual')
option2_parser.add_argument('pcapfilename')
# Add specific options for option1 here
option2_parser.set_defaults(func=manual_fun)

args = p.parse_args()
args.func(args)
