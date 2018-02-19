# MalaciousIPScanner
This program scans Network traffic and user entered ip addresses and will check them in Virus Total Database.
Introduction To MalaciousIPScanner:
In this project, we will leverage a powerful python library for packet manipulation and inspection, called Scapy. In this project, we will create a packet sniffer that inspects traffic on a local area network and extracts outbound IP connections and HTTP requests. These indicators (IP and hostnames) are then queried to a threat intelligence (TI) service providers to identify their maliciousness. You can use an open source threat intelligence of your choice, however, I recommend using Virus Total. 
Pre-Development Steps:
These steps are necessary to get the project done. Therefore, I recommend following these steps one after the other to make sure your project covers all the materials you need before you get to start coding.
   
    1- Use Scapy sniffing method to sniff traffic and extract IP and Hostnames. Use references [2] and [3] to start. Understand PCAP and how to parse PCAP using SCAPY [4].
Follow steps 3 and 4 if you chose Virus Total (VT) as your TI provider. Follow step 5, for both VT and any other TI provider of your choice.
    2- Study virustotal and get yourself familiar with IP and Hostname reports. For instance, read a report on this IP address: 188.138.88.184. See how you can conclude that this IP is a malicious IP. Hint: This IP is involved in locky ransomware campaign. See ‘URLs’ or ‘Communicating Files’ section of the report. 
    4- the main algorithm in the program tell on how to distinguish between a bad and benign IP or hostname. For instance, a number of bad reports or number of related bad files could be good suggestions.
    5- You will need an API service key to be able to query the TI provider automatically. For Virus Total subscribe to Virus Total first, using this linke here. 
    6- Some TI providers have SDK or library to connect to their services. You can see Virus Total implementations in Python here. I personally used this library to connect to VT in my projects. 
    7- Try querying VT or your TI provider of your own by some IP addresses using the library or SDK provided. Interpret the results and see how it compares to the results on the website itself. Note that the free API of Virus Total, is limited to four IPs per minute.
Development Steps
    1- This is a python script that operates in two modes. One automatic and one manual. 
    2- If the automatic mode is chosen by passing the argument ‘auto’ in the prompt, the system sniffs the packets on the network and looks for IP or hostnames requests. For instance, let's call the script ‘threatsniff’. Then, the command should look like this:

python threatsniff.py auto

    3- A method needs to be defined to query TI provider for identified IP or hostnames. If the IP or hostname concluded to be malicious it should print out the result on the screen and also append the malicious indicator (host or IP) in a file that contains all malicious IP or hostnames discovered since the start of the script.
    4- If the manual mode is chosen, the user needs to provide an argument ‘manual’ and also point to a PCAP file. The PCAP needs to be parsed to identify malicious indicators (host or IP) by first extracting them and second calling the function to query the TI provider.  The command will look like this:
python threatsniff.py manual malwaretraffic.pcap

 
