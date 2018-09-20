from scapy.all import *
import time
import csv
import re

def readWireshark(wireFile) :
    data = wireFile
    packets = rdpcap(data)
    return packets
    
def changWiresharkToCSV(text,packets) :
    dataset = open(text,"w")
    regex = re.compile(pattern='10.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}')
    regex2 = re.compile(pattern='172.16.[0-9]{1,3}.[0-9]{1,3}')
    regex3 = re.compile(pattern='192.168.[0-9]{1,3}.[0-9]{1,3}')

    for packet in packets:
        if packet.haslayer(IP):
            # print type(session[IP].dst)
            if(re.match(regex,packet[IP].dst) or re.match(regex2,packet[IP].dst) or re.match(regex3,packet[IP].dst) ) :
                continue
            dataset.write(packet[IP].src+" "+packet[IP].dst+" "+time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))+"\n")

    with open(text) as infile, open('DatasetCSV.csv','w') as outfile: 
        for line in infile: 
            outfile.write(line.replace(' ',','))
    

def main():

    packets = readWireshark("request_1536819763.pcap")

    changWiresharkToCSV("datatest.txt",packets)

if __name__ == '__main__':
    main()