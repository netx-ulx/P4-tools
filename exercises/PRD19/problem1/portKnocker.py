#!/usr/bin/python
import sys
import random
import time
import pdb
from scapy.all import *

srcIP = ""
vethFace = ""

def main(argv=None):
    argv = sys.argv
    global srcIP
    global vethFace
    srcIP = argv[1]
    mode = argv[2]
    vethFace = argv[3]

    print 'Starting {} client {}\n'.format(mode,srcIP)
    
    if ( mode == "malicious" ):
        while(1):
                port = pickRandomPort()
                sendAndWait(port)
    else:
         # the right secret sequence is hard-coded
         port_seq = [2222,3333,4444,22]
            
         # A legitimate user knocks the right sequence with 1sec gap between two consecutive knocks
         # once the 22 door opened, it produces 5 packets to that port and then it picks a random port number to reset the state to the initial one
         while(1):
             for port in port_seq:
                 sendAndWait(port)
             for attempts in range(5):
                 sendAndWait(22)
             
             port = pickRandomPort()
             sendAndWait(port)
                
         

def sendAndWait(tcpDstPort):
    packet = Ether()/IP(src=srcIP,dst="10.0.3.10")/TCP(dport=tcpDstPort) 
    sendp(packet,iface=vethFace)
    print "Sending to port {}\n".format(tcpDstPort)
    time.sleep(1)

def pickRandomPort():
    return random.randint(1024,65000)

if __name__ == "__main__":
    main()
