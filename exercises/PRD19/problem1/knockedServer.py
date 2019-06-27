from scapy.all import *

def main(argv=None):
    argv = sys.argv
    interface = argv[1]
    sniff(iface=interface, prn=lambda x: x.summary())

if __name__ == "__main__":
    main()
