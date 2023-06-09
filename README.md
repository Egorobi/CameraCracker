# CameraCracker
Group 38 project for 2IC80. This code is designed to tamper with the Alecto SmartBaby10 camera.
This project is designed for linux, and it depends on the [NetFilterQueue](https://pypi.org/project/NetfilterQueue/) and [Scapy](https://scapy.net/) python modules.

## Usage Instructions
Since the program relies on an ARP poisoning attack to intercept the camera footage, you need to be on the same network as the camera.

In the poison.py file, enter the name of your wifi interface:
```
interface = "IFACE-NAME"
```
The interface name can be found using the ```ifconfig``` command.

In the attack.py file, enter the IP and MAC addresses of the camera and router you are attacking:
```
ipCamera = "192.168.1.95"
macCamera = "38:be:ab:8f:ff:b0"
ipRouter = "192.168.1.1"
macRouter = "04:92:26:60:98:38"
```

Once this is set up, you can start the attack with:
```
sudo python3 attack.py
```
The program requires superuser permissions to sniff the network and set iptables rules.

The attack will allow a pre-set number of packets to come through before it freezes the footage, this can be changed in the code:
```
allowfirst = 400
```
These packets allow the camera to form a connection to the app and get an inital image which will then be frozen.
If the goal is to not allow any connection at all the block flag can be added to the inital command:
```
sudo python3 attack.py -b
```
There is also the resume flag that allows you to resume the footage after you are done instead of freezing it indefinetely (until the attack is stopped):
```
sudo python3 attack.py -r
```
