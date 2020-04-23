import socket

class RouterLeg:
    def __init__(self, iface, subnet, mac_addr, ip_addr):
        self.interface = iface
        self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.PACKET_OTHERHOST))
        self.raw_socket.bind((iface, 0))
        self.subnet = subnet
        self.mac = mac_addr
        self.ip = ip_addr