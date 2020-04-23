from router_leg import RouterLeg    
import pascy
import socket
import select
from functools import lru_cache
from const import BUFFER_SIZE

ROUTER_LEGS = []

ARP_TABLE = {'1.1.1.2':'02:42:01:01:01:02',
             '2.2.2.2':'02:42:02:02:02:02'}

def parse_arp(pkt_raw):
    arp = pascy.l2.ArpLayer()
    arp.deserialize(pkt_raw)
    pkt_raw = pkt_raw[len(arp):]

    return arp, pkt_raw

def parse_ip(pkt_raw):
    ip = pascy.l3.IpLayer()
    ip.deserialize(pkt_raw)
    pkt_raw = pkt_raw[len(ip):]
    
    # Parse icmp layer
    if ip.protocol == pascy.IpLayer.ICMP_PROTOCOL_NUMBER:
        icmp = pascy.l3.IcmpLayer()
        icmp.deserialize(pkt_raw)
        pkt_raw = pkt_raw[len(icmp):]
        ip.connect_layer(icmp)

    return ip, pkt_raw

def get_packet(leg: RouterLeg) -> pascy.Layer:
    # Recieve packet
    raw_socket = leg.raw_socket
    pkt_raw = raw_socket.recv(BUFFER_SIZE)

    # Parse ethernet layer
    eth = pascy.l2.EthernetLayer()
    eth.deserialize(pkt_raw)
    pkt_raw = pkt_raw[len(eth):]

    dst = pascy.fields.MacAddress.mac2str(eth.dst)
    # Checks if the packet is for me
    if dst != leg.mac and dst != pascy.l2.MAC_BROADCAST:
        return None

    # Parse arp layer
    if eth.ether_type == pascy.EthernetLayer.ARP_ETHER_TYPE:
        arp, pkt_raw = parse_arp(pkt_raw)
        eth.connect_layer(arp)

    # Parse ip layer
    elif eth.ether_type == pascy.EthernetLayer.IPV4_ETHER_TYPE:
        ip, pkt_raw = parse_ip(pkt_raw)
        eth.connect_layer(ip)

    # If there is more buffer after we parsed the whole layers add it 
    # to the raw layer
    if len(pkt_raw) > 0:
        raw = pascy.RawLayer()
        raw.load = pkt_raw
        eth.connect_layer(raw)

    return eth

def response_arp(pkt, leg: RouterLeg):
    resp_pkt = pascy.l2.EthernetLayer() / pascy.l2.ArpLayer()
    resp_pkt["Ethernet"].dst = pkt["Ethernet"].src
    resp_pkt["Ethernet"].src = leg.mac

    resp_pkt["ARP"].copy_layer(pkt["ARP"])
    resp_pkt["ARP"].operation = pascy.ArpLayer.OP_IS_AT
    resp_pkt["ARP"].sender_hardware_addr = leg.mac
    resp_pkt["ARP"].sender_protocol_addr = leg.ip
    resp_pkt["ARP"].target_hardware_addr = pkt["Ethernet"].src
    resp_pkt["ARP"].target_protocol_addr = pkt["ARP"].sender_protocol_addr

    leg.raw_socket.sendall(resp_pkt.build())
    print("Sent ARP reply.")

def response_icmp(pkt, leg: RouterLeg):
    resp_pkt = pascy.EthernetLayer() / (pascy.IpLayer() / pascy.IcmpLayer())
    resp_pkt.connect_layer(pascy.RawLayer())
    resp_pkt["Ethernet"].dst = pkt["Ethernet"].src
    resp_pkt["Ethernet"].src = leg.mac

    resp_pkt["IP"].copy_layer(pkt["IP"])
    resp_pkt["IP"].dst = pkt["IP"].src
    resp_pkt["IP"].src = leg.ip
    resp_pkt["IP"].calc_checksum()

    resp_pkt["ICMP"].type = pascy.IcmpLayer.ECHO_REPLY
    resp_pkt["ICMP"].rest = pkt["ICMP"].rest
    resp_pkt["ICMP"].calc_checksum()

    resp_pkt["Raw"].load = pkt["Raw"].load

    leg.raw_socket.sendall(resp_pkt.build())
    print("Sent ICMP reply.")

def forward_packet(pkt, leg: RouterLeg):
    dst_ip = socket.inet_ntoa(pkt["IP"].dst)
    pkt["Ethernet"].src = leg.mac
    pkt["Ethernet"].dst = ARP_TABLE[dst_ip]
    pkt["IP"].ttl -= 1

    leg.raw_socket.sendall(pkt.build())
    print("Message forwarded")

@lru_cache()
def get_leg_by_socket(s) -> RouterLeg:
    for leg in ROUTER_LEGS:
        if leg.raw_socket == s:
            return leg

    return None

@lru_cache()
def get_leg_by_ip(ip) -> RouterLeg:
    for leg in ROUTER_LEGS:
        if leg.subnet in ip:
            return leg

    return None

def main():
    ROUTER_LEGS.append(RouterLeg('net1', '1.1.1', '02:42:05:66:DC:60', '1.1.1.1'))
    ROUTER_LEGS.append(RouterLeg('net2', '2.2.2', '02:42:1A:B7:27:E5', '2.2.2.1'))

    legs_sockets = []
    for leg in ROUTER_LEGS:
        legs_sockets.append(leg.raw_socket)

    while legs_sockets:
        readable, _, exceptional = select.select(legs_sockets, [], legs_sockets)
        print("Recieved...")
        
        for s in readable:
            leg = get_leg_by_socket(s)
            if leg == None:
                raise Exception("Error occured! Unknown socket found!")

            pkt = get_packet(leg)
            if not pkt:
                continue

            # ARP request for me
            if pkt["Ethernet"].ether_type == pascy.EthernetLayer.ARP_ETHER_TYPE and \
                pkt["ARP"].target_protocol_addr == socket.inet_aton(leg.ip):
                response_arp(pkt, leg)

            # Packet is for me
            elif pkt["IP"].dst == socket.inet_aton(leg.ip):
                # Ping for me
                if pkt["IP"].protocol == pascy.IpLayer.ICMP_PROTOCOL_NUMBER:
                    response_icmp(pkt, leg)

            # Packet destination is not me
            else:
                leg = get_leg_by_ip(socket.inet_ntoa(pkt["IP"].dst))
                forward_packet(pkt, leg)

        for s in exceptional:
            leg = get_leg_by_socket(s)
            legs_sockets.remove(s)
            print("Critical: lost connection with leg {}".format(leg.interface))
        
if __name__ == "__main__":
    main()