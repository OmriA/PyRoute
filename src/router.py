from router_leg import RouterLeg    
import pascy
import socket

ROUTER_LEGS = []

ARP_TABLE = {'1.1.1.2':'02:42:01:01:01:02',
             '2.2.2.2':'02:42:02:02:02:02'}

BROADCAST = 'FF:FF:FF:FF:FF:FF'
ARP_ETHER_TYPE = 0x0806

def get_all_packets(leg : RouterLeg) -> pascy.Layer:
    # Recieve packet
    raw_socket = leg.raw_socket
    pkt_raw = raw_socket.recvfrom(65536)[0]

    eth = pascy.l2.EthernetLayer()
    eth.deserialize(pkt_raw)
    pkt_raw = pkt_raw[len(eth):]

    dst = pascy.fields.MacAddress.mac2str(eth.dst)
    # Checks if the packet is for me
    if dst != leg.mac and dst != BROADCAST:
        return None

    if eth.ether_type == ARP_ETHER_TYPE:
        print("ARP REQUEST!")
        arp = pascy.l2.ArpLayer()
        arp.deserialize(pkt_raw)
        pkt_raw = pkt_raw[len(arp):]
        eth.connect_layer(arp)

    eth.display()
    return eth

def response_arp(pkt, leg : RouterLeg):
    resp_pkt = pascy.l2.EthernetLayer() / pascy.l2.ArpLayer()
    resp_pkt["Ethernet"].dst = pkt["Ethernet"].src
    resp_pkt["Ethernet"].src = leg.mac
    resp_pkt["ARP"].hardware_type = pkt["ARP"].hardware_type
    resp_pkt["ARP"].protocol_type = pkt["ARP"].protocol_type
    resp_pkt["ARP"].hardware_len = pkt["ARP"].hardware_len
    resp_pkt["ARP"].protocol_len = pkt["ARP"].protocol_len
    resp_pkt["ARP"].operation = pascy.ArpLayer.OP_IS_AT
    resp_pkt["ARP"].sender_hardware_addr = leg.mac
    resp_pkt["ARP"].sender_protocol_addr = leg.ip
    resp_pkt["ARP"].target_hardware_addr = pkt["Ethernet"].src
    resp_pkt["ARP"].target_protocol_addr = pkt["ARP"].sender_protocol_addr

    leg.raw_socket.sendall(resp_pkt.build())

def main():
    ROUTER_LEGS.append(RouterLeg('net1', '1.1.1', '02:42:9d:8b:d4:a3', '1.1.1.1'))
    ROUTER_LEGS.append(RouterLeg('net2', '2.2.2', '02:42:7f:a5:c8:36', '2.2.2.1'))

    while True:
        pkt = get_all_packets(ROUTER_LEGS[0])
        if not pkt:
            continue

        if pkt.ether_type == ARP_ETHER_TYPE:
            response_arp(pkt, ROUTER_LEGS[0])
        
if __name__ == "__main__":
    main()