from pascy.layer import Layer
from pascy.fields import *
from pascy.l3 import IpLayer

MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"


class ArpLayer(Layer):
    OP_WHO_HAS = 1
    OP_IS_AT = 2

    NAME = "ARP"

    @staticmethod
    def fields_info():
        return [UnsignedShort("hardware_type"),
                UnsignedShort("protocol_type"),
                UnsignedByte("hardware_len"),
                UnsignedByte("protocol_len"),
                UnsignedShort("operation"),
                MacAddress("sender_hardware_addr"),
                IPAddress("sender_protocol_addr"),
                MacAddress("target_hardware_addr"),
                IPAddress("target_protocol_addr")]


class EthernetLayer(Layer):
    NAME = "Ethernet"

    ARP_ETHER_TYPE = 0x0806
    IPV4_ETHER_TYPE = 0x0800

    SUB_LAYERS = [
        [ArpLayer, "ether_type", 0x806],
        [IpLayer, "ether_type", 0x800]
    ]

    @staticmethod
    def fields_info():
        return [MacAddress("dst", MAC_BROADCAST),
                MacAddress("src"),
                UnsignedShort("ether_type", 0)]
