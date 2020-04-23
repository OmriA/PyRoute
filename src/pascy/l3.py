from pascy.layer import Layer
from pascy.fields import *
from functools import lru_cache

@lru_cache()
def calc_checksum(bytes_buffer: bytes):
    sum = 0
    for i in range(0, len(bytes_buffer), 2):
        sum += struct.unpack('>H', bytes_buffer[i:i+2])[0]
    
    sum = sum + (sum >> 16) - (sum >> 16 << 16)
    sum = 0xffff - sum

    return sum

class IcmpLayer(Layer):
    NAME = 'ICMP'

    ECHO_REQUEST = 8
    ECHO_REPLY = 0

    @staticmethod
    def fields_info():
        return [UnsignedByte("type"),
                UnsignedByte("code"),
                UnsignedShort("checksum"),
                UnsignedShort("identifier"),
                UnsignedShort("sequence"),
                ]

    def calc_checksum(self):
        self.checksum = 0
        self.checksum = calc_checksum(self.serialize())

class IpLayer(Layer):
    NAME = 'IP'

    ICMP_PROTOCOL_NUMBER = 0x01

    SUB_LAYERS = [
        [IcmpLayer, "protocol", ICMP_PROTOCOL_NUMBER],
    ]

    @staticmethod
    def fields_info():
        return [UnsignedByte("version_ihl"),
                UnsignedByte("tos"),
                UnsignedShort("length"),
                UnsignedShort("identification"),
                UnsignedShort("flags_offset"),
                UnsignedByte("ttl"),
                UnsignedByte("protocol"),
                UnsignedShort("checksum"),
                IPAddress("src"),
                IPAddress("dst"),
                ]

    def calc_checksum(self):
        self.checksum = 0
        self.checksum = calc_checksum(self.serialize())
