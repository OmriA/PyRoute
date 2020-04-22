from pascy.layer import Layer
from pascy.fields import *


class IcmpLayer(Layer):
    NAME = 'ICMP'

    ECHO_REQUEST = 8
    ECHO_REPLY = 0

    @staticmethod
    def fields_info():
        return [UnsignedByte("type"),
                UnsignedByte("code"),
                UnsignedShort("checksum"),
                ByteString("rest", 4)]

    def calc_checksum(self):
        self.checksum = 0

        buffer = self.serialize()
        sum = 0
        for i in range(0, len(buffer), 2):
            sum += struct.unpack('>H', buffer[i:i+2])[0]
        
        sum = sum + (sum >> 16) - (sum >> 16 << 16)
        sum = 0xffff - sum

        self.checksum = sum

class IpLayer(Layer):
    NAME = 'IP'

    ICMP_PROTOCOL_NUMBER = 0x01

    SUB_LAYERS = [
        [IcmpLayer, "protocol", ICMP_PROTOCOL_NUMBER]
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
                IPAddress("dst")]

    def calc_checksum(self):
        self.checksum = 0

        buffer = self.serialize()
        sum = 0
        for i in range(0, len(buffer), 2):
            sum += struct.unpack('>H', buffer[i:i+2])[0]
        
        sum = sum + (sum >> 16) - (sum >> 16 << 16)
        sum = 0xffff - sum

        self.checksum = sum
