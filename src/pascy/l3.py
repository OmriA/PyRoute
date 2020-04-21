from pascy.layer import Layer
from pascy.fields import *

class IpLayer(Layer):
    NAME = 'IP'

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
    