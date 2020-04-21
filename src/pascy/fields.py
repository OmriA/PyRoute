import struct
from functools import lru_cache
from typing import Any
from socket import inet_ntoa, inet_aton

class Endianity:
    BIG = ">"
    LITTLE = "<"


class Field:
    FORMAT = ''
    DEFAULT_NAME = ""

    # packet's default endianity is big
    ENDIANITY = Endianity.BIG
    
    def __init__(self, name: str = None, default: Any = 0):
        self.name = name or self.DEFAULT_NAME
        self.val = default
        self.size = struct.calcsize(self.ENDIANITY + self.FORMAT)
        
    def __str__(self):
        return "{} - {}".format(self.name, self.format_val())

    def __len__(self):
        return self.size

    def format_val(self):
        # Print ints as hex values
        if type(self.val) is int:
            return hex(self.val)

        return str(self.val)
    
    def set(self, value):
        self.val = value
        
    def get(self):
        return self.val
    
    def serialize(self) -> bytes:
        return struct.pack(self.ENDIANITY + self.FORMAT, self.val)
    
    def deserialize(self, buffer: bytes):
        self.val = struct.unpack(self.ENDIANITY + self.FORMAT, buffer[:self.size])[0]


class UnsignedByte(Field):
    FORMAT = 'B'


class UnsignedShort(Field):
    FORMAT = 'H'


class UnsignedInteger(Field):
    FORMAT = 'I'


class UnsignedLong(Field):
    FORMAT = 'Q'


class ByteString(Field):
    def __init__(self, name, size, default=None):
        self.FORMAT = '{}s'.format(size)
        super().__init__(name, default=default or b"\x00" * size)

class IPAddress(Field):
    FORMAT = "4s"
    def __init__(self, name="ip", default="0.0.0.0"):
        super().__init__(name, self.str2ip(default))

    def format_val(self):
        return self.ip2str(self.val)
    
    def set(self, value):
        if type(value) is str:
            value = self.str2ip(value)
        
        super().set(value)

    @staticmethod
    @lru_cache()
    def str2ip(val):
        return inet_aton(val)

    @staticmethod
    @lru_cache()
    def ip2str(ip):
        return inet_ntoa(ip)

class MacAddress(Field):
    FORMAT = "6s"

    def __init__(self, name="mac", default="00:00:00:00:00:00"):
        super().__init__(name, self.str2mac(default))

    def format_val(self):
        return self.mac2str(self.val)

    def set(self, value):
        if type(value) is str:
            value = self.str2mac(value)

        super().set(value)

    @staticmethod
    @lru_cache()
    def str2mac(val):
        return bytes.fromhex(val.replace(":", ''))

    @staticmethod
    @lru_cache()
    def mac2str(mac):
        return ":".join("{:02X}".format(octet) for octet in mac)
