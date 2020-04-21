from abc import ABC, abstractmethod
from collections import OrderedDict
from functools import lru_cache


class Layer(ABC):
    NAME = ""
    SUB_LAYERS = []

    def __init__(self):
        self.next_layer = None
        self.last_layer = self

        self.fields = OrderedDict((f.name, f) for f in self.fields_info())

    def __truediv__(self, other):
        """
        Create a connection between two layers, creating a packet.
        For example:
            >>> packet = EthernetLayer() / ArpLayer()
        Will create an ARP packet, whose L2 structure is Ethernet.

        :param other:   The upper layer
        :return:        self
                        (Usable for multiple one-line connections)
        """
        return self.connect_layer(other)

    def __getattr__(self, key):
        # Prevent infinite loop on init :(
        if "fields" not in self.__dict__:
            self.__dict__["fields"] = {}

        if key in self.__dict__:
            return self.__dict__[key]

        elif key in self.fields.keys():
            return self.fields[key].get()

    def __getitem__(self, key):
        if self.NAME == key:
            return self
        
        if self.next_layer:
            return self.next_layer.__getitem__(key)

        raise Exception("Couldn't find layer {}.".format(key))

    def __setattr__(self, key, val):
        if key in self.fields:
            self.fields[key].set(val)

        else:
            self.__dict__[key] = val

    @staticmethod
    @abstractmethod
    def fields_info():
        """
        Build and return the structure of this layer's fields.
        This should be implemented for each layer.

        :return:    A list of instances of Field (or subclasses).
                    Each item in this list represent (by order) the relevant packet field.
        """
        pass

    def display(self):
        content = ""
        indent = ""

        # Layer name
        content += indent + "--- {} ---\n".format(self.NAME)
        for _, f in self.fields.items():
            content += indent + str(f) + "\n"

        # Recurse all sub-layers
        next_layer = self.next_layer
        while next_layer:
            indent += "\t"
            content += indent + "--- {} ---\n".format(next_layer.NAME)

            for _, f in next_layer.fields.items():
                content += indent + str(f) + "\n"

            next_layer = next_layer.next_layer

        print(content)

    @property
    @lru_cache()
    def size(self) -> int:
        """
        :return:    The size (in bytes) of this layer's raw data
        """
        size = 0

        for _, field in self.fields.items():
            size += len(field)

        return size

    def serialize(self) -> bytes:
        """
        Serialize this layer to a buffer
        """
        buffer = b""

        for _, field in self.fields.items():
            buffer += field.serialize()

        return buffer

    def deserialize(self, buffer: bytes):
        """
        Deserialize this layer from a buffer
        """
        for _, field in self.fields.items():
            field.deserialize(buffer)
            buffer = buffer[len(field):]

    def build(self) -> bytes:
        """
        Build the entire packet into a raw buffer
        """
        if self.next_layer:
            return self.serialize() + self.next_layer.build()

        else:
            return self.serialize()

    def __len__(self) -> int:
        """
        :return:    The size (in bytes) of the entire packet's raw data
        """
        if self.next_layer:
            return self.size + len(self.next_layer)

        else:
            return self.size

    def connect_layer(self, other):
        for layer, field, val in self.SUB_LAYERS:
            if isinstance(other, layer):
                self.last_layer.fields[field].set(val)
                self.last_layer = other

                if not self.next_layer:
                    self.next_layer = other
                else:
                    self.next_layer.connect_layer(other)

                return self

        raise Exception("Can't link {} and {}.".format(self.__class__.__name__, other.__class__.__name__))
