from pascy.layer import Layer
from pascy.fields import ByteString

class RawLayer(Layer):

    NAME = "Raw"

    @staticmethod
    def fields_info():
        return [ByteString("load", 0)]