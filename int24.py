from construct import *

class UIntN(Construct):
    def __init__(self, name, size, be):
        Construct.__init__(self, name)
        self.size = size
        self.be = be
    def _parse(self, stream, context):
        data = stream.read(self.size)
        if not self.be: data = data[::-1]
        number = 0
        for c in data:
            number <<= 8
            number |= ord(c)
        return number
    def _build(self, obj, stream, context):
        data = ''
        for i in xrange(self.size):
            data += chr(obj & 255)
            obj >>= 8 
        if self.be: data = data[::-1]
        stream.write(data)
    def _sizeof(self, context):
        return self.size
            

def ULInt24(name):
    return UIntN(name, 3, False)

def UBInt24(name):
    return UIntN(name, 3, True)
