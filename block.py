from construct import *
from stuff import OConst, call
# note: structdefpatch.py is optional, but it allows everything but the actual pointer data to be omitted in the input
# to make this nicer, block and offset/size names ought to start with _, so they are also omitted in the output

# it should be correct on the second run if pointers are always before the corresponding data, but might require more if not.

class fakestream(object):
    def __init__(self):
        self.pos = 0
    def write(self, obj):
        self.pos += len(obj)
    def tell(self):
        return self.pos

class Nobody(object):
    def __init__(self, name):
        self.name = name
        self.pdata = {}
        self.ddata = None
        # If the same BPointer is reused with the same object, we want to repeat the data if it's in an array, but not if this is another invocation of build*.
        # We must act properly with a regular fakestream, but not a very fake stream.
        self.stream = None
    def __repr__(self):
        return '<%r Nobody: %x>' % (self.name, hash(self))
    def _getdata(self, idx):
        if self.ddata is not None:
            return self.ddata[idx]
        else:
            return 42
    def getoffset(self):
        return self._getdata(0)
    def getsize(self):
        return self._getdata(1)

class Block(Construct):
    def __init__(self, name):
         Construct.__init__(self, name)
         #self.subcon = self.context = None

    def _parse(self, stream, context):
        return Nobody(self.name)

    def _build(self, obj, stream, context):
        assert isinstance(obj, Nobody)

    def _getdefault(self, context):
        return Nobody(self.name)

    def _sizeof(self, context):
        return 0

class BPointer(Pointer):
    def __init__(self, nobodyfunc, offsetfunc, subcon):
        Pointer.__init__(self, offsetfunc, subcon)
        self.nobodyfunc = nobodyfunc

    def _build(self, obj, stream, context):
        nobody = self.nobodyfunc(context)
        assert isinstance(nobody, Nobody)
        if nobody.stream is not stream:
            nobody.pdata = {}
            nobody.stream = stream
        nobody.pdata[self] = (self.subcon, obj, context)

class BData(Construct):
    def __init__(self, nobodyfunc, align = 1, pattern = "\x00"):
        Construct.__init__(self, '_bd')
        self.nobodyfunc = nobodyfunc
        self.align = align
        self.pattern = pattern

    def _parse(self, stream, context):
        return None

    def _build(self, obj, stream, context):
        assert obj is None
        nobody = self.nobodyfunc(context)
        offset = stream.tell()

        if self.align != 1:
            diff = -offset % self.align
            padding = (self.pattern * (diff / len(self.pattern) + 1))[:diff]
            offset += diff
            stream.write(padding)

        for (subcon, obj, context) in nobody.pdata.itervalues():
            subcon._build(obj, stream, context)

        size = stream.tell() - offset
        nobody.ddata = (offset, size)

    def _sizeof(self, context):
        nobody = self.nobodyfunc(context)
        result += 0
        for (subcon, obj, context) in nobody.pdata.itervalues():
            result += obj._sizeof(context)
        return result
    
    def _getdefault(self, context):
        return None

def BOffset(nobodyfunc, subcon, minus=0):
    return OConst(subcon, lambda ctx: call(nobodyfunc, ctx).getoffset() - call(minus))

def BSize(nobodyfunc, subcon, divide=1):
    return OConst(subcon, lambda ctx: call(nobodyfunc, ctx).getsize() / call(divide))

def BOffsetSize(nobodyfunc, subcon1, subcon2, divide=1, minus=0):
    return Embedded(Struct('boffsetsize', BOffset(nobodyfunc, subcon1, minus), BSize(nobodyfunc, subcon2, divide)))
