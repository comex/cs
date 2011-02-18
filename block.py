from construct import *
# note: structdefpatch.py is optional, but it allows everything but the actual pointer data to be omitted in the input
# to make this nicer, block and offset/size names ought to start with _, so they are also omitted in the output

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
        self.pdata = None
        self.ddata = None
        self.bd_already_ran = False
    def __repr__(self):
        return '<%r Nobody: %x>' % (self.name, hash(self))



class Block(Construct):
    def __init__(self, name):
         Construct.__init__(self, name)
         #self.subcon = self.context = None

    def _parse(self, stream, context):
        return Nobody(self.name)

    def _build(self, obj, stream, context):
        assert isinstance(obj, Nobody)

    def _getdefault(self):
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
        nobody.pdata = (self.subcon, obj, context)
        if nobody.bd_already_ran:
            self.subcon._build(obj, fakestream(), context)

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
        if nobody.pdata is not None:
            (subcon, obj, context) = nobody.pdata
            offset = stream.tell()

            if self.align != 1:
                diff = -offset % self.align
                padding = (self.pattern * (diff / len(self.pattern) + 1))[:diff]
                stream.write(padding)
                offset += diff

            subcon._build(obj, stream, context)
            size = stream.tell() - offset
            nobody.ddata = (offset, size)
        else:
            stream.write('TAINTED')
            nobody.bd_already_ran = True

    def _sizeof(self, context):
        nobody = self.nobodyfunc(context)
        if nobody.pdata is not None:
            (subcon, obj, context) = nobody.pdata
            return obj._sizeof(context)
        else:
            #print 'omg'
            return 0
    
    def _getdefault(self):
        return None

class BOffsetOrSize(Adapter):
    def __init__(self, nobodyfunc, subcon):
        Adapter.__init__(self, subcon)
        self.nobodyfunc = nobodyfunc

    def _decode(self, obj, context):
        return obj

    def _encode(self, obj, context):
        # ignore obj
        nobody = self.nobodyfunc(context)
        assert isinstance(nobody, Nobody)
        if nobody.ddata is not None:
            return nobody.ddata[self.idx]
        else:
            return 42

    def _getdefault(self):
        return None
        
class BOffset(BOffsetOrSize):
    idx = 0

class BSize(BOffsetOrSize):
    idx = 1

def BOffsetSize(nobodyfunc, subcon1, subcon2):
    return Embedded(Struct('boffsetsize', BOffset(nobodyfunc, subcon1), BSize(nobodyfunc, subcon2)))
