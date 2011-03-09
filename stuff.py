from construct import Adapter, ConstAdapter

def call(obj, *args, **kwargs):
    if callable(obj):
        return obj(*args, **kwargs)
    else:
        return obj

class hexint(int):
    def __repr__(self):
        return hex(self)

class HexAdapter(Adapter):
    def _encode(self, obj, context):
        return obj
    def _decode(self, obj, context):
        return hexint(obj)

# this makes sense!
class OConst(ConstAdapter):
    def _decode(self, obj, context):
        return obj
    def _encode(self, obj, context):
        return call(self.value, context)
