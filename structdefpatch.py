from construct import Struct, Construct, Subconstruct, Adapter, ConstAdapter
from construct.lib import AttrDict
from stuff import call

def new_build(self, obj, stream, context):
    if "<unnested>" in context:
        del context["<unnested>"]
    elif self.nested:
        context = AttrDict(_ = context)
    for sc in self.subcons:
        if sc.conflags & self.FLAG_EMBED:
            context["<unnested>"] = True
            subobj = obj
        elif sc.name is None:
            subobj = None
        else:
            if not hasattr(obj, sc.name):
                try:
                    subobj = sc._getdefault(context)
                except NotImplementedError:
                    raise ValueError('no such property %s' % sc.name) 
                else:
                    setattr(obj, sc.name, subobj)
            else:
                subobj = getattr(obj, sc.name)
            context[sc.name] = subobj
        sc._build(subobj, stream, context)
Struct._build = new_build

def Construct_getdefault(self, context):
    raise NotImplementedError
Construct._getdefault = Construct_getdefault
    
#def Subconstruct_getdefault(self):
#    return self.subcon._getdefault()
#Subconstruct._getdefault = Subconstruct_getdefault

def Adapter_getdefault(self, context):
    s = self.subcon._getdefault(context)
    if s is not None:
        s = self._decode(s, None)
    return s
Adapter._getdefault = Adapter_getdefault

def ConstAdapter_getdefault(self, context):
    return None
ConstAdapter._getdefault = ConstAdapter_getdefault

class Default(Subconstruct):
    def __init__(self, subcon, value):
        Subconstruct.__init__(self, subcon)
        self.value = value
    def _getdefault(self, context):
        return call(self.value, context)
