from construct import Struct, Construct, Subconstruct
from construct.lib import AttrDict

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
                    subobj = sc._getdefault()
                except NotImplementedError:
                    raise ValueError('no such property %s' % sc.name) 
                else:
                    setattr(obj, sc.name, subobj)
            else:
                subobj = getattr(obj, sc.name)
            context[sc.name] = subobj
        sc._build(subobj, stream, context)
Struct._build = new_build

def Construct_getdefault(self):
    raise NotImplementedError
Construct._getdefault = Construct_getdefault
    
def Subconstruct_getdefault(self):
    return self.subcon._getdefault()
Subconstruct._getdefault = Subconstruct_getdefault
