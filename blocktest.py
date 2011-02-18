import structdefpatch
from block import *
import struct, sys

def probe(ctx):
    print ctx
    sys.exit(0)

Test = Struct('Test',
    Block('_block1'),
    Block('_block2'),
    Block('_block3'),
    BOffsetSize(lambda ctx: ctx['_block1'],
        UBInt32('_offset1'),
        UBInt32('_size1'),
    ),
    BOffsetSize(lambda ctx: ctx['_block2'],
        UBInt32('_offset2'),
        UBInt32('_size2'),
    ),
    BOffsetSize(lambda ctx: ctx['_block3'],
        UBInt32('_offset3'),
        UBInt32('_size3'),
    ),
    BPointer(lambda ctx: ctx['_block1'], lambda ctx: ctx['_offset1'],
        UBInt32('one')
    ),
    BPointer(lambda ctx: ctx['_block2'], lambda ctx: ctx['_offset2'],
        Struct('data', 
            BPointer(lambda ctx: ctx['_']['_block3'], lambda ctx: ctx['_']['_offset3'],
                UBInt32('two')
            ),
            #Aligned(BData(probe), 16),
            BData(lambda ctx: ctx['_']['_block3'], align=16, pattern='12'),
        ),
    ),
    BData(lambda ctx: ctx['_block1']),
    BData(lambda ctx: ctx['_block2']),
)

result = Test.parse(struct.pack('>IIIIIIIIII', 28, 4, 32, 8, 36, 4, 42, 1, 42, 2))
print result

result = Container(one=2, data=Container(two=4))
Test.build_stream(result, fakestream())
packed = Test.build(result)
print repr(packed)
