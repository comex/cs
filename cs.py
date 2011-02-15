from construct import *
import sys, os, re
import plistlib
from optparse import OptionParser

class PlistAdapter(Adapter):
    def _encode(self, obj, context):
        return plistlib.writePlistToString(obj)
    def _decode(self, obj, context):
        return plistlib.readPlistFromString(obj)

UInt32 = ULInt32

# talk about overdesign.
# magic is in the blob struct

Expr = LazyBound("expr", lambda: Expr_)
Blob = LazyBound("blob", lambda: Blob_)

Hashes = StrictRepeater(lambda ctx: ctx['nSpecialSlots'] + ctx['nCodeSlots'], Bytes("hash", lambda ctx: ctx['hashSize']))

CodeDirectory = Struct("CodeDirectory",
    Anchor("cd_start"),
    UBInt32("version"),
    UBInt32("flags"),
    UBInt32("hashOffset"),
    UBInt32("identOffset"),
    UBInt32("nSpecialSlots"), # known special slots: -5 hashes the fade7171 blob
    UBInt32("nCodeSlots"),
    UBInt32("codeLimit"),
    UBInt8("hashSize"),
    UBInt8("hashType"),
    UBInt8("spare1"),
    UBInt8("pageSize"),
    UBInt32("spare2"),
    If(lambda ctx: ctx['version'] >= 0x20100, UBInt32("scatterOffset")),
    If(lambda ctx: options.hashes, Pointer(lambda ctx: ctx['cd_start'] - 8 + ctx['hashOffset'] - ctx['hashSize']*ctx['nSpecialSlots'], Hashes))
)

Data = Struct("Data",
    UBInt32("length"),
    Bytes("data", lambda ctx: ctx['length']),
    Padding(lambda ctx: -ctx['length'] & 3),
)

CertSlot = Enum(UBInt32("slot"),
    anchorCert = -1,
    leafCert = 0,
    _default_ = Pass,
)

Expr_ = Struct("Expr",
    Enum(UBInt32("op"),
        opFalse = 0,
        opTrue = 1,
        opIdent = 2,
        opAppleAnchor = 3,
        opAnchorHash = 4,
        opInfoKeyValue = 5,
        opAnd = 6,
        opOr = 7,
        opCDHash = 8,
        opNot = 9,
        opInfoKeyField = 10,
        opCertField = 11,
        opTrustedCert = 12,
        opTrustedCerts = 13,
        opCertGeneric = 14,
        opAppleGenericAnchor = 15,
        opEntitlementField = 16,
    ),
    Switch("data", lambda ctx: ctx['op'], {
        'opIdent': Data,
        'opAnchorHash': Sequence("AnchorHash", CertSlot, Data),
        'opInfoKeyValue': Data,
        'opAnd': Sequence("And", Expr, Expr),
        'opOr': Sequence("Or", Expr, Expr),
        'opNot': Expr,
        'opCDHash': Data,
        'opInfoKeyField': Data,
        'opEntitlementField': Data,
        'opCertField': CertSlot,
        'opCertGeneric': CertSlot,
        'opTrustedCert': CertSlot,
    }, default = Pass),
)


Requirement = Struct("Requirement",
    Const(UBInt32("kind"), 1),
    Expr,
)

Entitlement = Struct("Entitlement",
    # actually a plist
    PlistAdapter(Bytes("data", lambda ctx: ctx['_']['length'] - 8)),
)

EntitlementsBlobIndex = Struct("BlobIndex",
    Enum(UBInt32("type"),
        kSecHostRequirementType = 1,
        kSecGuestRequirementType = 2,
        kSecDesignatedRequirementType = 3,
        kSecLibraryRequirementType = 4,
    ),
    UBInt32("offset"),
    Pointer(lambda ctx: ctx['_']['sb_start'] - 8 + ctx['offset'], Blob),
)

Entitlements = Struct("Entitlements", # actually a kind of super blob
    Anchor("sb_start"),
    UBInt32("count"),
    StrictRepeater(lambda ctx: ctx['count'], EntitlementsBlobIndex),
)

BlobWrapper = Struct("BlobWrapper",
    Bytes("data", lambda ctx: ctx['_']['length'] - 8),
)

Blob_ = Struct("Blob",
    Enum(UBInt32("magic"),
        CSMAGIC_REQUIREMENT = 0xfade0c00,
        CSMAGIC_REQUIREMENTS = 0xfade0c01,
        CSMAGIC_CODEDIRECTORY = 0xfade0c02,
        CSMAGIC_ENTITLEMENT = 0xfade7171, # actually, this is kSecCodeMagicEntitlement, and not defined in the C version :psyduck:
        CSMAGIC_BLOBWRAPPER = 0xfade0b01, # and this isn't even defined in libsecurity_codesigning; it's in _utilities
    ),
    UBInt32("length"),
    Switch("data", lambda ctx: ctx['magic'], {
        'CSMAGIC_REQUIREMENT': Requirement,
        'CSMAGIC_REQUIREMENTS': Entitlements,
        'CSMAGIC_CODEDIRECTORY': CodeDirectory,
        'CSMAGIC_ENTITLEMENT': Entitlement,
        'CSMAGIC_BLOBWRAPPER': BlobWrapper,
    }),
)

BlobIndex = Struct("BlobIndex",
    UBInt32("type"),
    UBInt32("offset"),
    Pointer(lambda ctx: ctx['_']['sb_start'] + ctx['offset'], Blob),
)

SuperBlob = Struct("SuperBlob",
    Anchor("sb_start"),
    Const(UBInt32("magic"), 0xfade0cc0),
    UBInt32("length"),
    UBInt32("count"),
    StrictRepeater(lambda ctx: ctx['count'], BlobIndex),
)

LoadCommand = Struct("LoadCommand",
    Enum(UInt32("cmd"),
        LC_SEGMENT = 0x1,
        LC_SYMTAB = 0x2,
        LC_SYMSEG = 0x3,
        LC_THREAD = 0x4,
        LC_UNIXTHREAD = 0x5,
        LC_LOADFVMLIB = 0x6,
        LC_IDFVMLIB = 0x7,
        LC_IDENT = 0x8,
        LC_FVMFILE = 0x9,
        LC_PREPAGE = 0xa,
        LC_DYSYMTAB = 0xb,
        LC_LOAD_DYLIB = 0xc,
        LC_ID_DYLIB = 0xd,
        LC_LOAD_DYLINKER = 0xe,
        LC_ID_DYLINKER = 0xf,
        LC_PREBOUND_DYLIB = 0x10,
        LC_ROUTINES = 0x11,
        LC_SUB_FRAMEWORK = 0x12,
        LC_SUB_UMBRELLA = 0x13,
        LC_SUB_CLIENT = 0x14,
        LC_SUB_LIBRARY = 0x15,
        LC_TWOLEVEL_HINTS = 0x16,
        LC_PREBIND_CKSUM = 0x17,
        LC_LOAD_WEAK_DYLIB = 0x80000018,
        LC_SEGMENT_64 = 0x19,
        LC_ROUTINES_64 = 0x1a,
        LC_UUID = 0x1b,
        LC_RPATH = 0x8000001c,
        LC_CODE_SIGNATURE = 0x1d,
        LC_SEGMENT_SPLIT_INFO = 0x1e,
        LC_REEXPORT_DYLIB = 0x8000001f,
        LC_LAZY_LOAD_DYLIB = 0x20,
        LC_ENCRYPTION_INFO = 0x21,
        LC_DYLD_INFO = 0x22,
        LC_DYLD_INFO_ONLY = 0x80000022,
        LC_LOAD_UPWARD_DYLIB = 0x80000023,
    ),
                
    UInt32("cmdsize"),
    Peek(Switch("data", lambda ctx: ctx['cmd'], {
        'LC_SEGMENT': Struct('Segment',
            Bytes('segname', 16),
            UInt32('vmaddr'),
            UInt32('vmsize'),
            UInt32('fileoff'),
            UInt32('filesize'),
            UInt32('maxprot'),
            UInt32('initprot'),
            UInt32('nsects'),
            UInt32('flags'),
            StrictRepeater(lambda ctx: ctx['nsects'], Struct('Section',
                Bytes('sectname', 16),
                Bytes('segname', 16),
                UInt32('addr'),
                UInt32('size'),
                UInt32('offset'),
                UInt32('align'),
                UInt32('reloff'),
                UInt32('nreloc'),
                UInt32('flags'),
                UInt32('reserved1'),
                UInt32('reserved2'),
            )),
        ),
        'LC_CODE_SIGNATURE': Struct("CodeSignature",
            UInt32('dataoff'),
            UInt32('datasize'),
            Pointer(lambda ctx: ctx['_']['_']['macho_start'] + ctx['dataoff'], SuperBlob),
            #Pointer(UInt32('dataoff'), SuperBlob),
            #UInt32('datasize')
        ),
    }, default = Pass)),
    OnDemand(Bytes('bytes', lambda ctx: ctx['cmdsize'] - 8)),
    #Probe(),
)
    

MachO = Struct("MachO",
    Anchor("macho_start"),
    Const(UInt32("magic"), 0xfeedface),
    UInt32("cputype"),
    UInt32("cpusubtype"),
    Enum(UInt32("filetype"),
        MH_OBJECT = 0x1,
        MH_EXECUTE = 0x2,
        MH_FVMLIB = 0x3,
        MH_CORE	 = 0x4,
        MH_PRELOAD = 0x5,
        MH_DYLIB = 0x6,
        MH_DYLINKER = 0x7,
        MH_BUNDLE = 0x8,
        MH_DYLIB_STUB = 0x9,
        MH_DSYM	 = 0xa,
        MH_KEXT_BUNDLE = 0xb,
        _default_ = Pass,
    ),
    UInt32("ncmds"),
    UInt32("sizeofcmds"),
    FlagsEnum(UInt32("flags"),
        MH_NOUNDEFS = 0x1,
        MH_INCRLINK = 0x2,
        MH_DYLDLINK = 0x4,
        MH_BINDATLOAD = 0x8,
        MH_PREBOUND = 0x10,
        MH_SPLIT_SEGS = 0x20,
        MH_LAZY_INIT = 0x40,
        MH_TWOLEVEL = 0x80,
        MH_FORCE_FLAT = 0x100,
        MH_NOMULTIDEFS = 0x200,
        MH_NOFIXPREBINDING = 0x400,
        MH_PREBINDABLE = 0x800,
        MH_ALLMODSBOUND = 0x1000,
        MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000,
        MH_CANONICAL = 0x4000,
        MH_WEAK_DEFINES = 0x8000,
        MH_BINDS_TO_WEAK = 0x10000,
        MH_ALLOW_STACK_EXECUTION = 0x20000,
        MH_DEAD_STRIPPABLE_DYLIB = 0x400000,
        MH_ROOT_SAFE = 0x40000,
        MH_SETUID_SAFE = 0x80000,
        MH_NO_REEXPORTED_DYLIBS = 0x100000,
        MH_PIE = 0x200000,
    ),
    StrictRepeater(lambda ctx: ctx['ncmds'], LoadCommand)
)

FatArch = Struct("FatArch",
    UBInt32("cputype"),
    UBInt32("cpusubtype"),
    UBInt32("offset"),
    UBInt32("size"),
    UBInt32("align"),
    Pointer(lambda ctx: ctx['offset'], MachO),
)

Fat = Struct("Fat",
    Const(UBInt32("magic"), 0xcafebabe),
    UBInt32("nfat_arch"),
    StrictRepeater(lambda ctx: ctx['nfat_arch'], FatArch),
)

MachOOrFat = Struct("MachOOrFat",
    Peek(UInt32("magic")),
    Switch("data", lambda ctx: ctx['magic'], {
        0xfeedface: MachO,
        0xcafebabe: Fat,
        0xbebafeca: Fat,
    })
)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-H', '--hashes', dest='hashes', action='store_true', default=False, help='print the actual hashes')
    options, args = parser.parse_args()
    filename = args[0]

    f = open(filename, 'rb')
    data = MachOOrFat.parse_stream(f)
    print data
else:
    class opt: pass
    options = opt()
    options.hashes = False
