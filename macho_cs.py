from block import *
import plistlib

class PlistAdapter(Adapter):
    def _encode(self, obj, context):
        return plistlib.writePlistToString(obj)
    def _decode(self, obj, context):
        return plistlib.readPlistFromString(obj)

# talk about overdesign.
# magic is in the blob struct

Expr = LazyBound("expr", lambda: Expr_)
Blob = LazyBound("blob", lambda: Blob_)

Hashes = LazyBound("hashes", lambda: Hashes_)
Hashes_ = StrictRepeater(lambda ctx: ctx['nSpecialSlots'] + ctx['nCodeSlots'], Bytes("hash", lambda ctx: ctx['hashSize']))

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
    Pointer(lambda ctx: ctx['cd_start'] - 8 + ctx['identOffset'], CString('ident')),
    If(lambda ctx: ctx['version'] >= 0x20100, UBInt32("scatterOffset")),
    Pointer(lambda ctx: ctx['cd_start'] - 8 + ctx['hashOffset'] - ctx['hashSize']*ctx['nSpecialSlots'], Hashes)
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
    OnDemand(Bytes("data", lambda ctx: ctx['_']['length'] - 8)),
)

BlobIndex = Struct("BlobIndex",
    UBInt32("type"),
    UBInt32("offset"),
    Pointer(lambda ctx: ctx['_']['sb_start'] - 8 + ctx['offset'], Blob),
)

SuperBlob = Struct("SuperBlob",
    Anchor("sb_start"),
    UBInt32("count"),
    StrictRepeater(lambda ctx: ctx['count'], BlobIndex),
)

Blob_ = Struct("Blob",
    Enum(UBInt32("magic"),
        CSMAGIC_REQUIREMENT = 0xfade0c00,
        CSMAGIC_REQUIREMENTS = 0xfade0c01,
        CSMAGIC_CODEDIRECTORY = 0xfade0c02,
        CSMAGIC_ENTITLEMENT = 0xfade7171, # actually, this is kSecCodeMagicEntitlement, and not defined in the C version :psyduck:
        CSMAGIC_BLOBWRAPPER = 0xfade0b01, # and this isn't even defined in libsecurity_codesigning; it's in _utilities
        CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0,
        CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc0,
        _default_ = Pass,
    ),
    UBInt32("length"),
    Peek(Switch("data", lambda ctx: ctx['magic'], {
        'CSMAGIC_REQUIREMENT': Requirement,
        'CSMAGIC_REQUIREMENTS': Entitlements,
        'CSMAGIC_CODEDIRECTORY': CodeDirectory,
        'CSMAGIC_ENTITLEMENT': Entitlement,
        'CSMAGIC_BLOBWRAPPER': BlobWrapper,
        'CSMAGIC_EMBEDDED_SIGNATURE': SuperBlob,
    })),
    OnDemand(Bytes('bytes', lambda ctx: ctx['length'] - 8)),
)

