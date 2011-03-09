"""
Executable and Linkable Format (ELF)
Note: This version is modified from construct's to support more section types, 64-bit, big endian?
"""
from construct import *
from int24 import *
import elfconst

big_endian = False
sixtyfour_bit = False

if big_endian:
    UInt64 = UBInt64
    UInt32 = UBInt32
    UInt16 = UBInt16
    SInt64 = SBInt64
    SInt32 = SBInt32
    SInt16 = SBInt16
    UInt24 = UBInt24
    EndianStruct = Struct
else:
    UInt64 = ULInt64
    UInt32 = ULInt32
    UInt16 = ULInt16
    SInt64 = SLInt64
    SInt32 = SLInt32
    SInt16 = SLInt16
    UInt24 = ULInt24
    EndianStruct = lambda name, *rest: Struct(name, *(rest[::-1]))

UIntX = [UInt32, UInt64][sixtyfour_bit]
SIntX = [SInt32, SInt64][sixtyfour_bit]

elf_r_info = Embedded(EndianStruct("info",
        (UInt32 if sixtyfour_bit else UInt24)("sym"),
        Enum((UInt32 if sixtyfour_bit else ULInt8)("type"), **elfconst.r_386)
))

if sixtyfour_bit:
    elf_sym = Struct("symbol",
        UInt64("name"),
        ULInt8("info"),
        ULInt8("other"),
        UInt16("section_index"),
        Padding(4),
        UInt64("value"),
        UInt64("size"),
    )
else:
    elf_sym = Struct("symbol",
        UInt32("name"),
        UInt32("value"),
        UInt32("size"),
        ULInt8("info"),
        ULInt8("other"),
        UInt16("section_index"),
    )


elf_rel = Struct("rel",
    UIntX("offset"),
    elf_r_info,
)

elf_rela = Struct("rela",
    UIntX("offset"),
    elf_r_info,
    SIntX("addend"), 
)

elf_program_header = Struct("program_header",
    Enum(UInt32("type"), **elfconst.pt),
    UInt32("flags") if sixtyfour_bit else Pass,
    UIntX("offset"),
    UIntX("vaddr"),
    UIntX("paddr"),
    UIntX("file_size"),
    UIntX("mem_size"),
    Pass if sixtyfour_bit else UInt32("flags"),
    UIntX("align"),
)

elf_section_header = Struct("section_header",
    UInt32("name_offset"),
    Pointer(lambda ctx: ctx._.strtab_data_offset + ctx.name_offset,
        CString("name")
    ),
    Enum(UInt32("type"), **elfconst.sht),
    UIntX("flags"),
    UIntX("addr"),
    UIntX("offset"),
    UIntX("size"),
    UInt32("link"),
    UInt32("info"),
    UIntX("align"),
    UIntX("entry_size"),
    Pointer(lambda ctx: ctx.offset,
        Switch("data", lambda ctx: ctx.type, {
            "NULL": Pass,
            "PROGBIS": OnDemand(HexDumpAdapter(Field("data", lambda ctx: ctx.size))),
            "SYMTAB": Array(lambda ctx: ctx.size / elf_sym.sizeof(), elf_sym),
            "STRTAB": Pass,
            "RELA": Array(lambda ctx: ctx.size / elf_rela.sizeof(), elf_rela),
            "DYNAMIC": Pass,
            "NOTE": Pass,
            "NOBITS": Pass,
            "REL": Array(lambda ctx: ctx.size / elf_rel.sizeof(), elf_rel),
            "SHLIB": Pass,
            "DYNSYM": Pass,
            "INIT_ARRAY": Pass,
            "FINI_ARRAY": Pass,
            "PREINIT_ARARY": Pass,
        }, default=Pass)
    )
)

elf_file = Struct("elf_file",
    Struct("identifier",
        Const(Bytes("magic", 4), "\x7fELF"),
        Enum(Byte("file_class"),
            NONE = 0,
            CLASS32 = 1,
            CLASS64 = 2,
        ),
        Enum(Byte("encoding"),
            NONE = 0,
            LSB = 1,
            MSB = 2,            
        ),
        Byte("version"),
        Padding(9),
    ),
    Enum(UInt16("type"),
        NONE = 0,
        RELOCATABLE = 1,
        EXECUTABLE = 2,
        SHARED = 3,
        CORE = 4,
    ),
    Enum(UInt16("machine"), **elfconst.em),
    UInt32("version"),
    UIntX("entry"),
    UIntX("ph_offset"),
    UIntX("sh_offset"),
    UInt32("flags"),
    UInt16("header_size"),
    UInt16("ph_entry_size"),
    UInt16("ph_count"),
    UInt16("sh_entry_size"),
    UInt16("sh_count"),
    UInt16("strtab_section_index"),
    
    # calculate the string table data offset (pointer arithmetics)
    # ugh... anyway, we need it in order to read the section names, later on
    Pointer(lambda ctx: 
        ctx.sh_offset + ctx.strtab_section_index * ctx.sh_entry_size + (24 if sixtyfour_bit else 16),
        UInt32("strtab_data_offset"),
    ),
    
    # program header table
    Rename("program_table",
        Pointer(lambda ctx: ctx.ph_offset,
            Array(lambda ctx: ctx.ph_count,
                elf_program_header
            )
        )
    ),
    
    # section table
    Rename("sections", 
        Pointer(lambda ctx: ctx.sh_offset,
            Array(lambda ctx: ctx.sh_count,
                elf_section_header
            )
        )
    ),
)


if __name__ == "__main__":
    import sys
    from construct_try import construct_try
    obj = construct_try(lambda: elf_file.parse_stream(open(sys.argv[1], "rb")))
    print obj
    #[s.data.value for s in obj.sections if s.data is not None]
    #print obj

