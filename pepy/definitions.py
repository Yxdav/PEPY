from enum import Enum, auto
import ctypes


IMAGE_SIZEOF_SHORT_NAME = 8

class Code(Enum):
    ''' This subclass makes the code more readable by assiging errors to a 
        constant value. Similar to the `#define` macro
    '''

    # Used if a signature/magic number is invalid
    # This can be apply beyond PE files
    ERR_INVALID_SIGNATURE = auto()

class DATA_DIRECTORY_INDEX(Enum):
    IMAGE_DIRECTORY_ENTRY_EXPORT = ("Export Directory" ,0)
    IMAGE_DIRECTORY_ENTRY_IMPORT = ("Import Directory", 1)
    IMAGE_DIRECTORY_ENTRY_RESOURCE = ("Resource Directory", 2)
    IMAGE_DIRECTORY_ENTRY_EXCEPTION = ("Exception Directory", 3)
    IMAGE_DIRECTORY_ENTRY_SECURITY = ("Security Directory", 4)
    IMAGE_DIRECTORY_ENTRY_BASERELOC = ("Base Relocation Table", 5)
    IMAGE_DIRECTORY_ENTRY_DEBUG = ("Debug directory", 6)
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = ("Architecture-specific data", 7)
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR = ("RVA of global pointer", 8)
    IMAGE_DIRECTORY_ENTRY_TLS = ("Thread local storage directory", 9)
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG= ("Load configuration directory", 10)
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = ("Bound import directory", 11)
    IMAGE_DIRECTORY_ENTRY_IAT = ("Import address table", 12)
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = ("Delay import table", 13)
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = ("Delay import table", 14)

class SECTION_FLAGS(Enum):
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_LNK_OTHER = 0x00000100
    IMAGE_SCN_LNK_INFO = 0x00000200
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    IMAGE_SCN_GPREL = 0x00008000
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    IMAGE_SCN_MEM_16BIT = 0x00020000
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    IMAGE_SCN_MEM_PRELOAD = 0x00080000
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000

class MachineType(Enum):
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0
    IMAGE_FILE_MACHINE_AM33 = 0x1d3
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM = 0x1c0
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64
    IMAGE_FILE_MACHINE_ARMNT = 0x1c4
    IMAGE_FILE_MACHINE_EBC = 0xebc
    IMAGE_FILE_MACHINE_I386 = 0x14c
    IMAGE_FILE_MACHINE_IA64 = 0x200
    IMAGE_FILE_MACHINE_M32R = 0x9041
    IMAGE_FILE_MACHINE_MIPS16 = 0x266
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
    IMAGE_FILE_MACHINE_POWERPC = 0x1f0
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1
    IMAGE_FILE_MACHINE_R4000 = 0x166
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128
    IMAGE_FILE_MACHINE_SH3 = 0x1a2
    IMAGE_FILE_MACHINE_SH3DSP = 0x1a3
    IMAGE_FILE_MACHINE_SH4 = 0x1a6
    IMAGE_FILE_MACHINE_SH5 = 0x1a8
    IMAGE_FILE_MACHINE_THUMB = 0x1c2
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169

class PECharacteristics(Enum):
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080
    IMAGE_FILE_32BIT_MACHINE = 0x0100
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800
    IMAGE_FILE_SYSTEM = 0x1000
    IMAGE_FILE_DLL = 0x2000
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000

class IMAGE_BASE_RELOCATION(ctypes.Structure):
    _fields_ = [
        ("VirtualAddress", ctypes.c_uint32),
        ("SizeOfBlock", ctypes.c_uint32),
    ]


class IMAGE_IMPORT_BY_NAME(ctypes.Structure):
    _fields_ = [
                 ("Hint", ctypes.c_uint16),
                 ("Name", ctypes.c_char_p)    
    ]

class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
                 ("OriginalFirstThunk", ctypes.c_uint32),
                 ("TimeDateStamp", ctypes.c_uint32),
                 ("ForwarderChain", ctypes.c_uint32),
                 ("Name", ctypes.c_uint32),
                 ("FirstThunk", ctypes.c_uint32)
               ]

class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("VirtualAddress", ctypes.c_uint32),
        ("Size", ctypes.c_uint32),
    ]
class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
                ("Machine", ctypes.c_ushort),
                ("NumberOfSections", ctypes.c_ushort),
                ("TimeDateStamp", ctypes.c_ulong),
                ("PointerToSymbolTable", ctypes.c_ulong),
                ("NumberOfSymbols",  ctypes.c_ulong),
                ("SizeOfOptionalHeader", ctypes.c_ushort),
                ("Characteristics", ctypes.c_ushort)
               ]


# Define the IMAGE_OPTIONAL_HEADER64 structure
class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ("Magic", ctypes.c_uint16),
        ("Major LinkerVersion", ctypes.c_byte),
        ("MinorLinkerVersion", ctypes.c_byte),
        ("SizeOfCode", ctypes.c_uint32),
        ("SizeOfInitializedData", ctypes.c_uint32),
        ("SizeOfUninitializedData", ctypes.c_uint32),
        ("AddressOfEntryPoint", ctypes.c_uint32),
        ("BaseOfCode", ctypes.c_uint32),
        ("ImageBase", ctypes.c_uint64),
        ("SectionAlignment", ctypes.c_uint32),
        ("FileAlignment", ctypes.c_uint32),
        ("MajorOperatingSystemVersion", ctypes.c_uint16),
        ("MinorOperatingSystemVersion", ctypes.c_uint16),
        ("MajorImageVersion", ctypes.c_uint16),
        ("MinorImageVersion", ctypes.c_uint16),
        ("MajorSubsystemVersion", ctypes.c_uint16),
        ("MinorSubsystemVersion", ctypes.c_uint16),
        ("Win32VersionValue", ctypes.c_uint32),
        ("SizeOfImage", ctypes.c_uint32),
        ("SizeOfHeaders", ctypes.c_uint32),
        ("CheckSum", ctypes.c_uint32),
        ("Subsystem", ctypes.c_uint16),
        ("DllCharacteristics", ctypes.c_uint16),
        ("SizeOfStackReserve", ctypes.c_uint64),
        ("SizeOfStackCommit", ctypes.c_uint64),
        ("SizeOfHeapReserve", ctypes.c_uint64),
        ("SizeOfHeapCommit", ctypes.c_uint64),
        ("LoaderFlags", ctypes.c_uint32),
        ("NumberOfRvaAndSizes", ctypes.c_uint32),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * 16)
    ]


class IMAGE_OPTIONAL_HEADER32(ctypes.Structure):
    _fields_ = [
        ("Magic", ctypes.c_uint16),
        ("MajorLinkerVersion", ctypes.c_byte),
        ("MinorLinkerVersion", ctypes.c_byte),
        ("SizeOfCode", ctypes.c_uint32),
        ("SizeOfInitializedData", ctypes.c_uint32),
        ("SizeOfUninitializedData", ctypes.c_uint32),
        ("AddressOfEntryPoint", ctypes.c_uint32),
        ("BaseOfCode", ctypes.c_uint32),
        ("BaseOfData", ctypes.c_uint32),
        ("ImageBase", ctypes.c_uint32),
        ("SectionAlignment", ctypes.c_uint32),
        ("FileAlignment", ctypes.c_uint32),
        ("MajorOperatingSystemVersion", ctypes.c_uint16),
        ("MinorOperatingSystemVersion", ctypes.c_uint16),
        ("MajorImageVersion", ctypes.c_uint16),
        ("MinorImageVersion", ctypes.c_uint16),
        ("MajorSubsystemVersion", ctypes.c_uint16),
        ("MinorSubsystemVersion", ctypes.c_uint16),
        ("Win32VersionValue", ctypes.c_uint32),
        ("SizeOfImage", ctypes.c_uint32),
        ("SizeOfHeaders", ctypes.c_uint32),
        ("CheckSum", ctypes.c_uint32),
        ("Subsystem", ctypes.c_uint16),
        ("DllCharacteristics", ctypes.c_uint16),
        ("SizeOfStackReserve", ctypes.c_uint32),
        ("SizeOfStackCommit", ctypes.c_uint32),
        ("SizeOfHeapReserve", ctypes.c_uint32),
        ("SizeOfHeapCommit", ctypes.c_uint32),
        ("LoaderFlags", ctypes.c_uint32),
        ("NumberOfRvaAndSizes", ctypes.c_uint32),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * 16),  # Assumes IMAGE_NUMBEROF_DIRECTORY_ENTRIES is 16
    ]
class IMAGE_SECTION_HEADER(ctypes.Structure):
    _fields_ = [
        ("Name", ctypes.c_ubyte * IMAGE_SIZEOF_SHORT_NAME),
        ("Misc", ctypes.c_uint32),  # Union
        ("VirtualAddress", ctypes.c_uint32),
        ("SizeOfRawData", ctypes.c_uint32),
        ("PointerToRawData", ctypes.c_uint32),
        ("PointerToRelocations", ctypes.c_uint32),
        ("PointerToLinenumbers", ctypes.c_uint32),
        ("NumberOfRelocations", ctypes.c_uint16),
        ("NumberOfLinenumbers", ctypes.c_uint16),
        ("Characteristics", ctypes.c_uint32),
    ]

class IMAGE_NT_HEADERS64(ctypes.Structure):
    _fields_ = [
                  ("Signature", ctypes.c_ulong),
                  ("FileHeader",  IMAGE_FILE_HEADER),
                  ("OptionalHeader", IMAGE_OPTIONAL_HEADER64)
                 ]
    
class IMAGE_NT_HEADERS32(ctypes.Structure):
    _fields_ = [
                  ("Signature", ctypes.c_ulong),
                  ("FileHeader",  IMAGE_FILE_HEADER),
                  ("OptionalHeader", IMAGE_OPTIONAL_HEADER32)
                 ]

class DLLCharacteristics(Enum):
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000

def get_machine_type(hex_value:int) -> str :
    ''' Returns a human readable format for the machine type
        
    :hex_value: the integer value of the machine type

    return: A string representation og the machine type
    '''

    for type in MachineType:
        if hex_value == type.value:
            return type.name

def get_characteristics(characterisitcs_as_int:int) -> str:
    characteteristics:list[str] = []

    for characteristic in PECharacteristics:
        if characterisitcs_as_int & characteristic.value:
            characteteristics.append(characteristic.name)
    
    if characteteristics:
        return " | ".join(characteteristics)
    else:
        return "None"
    
def get_dll_characteristics(dll_characterisitcs_as_int:int) -> str:
    characteteristics:list[str] = []

    for characteristic in DLLCharacteristics:
        if dll_characterisitcs_as_int & characteristic.value:
            characteteristics.append(characteristic.name)
    
    if characteteristics:
        return " | ".join(characteteristics)
    else:
        return "None"
    

def get_section_flags(section_flag_as_int:int)->str:
    section_flags:list[str] = []

    for section_flag in SECTION_FLAGS:
        if section_flag_as_int & section_flag.value:
            section_flags.append(section_flag.name)
    
    if section_flags:
        return " | ".join(section_flags)
    else:
        return "None"