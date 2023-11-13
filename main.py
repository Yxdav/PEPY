import argparse
import sys
import os
import logging
import ctypes

from enum import Enum, auto
from math import ceil

from pepy.message import info, error, warning, ok
from pepy.definitions import * # a mini <Windows.h>/<winnt.h>

FILE_NAME = sys.argv[0]


def is_64bit(file_contents)-> bool:
        # Parses the DOS header and automatically outputs results
    if DOS.parse(file_contents) ==  Code.ERR_INVALID_SIGNATURE:
        error("Invalid DOS magic number")
        return
    
    # A IMAGE_NT_HEADER struct
    # At this the OptionalHeader Fields is still empty
    nt_file_headers:IMAGE_NT_HEADERS64 | IMAGE_NT_HEADERS32 = PE.parse(file_contents, False)
    
    # The program exits if the first four bytes of the header ( the signature)
    # does not match PE\0\0
    if nt_file_headers== Code.ERR_INVALID_SIGNATURE:
        error("Invalid PE signature")
        return 
    
    # Returns the optional header which is added to `nt_file_headers`'s OptionalHeader Field
    optional_header:IMAGE_OPTIONAL_HEADER32 |IMAGE_OPTIONAL_HEADER64 = PE_OPTIONAL.parse(file_contents, nt_file_headers.FileHeader.SizeOfOptionalHeader, False)

    if optional_header.Magic == 0x20b:
        return True
    return False


class DOS:
    ''' This class essentialy wraps the functionality of parsing
        and printing values of importance from the DOS header 
    '''

    magic:bytes = (0x5a4D).to_bytes(2, byteorder="little") # A constant
    
    # Note that only the useful ones are parsed
    dos_magic: bytes | None = None
    header_offset: bytes | None = None # offset to start of file header
    
    @staticmethod
    def parse(buffer:bytes)-> Code | bool:
        ''' Parses the DOS header represented by `buffer` 
            and returns appropriate value to notify caller
            if the function succeeded

            param: buffer: It can be the whole PE file, however only the first 64 bytes are of importance

            return: A bool(True) if the functino succeeded or Code.ERR_INVALID_SIGNATURE
        '''

        __class__.dos_magic = buffer[0:2]
        logging.debug(f"DOS magic -> {__class__.dos_magic}")
        if __class__.dos_magic == __class__.magic:
            __class__.header_offset = buffer[0x3c:0x3c+4][::-1] # Last 4 bytes of DOS header Structure (Which is 64 bytes)
            logging.debug(f"Offset to COFF header {__class__.header_offset}")
        else:
            return Code.ERR_INVALID_SIGNATURE
        __class__.pprint_dos()
        return True
      
    @staticmethod
    def pprint_dos() -> None:
        ''' Prints the parsed DOS header in a suitable format.
            It should only be called only if `parse(bytes) -> Code | bool`
            succeeds

            return: None
        '''

        print("DOS header:")
        print(f"\t Magic Number: 0x{__class__.dos_magic.hex().upper()}")
        print(f"\t COFF header Offset: 0x{__class__.header_offset.hex().upper()}")
        print()

class PE:
    ''' This wraps the parsing the file header '''
    
    # PE signature
    PE_SIGNATURE:bytes = (0x50450000).to_bytes(4)

    @staticmethod
    def parse(buffer:bytes, is_64bit:bool)-> IMAGE_NT_HEADERS64 | IMAGE_NT_HEADERS32 | Code:
        ''' Carves the section which is the File Header from an offset in the
            DOS header
           
            param: buffer: It can be the whole PE file, however only the first 64 bytes are of importance
            return: Returns an object whose class inherited from enum.Structure(see definition in pepy/definitions.py) or an error enum
        '''
        
        # Uses offset from DOS header and size of FileHeader from `IMAGE_NT_HEADERS` to carve out the file header
        source:bytes = buffer[int.from_bytes(DOS.header_offset):int.from_bytes(DOS.header_offset)+ctypes.sizeof(IMAGE_FILE_HEADER)+4] # +4 because the signature is four bytes and the file header structure does not include it
        image_headers: IMAGE_NT_HEADERS32 | IMAGE_NT_HEADERS64 | None = None
        if is_64bit:
            image_headers:IMAGE_NT_HEADERS64   = IMAGE_NT_HEADERS64() # see pepy/definitions.py
        else:
            image_headers:IMAGE_NT_HEADERS32  = IMAGE_NT_HEADERS32()
        
        # First 4 bytes(Which is also the signature) after MS-DOS stubs
        if source[0:4] == __class__.PE_SIGNATURE:
            # Only fills `image_headers` 'structure' if signature is valid
            image_headers.Signature = int.from_bytes(source[0:4], byteorder="little")
            ctypes.memmove(ctypes.byref(image_headers.FileHeader) ,ctypes.c_char_p(source[4:]), len(source[4:]))
            return image_headers
        else:
            return Code.ERR_INVALID_SIGNATURE    
        
    @staticmethod
    def print(image_nt_headers:IMAGE_NT_HEADERS64 | IMAGE_NT_HEADERS32, raw:bool = False)->None:
        ''' Print information about file header 
            
            image_nt_headers: Pretty self-explanatory
            raw: A bool value indicative of whether to show flags in a human readable format

            return: None
        '''

        print("File Header:")
        print(f"\t Signature: 0x{image_nt_headers.Signature.to_bytes(4, byteorder='little').hex().upper()}")
        for fname, ftype in image_nt_headers.FileHeader._fields_:
            fvalue = getattr(image_nt_headers.FileHeader, fname)
            if fname == "Machine":
                if raw:
                    print(f"\t Machine: {hex(image_nt_headers.FileHeader.Machine).ljust(4, '0')}")
                else:
                    print(f"\t Machine: {hex(image_nt_headers.FileHeader.Machine).ljust(4, '0')} ({get_machine_type(image_nt_headers.FileHeader.Machine)})")
                print()
                continue
            elif fname == "Characteristics":
                if raw:
                    print(f"\t Characteristics: {hex(image_nt_headers.FileHeader.Characteristics)}")
                else:
                    print(f"\t Characteristics: {hex(image_nt_headers.FileHeader.Characteristics)} ({get_characteristics(image_nt_headers.FileHeader.Characteristics)})")
                continue
            print(f"\t {fname}: {fvalue} ({hex(fvalue)})")
        print()


class PE_OPTIONAL:
    ''' This class abstracts the parsing of the optional header '''

    @staticmethod
    def parse(buffer:bytes, size:int, is_64bit:bool)->IMAGE_OPTIONAL_HEADER64 | IMAGE_OPTIONAL_HEADER32 | None:
        '''  parses the file and returns a `IMAGE_OPTIONAL_HEADER64` which  essentially
             acts as a structure

             buffer: bytes: contents of the file at least from the first byte of the file to the last byte of the optional header
             size: int: Size of the optional header which is obtained from the file header, IMAGE_NT_HEADERS64.FileHeader.SizeOfOptionalHeader

             return:A object acting as a struct which holds information about the optional header or None on failure   
        '''
        start:int = int.from_bytes(DOS.header_offset) + ctypes.sizeof(IMAGE_FILE_HEADER) + 4 # Index of start of optional header
        end:int = start + size # index of last byte of optional header + 1
        # Carving the portion of the file which represents the optional header
        source:bytes = buffer[start:end]
        opt_header: IMAGE_OPTIONAL_HEADER32 | IMAGE_OPTIONAL_HEADER64 | None = None 
        if is_64bit:
            opt_header = IMAGE_OPTIONAL_HEADER64()
            ctypes.memmove(ctypes.byref(opt_header), ctypes.c_char_p(source), len(source))
            return opt_header
        else:
             opt_header = IMAGE_OPTIONAL_HEADER32()
             ctypes.memmove(ctypes.byref(opt_header), ctypes.c_char_p(source), len(source))
             return opt_header
        # match int.from_bytes(source[0:2], byteorder="little"):
        #     case 0x20B:
        #         executable_type = "64-bit executable"
        #         logging.debug("64-bit executable detected")
        #         opt_header = IMAGE_OPTIONAL_HEADER64()
        #         ctypes.memmove(ctypes.byref(opt_header), ctypes.c_char_p(source), len(source))
        #         return opt_header
        #     case 0x10b:
        #         executable_type = "32-bit executable"
        #         logging.debug("32-bit executable detected")
        #         opt_header = IMAGE_OPTIONAL_HEADER32()
        #         logging.debug(f"Size of Optional header: {ctypes.sizeof(opt_header)} Bytes")
        #         ctypes.memmove(ctypes.byref(opt_header), ctypes.c_char_p(source), len(source))
        #         return opt_header
        #     case 0x107:
        #         executable_type = "ROM image"
        #         logging.debug("ROM image detected")
        #         return opt_header
    
    @staticmethod
    def print(image_nt_headers:IMAGE_NT_HEADERS64, raw:bool=False)->None:
        ''' Print information about file header 
            
            image_nt_headers: Pretty self-explanatory
            raw: A bool value indicative of whether to show flags in a human readable format

            return: None
        '''
        print("Optional header:")

        # A neat trick to obtain the values dynamically :)
        for fname, ftype in image_nt_headers.OptionalHeader._fields_:
            fvalue = getattr(image_nt_headers.OptionalHeader, fname)
            if fname == "DataDirectory":
                print(f"\t {fname}:".ljust(45) + "\t  " +"RVA".ljust(10) + "Size".ljust(10))
                for index in DATA_DIRECTORY_INDEX:
                    print(f" \t\t\\_______ {index.value[0]}: ".ljust(45) + f"{hex(fvalue[index.value[1]].VirtualAddress)}".ljust(10) + f"{hex(fvalue[index.value[1]].Size)}".ljust(10))
                continue
            if fname == "DllCharacteristics":
                if raw:
                    print(f"\t {fname}: {fvalue} {hex(fvalue)}")
                else:
                    print(f"\t {fname}: {fvalue} {hex(fvalue)} ({get_dll_characteristics(fvalue)})")
                continue
            print(f"\t {fname}: {fvalue} ({hex(fvalue)})")
        print()

def nt_print(image_nt_headers:IMAGE_NT_HEADERS64, section_headers:ctypes.Array[IMAGE_SECTION_HEADER], image_import_desc_arr:list[IMAGE_IMPORT_DESCRIPTOR] , buffer:bytes, is_64bit, base_reloc_arr:list[IMAGE_BASE_RELOCATION] | None , raw:bool=False)->None:
    ''' Prints all headers and section 
        
        image_nt_headers: IMAGE_NT_HEADERS64: An object/struct
        section_headers: ctypes.Array[IMAGE_SECTION_HEADER]: An array of IMAGE_SECTION_HEADER
        image_import_desc_arr: list[IMAGE_IMPORT_DESCRIPTOR]:
        buffer: bytes: The contents of the file itself
        is_64bit: bool: A boolean value which indicates whether it the file is 32 or 64 bit executable
        raw: A bool value indicative of whether to show flags in a human readable format

        return: None
    '''
    
    PE.print(image_nt_headers, raw)
    PE_OPTIONAL.print(image_nt_headers, raw)
    SECTION_HEADERS.print(section_headers, raw)
    Imports.print(image_import_desc_arr, buffer, is_64bit)
    Relocation.print(base_reloc_arr, buffer)

class SECTION_HEADERS:

    @staticmethod
    def parse(image_nt_headers:IMAGE_NT_HEADERS64|IMAGE_NT_HEADERS32, buffer:bytes)->ctypes.Array[IMAGE_SECTION_HEADER]:
        ''' The method essential returns an array where each elements is a `IMAGE_SECTION_HEADER using values of a `IMAGE_NT_HEADERS` struct `
        
        image_nt_headers: Self explanatory
        buffer: Contents of the file, at least from the first byte to the last byte of the section headers + 1

        return: An array of IMAGE_SECTION_HEADER
        '''

        # Index of first byte of section headers
        start:int = int.from_bytes(DOS.header_offset) + ctypes.sizeof(IMAGE_FILE_HEADER) + 4 + image_nt_headers.FileHeader.SizeOfOptionalHeader
        end:int = start + (ctypes.sizeof(IMAGE_SECTION_HEADER)* image_nt_headers.FileHeader.NumberOfSections) # Index of last of section headers + 1
        # A buffer containing the section headers
        buffer: bytes = buffer[start:end]
        section_headers_array:ctypes.Array[IMAGE_SECTION_HEADER] = (IMAGE_SECTION_HEADER * image_nt_headers.FileHeader.NumberOfSections)()
        ctypes.memmove(ctypes.byref(section_headers_array), ctypes.c_char_p(buffer), len(buffer))
        return section_headers_array

    @staticmethod
    def print(section_headers:ctypes.Array[IMAGE_SECTION_HEADER], raw:bool=False)->None:
        '''Parses the section headers

          section_headers: Pretty self-explanatory by now
          raw: A bool value indicative of whether to show flags in a human readable format
          
          return: None
        '''
        spacing:int  = 18
        print("Section Headers: ")
        print("\t " + "Name".ljust(spacing) + "Virtual Size".ljust(spacing) + "Virtual Address".ljust(spacing) + "Raw Data Size".ljust(spacing) + "Raw Data Ptr".ljust(spacing) + "Relocations Ptr".ljust(spacing) + "Line Num Ptr" .ljust(spacing) + "Relocations Num".ljust(spacing) + "Line Num Num".ljust(spacing) + "Chacteristics".ljust(spacing))
        for section_header in section_headers:
                if raw:    
                    print("\t " + f"{''.join([chr(char) if char != 0 else ' ' for char in section_header.Name])}".ljust(spacing) + f"{hex(section_header.Misc)}".ljust(spacing) + f"{hex(section_header.VirtualAddress)}".ljust(spacing) + f"{hex(section_header.SizeOfRawData)}".ljust(spacing) + f"{hex(section_header.PointerToRawData)}".ljust(spacing) + f"{hex(section_header.PointerToRelocations)}".ljust(spacing) + f"{hex(section_header.PointerToLinenumbers)}".ljust(spacing) + f"{hex(section_header.NumberOfRelocations)}".ljust(spacing) + f"{hex(section_header.NumberOfLinenumbers)}".ljust(spacing) + f"{hex(section_header.Characteristics)}")
                else: 
                    print("\t " + f"{''.join([chr(char) if char != 0 else ' ' for char in section_header.Name])}".ljust(spacing) + f"{hex(section_header.Misc)}".ljust(spacing) + f"{hex(section_header.VirtualAddress)}".ljust(spacing) + f"{hex(section_header.SizeOfRawData)}".ljust(spacing) + f"{hex(section_header.PointerToRawData)}".ljust(spacing) + f"{hex(section_header.PointerToRelocations)}".ljust(spacing) + f"{hex(section_header.PointerToLinenumbers)}".ljust(spacing) + f"{hex(section_header.NumberOfRelocations)}".ljust(spacing) + f"{hex(section_header.NumberOfLinenumbers)}".ljust(spacing) + f"{hex(section_header.Characteristics)}({get_section_flags(section_header.Characteristics)})".ljust(spacing))
        print()

class Imports:
    ''' Abstracts the parsing the imported functions'''
    
    # This value is subtracted from
    # Relative virtual addresses. Rvas are usually relative to the image base
    # which is only applicable if the file is loadde in memory. However this value
    # works a little different when the file in on disk.
    # The actual RVA is obtained by this equation  RVA = RVA - crucial_value
    crucial_value:int | None = None
    
    # These are used to keep track of the name of libraries imported and their offsets 
    # from the start of the file. RVAs used in this program invariably refer to offset from the beginning of the file and not from the image base
    name_to_index:dict[str, int] = {}  
    offset_arr:list[int] = []

    @staticmethod
    def parse(section_headers:ctypes.Array[IMAGE_SECTION_HEADER], buffer:bytes)-> list[IMAGE_IMPORT_DESCRIPTOR]:

        import_desc_arr:list[IMAGE_IMPORT_DESCRIPTOR] = []
        import_desc_size:int = ctypes.sizeof(IMAGE_IMPORT_DESCRIPTOR)
        rva:int
        actual_offset:int
        for section_header in section_headers:
            # Retrieve the IMAGE_SECTION_HEADER represent the .idata field
            if ("".join([chr(char) if char != 0 else ' ' for char in section_header.Name])).strip() == ".idata":
                rva = section_header.VirtualAddress
                __class__.crucial_value = rva - section_header.PointerToRawData
                actual_offset = rva - __class__.crucial_value # Told you...
        
        # Determine how many IMAGE_IMPORT_DESCRITOR in .idata section
        # Essentialy the start of this section contain at least
        # one `IMAGE_IMPORT_DESCRIPTOR`, the last one has all valued nulled out.
        # Therefore we stop if one of the structs has all their valued as zero
        count:int = 0
        while True:
            
            import_desc:IMAGE_IMPORT_DESCRIPTOR = IMAGE_IMPORT_DESCRIPTOR()
            ctypes.memmove(ctypes.byref(import_desc), ctypes.c_char_p(buffer[actual_offset+count:actual_offset+count+import_desc_size]), import_desc_size)
            count += import_desc_size
            if ((import_desc.OriginalFirstThunk == 0) and (import_desc.TimeDateStamp == 0) and (import_desc.ForwarderChain == 0) and ( import_desc.Name == 0) and (import_desc.FirstThunk == 0)):
                return import_desc_arr
            import_desc_arr.append(import_desc)
        
    @staticmethod
    def lookup_table_parse(abs_offset:int, buffer:bytes, is_64bit:bool)->tuple[str, int]:
        size:int
        ''' Parse the import lookup table
        
            abs_offset: int: The actual offset from the beginning of the file
            buffer: bytes: Teh contents of the file
            is_64bit: boolean value which indicates whether it the file is 32 or 64 bit executable

            return: A tuple of a string to use as output and the actual integer value of the actual offset
        '''

        if is_64bit:
            size = 8
        else:
            size = 4
        bytes_arr:list[int] = []
        for char in buffer[abs_offset:abs_offset+size]:
            bytes_arr.append(char)
        
        # Inshallah you understand this
        return (f"{' '.join([bin(char)[2:] for char in bytes_arr])} ({' '.join([hex(char) for char in bytes_arr])}) (offset to hint table: {hex(int.from_bytes(buffer[abs_offset:abs_offset+2], byteorder='little') - __class__.crucial_value)})", int.from_bytes(buffer[abs_offset:abs_offset+2], byteorder='little') - __class__.crucial_value)

    @staticmethod
    def print(import_desc_arr: list[IMAGE_IMPORT_DESCRIPTOR], buffer:bytes, is_64bit:bool)->None:
        ''' Parses the import directory table 
        
            import_desc_arr: An array of IMAGE_IMPORT_DESCRIPTOR
            buffer: bytes: contentents of the file
            is_64bit: A boolean value indicating whether the file is a 32 or 64 bit executable

            return: None
        '''

        library_name:list[str] = []
        print(" Imports:")
        for import_desc in import_desc_arr:
            actual_offset:int = import_desc.Name - __class__.crucial_value
            print(f"\t Absolute Offset :{hex(actual_offset)}")
            print(f"\t Name: ", end="")
            for char in buffer[actual_offset:]:
                if char:
                    print(f"{chr(char)}", end="")
                    library_name.append(chr(char))
                    continue
                __class__.offset_arr.append(__class__.lookup_table_parse(import_desc.OriginalFirstThunk - __class__.crucial_value, buffer, is_64bit)[1])
                __class__.name_to_index["".join(library_name)] = __class__.offset_arr.index(__class__.lookup_table_parse(import_desc.OriginalFirstThunk - __class__.crucial_value, buffer, is_64bit)[1]) 
                library_name = []
                break
            print()

            print(f"\t Import Lookup Table RVA: {hex(import_desc.OriginalFirstThunk - __class__.crucial_value)}")
            print(f"\t\t\\______ {__class__.lookup_table_parse(import_desc.OriginalFirstThunk - __class__.crucial_value, buffer, is_64bit)[0]}")
            print(f"\t Time Date Stamp: {import_desc.TimeDateStamp}")
            print(f"\t Forwarder chain: {import_desc.ForwarderChain} ({hex(import_desc.ForwarderChain)})")
            print(f"\t Import Address Table RVA: {hex(import_desc.FirstThunk - __class__.crucial_value)}")
            print(f"\t\t\\______ {__class__.lookup_table_parse(import_desc.FirstThunk - __class__.crucial_value, buffer, is_64bit)[0]}")
            print()
            print("-"*100)
            print()
        
        print(" Hint Table: ")
        # The code below simple parses the hint tables pointed by
        # IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk
        # The length of the simple task is due to the fact that
        # Each hint table entry does not have a fix size due
        # to varying lengh of function names
        # Of course their sizes can be calculated except for the last one
        # which does not have any other hint table entry after it. Therefore
        # we cannot its offset to determine the size of the last entry
        for name, index in __class__.name_to_index.items():
            try:
                printed:bool = False
                hint_table_size:int = __class__.offset_arr[index+1] - __class__.offset_arr[index]
                hint_table_buffer:bytes = buffer[__class__.offset_arr[index]:__class__.offset_arr[index]+hint_table_size]
                start_index:int = 0
                print()
                print(f"\t {name}: ".ljust(8))
                print("\t\t" + f"Hint".ljust(8), "Name")

                count:int = 0
                while start_index < len(hint_table_buffer):
                    printed = False
                    char = hint_table_buffer[count]
                    if not char:
                        image_import_by_name:IMAGE_IMPORT_BY_NAME = IMAGE_IMPORT_BY_NAME()
                        hint_number:bytes = hint_table_buffer[start_index:start_index+IMAGE_IMPORT_BY_NAME.Hint.size]
                        func_name:bytes = hint_table_buffer[start_index+IMAGE_IMPORT_BY_NAME.Hint.size: hint_table_buffer.index(char, start_index+IMAGE_IMPORT_BY_NAME.Hint.size)]
                        image_import_by_name.Hint = int.from_bytes(hint_number, byteorder="little")
                        image_import_by_name.Name = ctypes.c_char_p(func_name)
                        print("\t\t" + f"{image_import_by_name.Hint}".ljust(8) + f"{''.join([chr(char) for char in image_import_by_name.Name])}")
                        printed = True
                        start_index = (hint_table_buffer.index(char, start_index+IMAGE_IMPORT_BY_NAME.Hint.size))
                        if  hint_table_buffer[start_index+1]:
                            start_index += 1
                            count += 1
                            continue
                        start_index += 2
                        count += 1
                        continue
                    count+=1
                           
            except (IndexError,ValueError):
                if printed:
                    continue
                print()
                start_index:int = 0
                try:
                    hint_table_buffer = buffer[__class__.offset_arr[index]:]
                except IndexError:
                    break
                print(f"\t {name}: ".ljust(8))
                print("\t\t" + f"Hint".ljust(8), "Name")
                while True:
                    image_import_by_name:IMAGE_IMPORT_BY_NAME = IMAGE_IMPORT_BY_NAME()
                    hint_number:bytes = hint_table_buffer[start_index:start_index+IMAGE_IMPORT_BY_NAME.Hint.size]
                    func_name:bytes = hint_table_buffer[start_index+IMAGE_IMPORT_BY_NAME.Hint.size: hint_table_buffer.index(char, start_index+IMAGE_IMPORT_BY_NAME.Hint.size)+1]
                    image_import_by_name.Hint = int.from_bytes(hint_number, byteorder="little")
                    image_import_by_name.Name = ctypes.c_char_p(func_name)
                    start_index = (hint_table_buffer.index(char, start_index+IMAGE_IMPORT_BY_NAME.Hint.size))
                    if not "".join([chr(char) for char in image_import_by_name.Name]) :
                        logging.debug("End of image_by_imports")
                        break
                    if  hint_table_buffer[start_index+1]:
                        start_index += 1
                        print("\t\t" + f"{(image_import_by_name.Hint)}".ljust(8) + f"{''.join([chr(char) for char in image_import_by_name.Name])}")
                        continue
                    start_index +=2 
                    print("\t\t" + f"{(image_import_by_name.Hint)}".ljust(8) + f"{''.join([chr(char) for char in image_import_by_name.Name])}")
                
class Relocation:
    ''' Abstracts parsing of relocation table '''

    # This value is subtracted from
    # Relative virtual addresses. Rvas are usually relative to the image base
    # which is only applicable if the file is loadde in memory. However this value
    # works a little different when the file in on disk.
    # The actual RVA is obtained by this equation  RVA = RVA - crucial_value
    crucial_value:int | None = None
    
    offset:list[int] = []
    


    @staticmethod
    def parse(section_headers:ctypes.Array[IMAGE_SECTION_HEADER], buffer:bytes)-> list[IMAGE_BASE_RELOCATION] | None:

        rva:int
        actual_offset:int
        reloc_section_size: int
        base_reloc_arr:list[IMAGE_BASE_RELOCATION] = []
        for section_header in section_headers:
            # Retrieve the IMAGE_SECTION_HEADER represent the .idata field
            if ("".join([chr(char) if char != 0 else ' ' for char in section_header.Name])).strip() == ".reloc":
                rva = section_header.VirtualAddress
                __class__.crucial_value = rva - section_header.PointerToRawData
                actual_offset = rva - __class__.crucial_value # Told you...
                reloc_section_size = section_header.Misc
            else:
                return None

        while True:
            base_reloc: IMAGE_BASE_RELOCATION = IMAGE_BASE_RELOCATION()
            ctypes.memmove(ctypes.byref(base_reloc), ctypes.c_char_p(buffer[actual_offset:]), ctypes.sizeof(IMAGE_BASE_RELOCATION))
            if (base_reloc.VirtualAddress == 0) and (base_reloc.SizeOfBlock == 0):
                break
            base_reloc_arr.append(base_reloc)
            __class__.offset.append(actual_offset)
            actual_offset += base_reloc.SizeOfBlock
        return base_reloc_arr
    
    @staticmethod
    def print(base_reloc_arr:list[IMAGE_BASE_RELOCATION] | None, buffer:bytes)->None:
        if base_reloc_arr is None:
            return None
        print("Relocation Table:")
        print("\t Offset".ljust(15) + "Page RVA".ljust(15) + "Size".ljust(10) + "entries")
        for index,base_reloc_block in enumerate(base_reloc_arr):
            print("\t " + f"{hex(__class__.offset[index])}".ljust(15)  + f"{hex(base_reloc_block.VirtualAddress)}".ljust(15) + f"{hex(base_reloc_block.SizeOfBlock)}".ljust(10) + f"{ceil((base_reloc_block.SizeOfBlock-ctypes.sizeof(IMAGE_BASE_RELOCATION))/2)}")


def main() -> None:

    # Main program
    pe_file:str = args.file.strip()
    file_contents: bytes | None = None
    if (os.path.exists(pe_file)) and (os.path.isfile(pe_file)):
        logging.debug("User supplied file passed checks, proceeding to open file...")
    else:
        logging.error("Either the path supplied is not a file or it does not exist")
        error("Either the path supplied is not a file or it does not exist")
        return
    
    stat_info = os.stat(pe_file)    
    info(f" File size --> {stat_info.st_size} bytes ({stat_info.st_size >> 10} KB)")
    
    with open(pe_file, "rb") as file:
        file_contents = file.read()
        logging.debug(f" Read {len(file_contents)} bytes from file")
    
    is_file_64bit:bool = is_64bit(file_contents)
    if is_file_64bit:
        info(" 64-bit file detected...")
    else:
        info("32-bit file detected...")
    # Parses the DOS header and automatically outputs results
    if DOS.parse(file_contents) ==  Code.ERR_INVALID_SIGNATURE:
        error("Invalid DOS magic number")
        return
    
    # At this point the OptionalHeader Fields is still empty
    nt_file_headers:IMAGE_NT_HEADERS64 | IMAGE_NT_HEADERS32 = PE.parse(file_contents, is_file_64bit)
    
    # The program exits if the first four bytes of the header (the signature)
    # does not match PE\0\0
    if nt_file_headers== Code.ERR_INVALID_SIGNATURE:
        error("Invalid PE signature")
        return 
    
    optional_header:IMAGE_OPTIONAL_HEADER32 |IMAGE_OPTIONAL_HEADER64 = PE_OPTIONAL.parse(file_contents, nt_file_headers.FileHeader.SizeOfOptionalHeader, is_file_64bit)
    nt_file_headers.OptionalHeader = optional_header

    section_headers: ctypes.Array[IMAGE_SECTION_HEADER] = SECTION_HEADERS.parse(nt_file_headers, file_contents)
 
    import_desc_arr:list[IMAGE_IMPORT_DESCRIPTOR] = Imports.parse(section_headers, file_contents)

    base_reloc_arr:list[IMAGE_BASE_RELOCATION] = Relocation.parse(section_headers, file_contents)

    if args.raw:
        nt_print(nt_file_headers, section_headers, import_desc_arr, file_contents, is_file_64bit, base_reloc_arr ,raw=True)
        return
    nt_print(nt_file_headers, section_headers, import_desc_arr, file_contents ,is_file_64bit, base_reloc_arr)
   
        
if __name__== "__main__":

    # Parses command line arguements
    parser = argparse.ArgumentParser(formatter_class = argparse.RawTextHelpFormatter,description="A python program that parses PE files", epilog=f"Usage: \n\tpython {FILE_NAME} -f example.exe")
    parser.add_argument("-f", "--file", help="Path to file", dest="file", type=str, required=True)
    parser.add_argument("-d", "--debug", help="Show debug messages", dest="debug", action="store_true")
    parser.add_argument("-r", "--raw", help="Does not parse values that represent flags/Charavteristics. Only shows raw value", dest="raw", action="store_true")
    
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(format="[%(asctime)s] [%(filename)s:%(lineno)d] [%(levelname)s] - %(message)s", level=logging.DEBUG, datefmt="%Y-%m-%d %H:%M:%S")
        logging.debug(args)
    else:
        logging.basicConfig(format="[%(asctime)s] [%(filename)s:%(lineno)d] [%(levelname)s]  - %(message)s", level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S")
    main()
    info("Exiting Program")
