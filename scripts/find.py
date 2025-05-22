from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import capstone


def find_function_bounds(elffile, function_name):
    for section in elffile.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        
        for symbol in section.iter_symbols():
            if symbol.name == function_name:
                return symbol['st_value'], symbol['st_size']
    
    return None, None

def find_ret_address(objname, funname):
    rets = []
    with open(objname, 'rb') as f:
        elffile = ELFFile(f)
        
        function_addr, function_size = find_function_bounds(elffile, funname)
        if function_addr is None:
            print("Function not found in the ELF file.")
        else:
            code_section = elffile.get_section_by_name('.text')
            code = code_section.data()
            code_address = code_section['sh_addr']
            
            function_offset = function_addr - code_address
            
            function_code = code[function_offset:function_offset+function_size]
            
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            
            for i in md.disasm(function_code, function_addr):
                if i.mnemonic == 'pop' and (i.op_str == 'rbp' or i.op_str == 'ebp'):
                    retaddr = hex(i.address)
                    import ipdb;ipdb.set_trace()
                    print("Found ret at 0x{:x}".format(i.address))

find_ret_address('./a.out', "bcftest")
