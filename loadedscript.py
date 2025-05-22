from elftools.elf.sections import SymbolTableSection
from elftools.elf.elffile import ELFFile
from collections import defaultdict

import capstone
import gdb
import pickle
import json5 as json
import ipdb

primitive_types = [gdb.TYPE_CODE_INT,  gdb.TYPE_CODE_FLT, 
                   gdb.TYPE_CODE_BOOL, gdb.TYPE_CODE_CHAR,  gdb.TYPE_CODE_ENUM
                  ]

ptr_types = [gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_REF, gdb.TYPE_CODE_METHODPTR, gdb.TYPE_CODE_MEMBERPTR]
complex_types = [ gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION, gdb.TYPE_CODE_ARRAY]
func_types = [gdb.TYPE_CODE_FUNC, gdb.TYPE_CODE_METHOD]

def find_function_bounds(elffile, function_name):
    for section in elffile.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        
        for symbol in section.iter_symbols():
            if symbol.name == function_name:
                return symbol['st_value'], symbol['st_size']
    
    return None, None

def find_ret_addresses(objname, funname):
    rets = set()
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

            arch = gdb.selected_frame().architecture()
            if arch.name() == 'i386:x86-64':
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            
            for i in md.disasm(function_code, function_addr):
                if i.mnemonic == 'pop' and (i.op_str == 'rbp' or i.op_str == 'ebp'):
                    print("Found ret at 0x{:x}".format(i.address))
                    rets.add(hex(i.address))

    return rets

def parse_value(raw):
    try:
        rawtype = raw.type.strip_typedefs()
        typecode = rawtype.code

        if typecode in primitive_types:
            return str(raw)
        elif typecode in ptr_types:
            try: 
                defer = raw.referenced_value()
                if defer.type.code in primitive_types and '"' in str(raw):
                    strv = str(raw)
                    left = strv.find('"')
                    right = strv.rfind('"')
                    if left!=-1 and right!=-1:
                        return {"pointo": strv[left+1: right]}
            except Exception as e: # defer void* will result in error
                print("deal with pointer error: %s", e)
                #ipdb.post_mortem()
                return "void*"
            referencedvalue = parse_value(defer)
            return { "pointo": referencedvalue }
        elif typecode in complex_types:
            fields = rawtype.fields()
            subdata = {}
            for i, field in enumerate(fields):
                if typecode == gdb.TYPE_CODE_ARRAY:
                    indexvalue = raw[i]
                else:
                    indexvalue = raw[field]
                sub_value = parse_value(indexvalue)
                subdata[i] = sub_value
            return subdata
        elif typecode in func_types:
            return "func" 
        else:
            raise Exception("unsupported type")
    except Exception as e:
        ipdb.post_mortem()
        print("------------------------------------------")


def load_meta(meta_file, debugged_fun):
    data = {}
    try:
        with open(meta_file) as f:
            data = json.load(f)
    except Exception as e:
        print("load meta error: %s\n", e)
    finally:
        if "names" in data and debugged_fun in data["names"]:
            return data["names"][debugged_fun]
        else:
            return {}

def get_value(rawname):
    try:
        rawvalue = gdb.parse_and_eval(rawname)
        parsedvalue = parse_value(rawvalue)
        return parsedvalue
    except Exception as e:
        print("get value of %s error", rawname)
        #ipdb.post_mortem()
        return ""

def get_array_values(metadata, arrayname):
    gvalues = {}
    for name in metadata[arrayname]:
        gvalue = get_value(name)
        gvalues[name] = gvalue
    return gvalues

def collect_data(metadata, is_return):
    res = {}
    if "funargs" in metadata:
        res["funargs"] = get_array_values(metadata, "funargs")

    if "globals" in metadata:
        res["globals"] = get_array_values(metadata, "globals")

    if is_return:
        arch = gdb.selected_frame().architecture()
        if arch.name() == 'i386:x86-64':
            retreg = "$rax"
        else:
            retreg = "$eax"
        try:
            retvalue = get_value(retreg)
            res["retvalue"] = retvalue       
        except Exception as e:
            print("get return value error :%s", e)
            res["retvalue"] = ""
    return res


gdb.execute("set pagination off")
gdb.execute("b " + debugged_fun)
gdb.execute("run")

metadata = load_meta(meta_file, debugged_fun)
rets = find_ret_addresses(exefile, debugged_fun)

try:
    start_data = collect_data(metadata, False)
except Exception as e:
    print("collect function start data error: %s", e)
    start_data = {}

for ret in rets:
   gdb.execute("b *" + ret)

gdb.execute("c")

try:
    end_data = collect_data(metadata, True)
except Exception as e:
    print("collect function end data error: %s", e)
    end_data = {}

res = {}
res['start_data'] = start_data
res['end_data'] = end_data

gdb.execute("c")

with open(result_file, "w") as f:
    json.dump(res, f)


gdb.execute("q")
