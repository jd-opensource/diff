#pragma once
#include "headers.h"

#define STRUCT_ALIGN(offset, align) (((offset) + (align) - 1) & ~((align) - 1))
#define ENUM_TO_STRING_CASE(name) case name: return #name;


class array_t {
public:
    int array_len;
    int array_type;
} ;

class elements_t{
public:
    int element_type;
    int element_offset;
};

class struct_t {
public:
    vector<elements_t> struct_elements;
    std::string struct_name;
    int struct_num;
    int struct_size;
    int struct_alignment;
    bool struct_packed;
    bool struct_computed;
} ;

class pointer_t {
public:
    int pointee_type;
};

class function_t {
public:
    vector<int> func_parameters;
    int func_returntype;
    int func_num_parameters;
    bool func_isargvar;
} ;

class type_t {
public:
    Type::TypeID typecode;
    int intxbits; 
    array_t iarray;
    struct_t istruct;
    pointer_t ipointer;
    function_t ifunction;
};

std::string TypeId2String(Type::TypeID tmptypeid);
