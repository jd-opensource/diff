#pragma once

#include "type.h"

class TypeAnalysis{
    public:
        std::map<Value *, int> valuemaps;
        std::map<Type *, int> typemaps;

        std::map<int, Type*> ptr2typemaps;
        int ptr2type_count; 

        vector<type_t> analysedtypes;
 
        std::set<Function*> analysedfuns;

        Function* curfunction;

        /* EXTENV */
        std::map<Function*, set<GlobalVariable*>> extenv_globals;
        std::map<Function*, set<Value*>> extenv_funargs;
        std::map<Function*, set<Value*>> extenv_retvals;

        TypeAnalysis();

        void analysis_function(Function* F);
        void analysis_inst(Instruction *ins);
        void analysis_funargs(Function* F);


        type_t create_newtype(Type *ty);

        int create_pointer(int typeindex);

        int create_value_and_get_index(Value* value);
        int create_type_and_get_index(Type* ty);


        type_t *find_type_by_index(int typeindex);
        void struct_padding_analysis(type_t *type);
        int get_typesize(const type_t *type);
        int calc_pointer_padding(const type_t *type);
        void adjust_struct_padding();


        void dumps(string modulename);
        json type_dump(const type_t type);
};

void analysis_error(const char *fmt, ...);

