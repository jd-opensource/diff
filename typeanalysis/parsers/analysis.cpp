#pragma once

#include "analysis.h"


TypeAnalysis::TypeAnalysis(){
    this->ptr2type_count = 2;
}

void TypeAnalysis::analysis_function(Function* F){
    create_value_and_get_index(F);
    analysis_funargs(F);

    for(auto bbl = F->begin(); bbl != F->end(); bbl++){
        BasicBlock *BB = &*bbl;

        for(auto ins = bbl->begin(); ins != bbl->end(); ins++){
            Instruction *inst = dyn_cast<Instruction>(ins); 
            for (unsigned idx = 0; idx < inst->getNumOperands(); idx++) {       
                if (ConstantExpr * Op = dyn_cast<ConstantExpr>(inst->getOperand(idx))) {
                    Instruction * const_inst = Op->getAsInstruction();
                    const_inst->insertBefore(inst);
                    inst->setOperand(idx, const_inst);

                    analysis_inst(const_inst);
                } 
            }
            analysis_inst(inst); 
        }
    }
    adjust_struct_padding(); 
}


type_t TypeAnalysis::create_newtype(Type *ty){
    type_t newtype;
    Type::TypeID tmptypeid = ty->getTypeID();

    newtype.typecode = tmptypeid;
    switch(tmptypeid) {
        case Type::IntegerTyID:{
            newtype.intxbits = ty->getIntegerBitWidth();
            break;
        }
            
        case Type::ArrayTyID:{
            newtype.iarray.array_len = ty->getArrayNumElements();
            Type* arrayelementtype =  ty->getArrayElementType();
            newtype.iarray.array_type = create_type_and_get_index(arrayelementtype);
            break;
        }

        case Type::StructTyID:{
            StructType* newty = (StructType*)ty;
            if(newty->hasName()){
                newtype.istruct.struct_name = std::string(newty->getStructName().str());                        
            }else{
                newtype.istruct.struct_name = std::string();
            }
            
            newtype.istruct.struct_computed = false;
            newtype.istruct.struct_num = newty->getStructNumElements();
            
            newtype.istruct.struct_elements.reserve(newtype.istruct.struct_num);
            newtype.istruct.struct_elements.resize(newtype.istruct.struct_num);

            if(newty->isPacked()){
                newtype.istruct.struct_packed = true;
            }else{
                newtype.istruct.struct_packed = false;
            }
            
            for(int i = 0; i < newtype.istruct.struct_num; i++) {
                Type* tmpelementtype = newty->getElementType(i);
                if(tmpelementtype->isPointerTy()){
                    Type* pointee = tmpelementtype->getPointerElementType();
                    this->ptr2typemaps[this->ptr2type_count] = pointee;
                    newtype.istruct.struct_elements[i].element_type = -this->ptr2type_count;
                    this->ptr2type_count += 1;
                    
                }else{
                    newtype.istruct.struct_elements[i].element_type = create_type_and_get_index(newty->getElementType(i));
                } 
            }

            break;
        }

        case Type::PointerTyID:{
            Type* pointeetype =  ty->getPointerElementType();
            newtype.ipointer.pointee_type = create_type_and_get_index(pointeetype);

            break;
        }

        case Type::FunctionTyID:{
            FunctionType* newty = (FunctionType*)ty;
            if(newty->isVarArg()){
                newtype.ifunction.func_isargvar = 1;
            }else{
                newtype.ifunction.func_isargvar = 0;
            }

            newtype.ifunction.func_returntype = create_type_and_get_index(newty->getReturnType());
            newtype.ifunction.func_num_parameters = newty->getNumParams();

            newtype.ifunction.func_parameters.reserve(newtype.ifunction.func_num_parameters);
            newtype.ifunction.func_parameters.resize(newtype.ifunction.func_num_parameters);

            for(int i = 0; i < newtype.ifunction.func_num_parameters; i++){
                Type* tmpelementtype = newty->getParamType(i);

                if(tmpelementtype->isPointerTy()){
                    Type* pointee1 = tmpelementtype->getPointerElementType();
                    this->ptr2typemaps[this->ptr2type_count] = pointee1;
                    newtype.ifunction.func_parameters[i] = -this->ptr2type_count;
                    this->ptr2type_count += 1;
                }else{
                    newtype.ifunction.func_parameters[i] = create_type_and_get_index(newty->getParamType(i));
                }    
            }

            break;
        }

        default:
            break;
    }
    return newtype;
}

type_t *TypeAnalysis::find_type_by_index(int typeindex){
    if(typeindex >= this->analysedtypes.size() || typeindex < 0 ){
        analysis_error("get a error typeindex %d", typeindex);
    }
    return &this->analysedtypes[typeindex];
}

int TypeAnalysis::get_typesize(const type_t *tmptype){
    switch(tmptype->typecode) {
        case Type::VoidTyID:
            return 0;
        case Type::IntegerTyID:
            switch(tmptype->intxbits){
                case 1:
                    return 1;
                default:
                    return tmptype->intxbits/8;
            }
        case Type::FloatTyID:
            return 4;
        case Type::DoubleTyID:
            return 8;

        case Type::FunctionTyID:
        case Type::PointerTyID:
            return sizeof(intptr_t);

        case Type::StructTyID:
            return tmptype->istruct.struct_size;

        case Type::ArrayTyID:
            return get_typesize(find_type_by_index(tmptype->iarray.array_type)) * tmptype->iarray.array_len;
        default:
            cout << "===========================================================================" << endl;
            cout << TypeId2String(tmptype->typecode)   << endl;
            cout << "===========================================================================" << endl;
            analysis_error("Unable to compute size of type\n");
    }
}

int TypeAnalysis::calc_pointer_padding(const type_t *tmptype){
    switch(tmptype->typecode) {
        case Type::VoidTyID:
            return 0;
        case Type::FloatTyID:
            return 4;
        case Type::DoubleTyID:
            return 8;
        case Type::IntegerTyID:{
            switch(tmptype->intxbits){
                case 1:
                    return 1;
                default:
                    return tmptype->intxbits/8;
            }
            break;
        }
        case Type::PointerTyID:
            return sizeof(intptr_t);

        case Type::StructTyID:
            return tmptype->istruct.struct_alignment;

        case Type::ArrayTyID:
            return calc_pointer_padding(find_type_by_index(tmptype->iarray.array_type));
        default:
              analysis_error("Unable to compute struct_alignment for type\n");
    }
}

void TypeAnalysis::struct_padding_analysis(type_t *tmptype){
    int struct_offset = 0;
    int ba = 1;
    for(int i = 0; i < tmptype->istruct.struct_num; i++) {
        type_t *ty = find_type_by_index(tmptype->istruct.struct_elements[i].element_type);

        if(ty->typecode == Type::StructTyID && !ty->istruct.struct_computed){
            struct_padding_analysis(ty);
        }

        int tmpsize = get_typesize(ty);

        if(!tmptype->istruct.struct_packed) {
            int a = calc_pointer_padding(ty);
            struct_offset = STRUCT_ALIGN(struct_offset, a);
            ba = std::max(ba, a);
        }
        tmptype->istruct.struct_elements[i].element_offset = struct_offset;
        struct_offset += tmpsize;
    }
    tmptype->istruct.struct_size = tmptype->istruct.struct_packed ? struct_offset : STRUCT_ALIGN(struct_offset, ba);
    tmptype->istruct.struct_alignment = ba;
    tmptype->istruct.struct_computed = true;
}

void TypeAnalysis::analysis_inst(Instruction *I){
    if(ReturnInst * inst = dyn_cast<ReturnInst>(I)){
        this->extenv_retvals[this->curfunction].insert(inst->getReturnValue());
    }
    for (unsigned i = 0; i < I->getNumOperands(); ++i) {
        Value *Operand = I->getOperand(i);

        create_type_and_get_index(Operand->getType());
        create_value_and_get_index(Operand);
    }
    create_type_and_get_index(I->getType());
    create_value_and_get_index(I);
}

int TypeAnalysis::create_value_and_get_index(Value* value){
    if(this->valuemaps.find(value) != this->valuemaps.end()){
        return this->valuemaps[value];
    }else{
        int index = this->valuemaps.size();
        this->valuemaps.insert(pair<Value *, int>(value, index));
        
        if(value->getValueID() == Value::FunctionVal || value->getValueID() == Value::GlobalIFuncVal ){

            Function* F = dyn_cast<Function>(value);
            create_type_and_get_index(F->getFunctionType());

        }else if(value->getValueID() == Value::GlobalVariableVal){
            GlobalVariable* gvalue = dyn_cast<GlobalVariable>(value);
            create_type_and_get_index(gvalue->getValueType());
            create_type_and_get_index(gvalue->getType());

            if(gvalue->hasInitializer()){
                Constant* init_con = gvalue->getInitializer();
                create_type_and_get_index(init_con->getType());
            }
            /* EXTENV */

            if(!gvalue->isConstant()){
                this->extenv_globals[this->curfunction].insert(gvalue);
            }
        }else if(value->getValueID() == Value::ConstantDataArrayVal){ 
            unsigned int curindex = create_type_and_get_index(value->getType());
        }else if(value->getValueID() == Value::ConstantArrayVal || value->getValueID() == Value::ConstantStructVal || value->getValueID() == Value::ConstantAggregateZeroVal || value->getValueID() == Value::ConstantVectorVal){ // VALUECLASS::AGGREGATE
            User* uservalue = dyn_cast<User>(value);
            for(int i = 0; i < uservalue->getNumOperands(); i++) {
                Value* vv = uservalue->getOperand(i);
                create_type_and_get_index(vv->getType());
            }
        }
        
        return index;
    }
}


int TypeAnalysis::create_type_and_get_index(Type* ty){

    if(this->typemaps.find(ty) != this->typemaps.end()){
        return this->typemaps[ty];
    }
    
    type_t newtype = create_newtype(ty);

    int r = this->analysedtypes.size();
    this->analysedtypes.push_back(newtype); 

    this->typemaps.insert(pair<Type *, int>(ty, r));
    
    if(newtype.typecode == Type::StructTyID){
        for(int i = 0; i < newtype.istruct.struct_num; i++) {
            if(newtype.istruct.struct_elements[i].element_type < -1){
                Type* pointee1 = this->ptr2typemaps[-newtype.istruct.struct_elements[i].element_type];
                if(this->typemaps.find(pointee1) != this->typemaps.end()){
                    int typeindex =  this->typemaps[pointee1];
                    newtype.istruct.struct_elements[i].element_type = create_pointer(typeindex);
                }else{
                    int typeindex = create_type_and_get_index(pointee1);
                    newtype.istruct.struct_elements[i].element_type = create_pointer(typeindex);
                }
            }
        }
    }else if(newtype.typecode == Type::FunctionTyID){
        for(int i = 0; i < newtype.ifunction.func_num_parameters; i++){
            if(newtype.ifunction.func_parameters[i] < -1){
                Type* pointee1 = this->ptr2typemaps[-newtype.ifunction.func_parameters[i]];
                if(this->typemaps.find(pointee1) != this->typemaps.end()){
                    int typeindex =  this->typemaps[pointee1];
                    newtype.ifunction.func_parameters[i] = create_pointer(typeindex);
                }else{
                    int typeindex = create_type_and_get_index(pointee1);
                    newtype.ifunction.func_parameters[i] = create_pointer(typeindex);
                }
            }
        }         
    }
    
    return r;

} 

void TypeAnalysis::analysis_funargs(Function* F){
    int index = create_type_and_get_index(F->getFunctionType());

    type_t *tmptype = find_type_by_index(index);

    for(int i = 0; i < tmptype->ifunction.func_num_parameters; i++){
        Value * argvalue = F->getArg(i);

        if(argvalue->getType()->getTypeID() == Type::PointerTyID){
            this->extenv_funargs[F].insert(argvalue); 
        }
    }
}


void TypeAnalysis::adjust_struct_padding(){
    for(int i = 0; i < this->analysedtypes.size(); i++) {
        type_t *tmptype = &this->analysedtypes[i];
        if(tmptype->typecode == Type::StructTyID && !tmptype->istruct.struct_computed) {
            struct_padding_analysis(tmptype);
        }
    }
}

int TypeAnalysis::create_pointer(int typeindex){
    for(int i = 0; i < this->analysedtypes.size(); i++) {
        type_t tmptype = this->analysedtypes[i];
        if(tmptype.typecode == Type::PointerTyID && tmptype.ipointer.pointee_type == typeindex)
            return i;
    }

    type_t tmptype;
    int r = this->analysedtypes.size();
    tmptype.typecode = Type::PointerTyID;
    tmptype.ipointer.pointee_type = typeindex;
    this->analysedtypes.push_back(tmptype); 
    return r;
}


void TypeAnalysis::dumps(string modulename){            
    json all;
    
    json json_types;
    json json_names;
    for(auto tmptype = this->analysedfuns.begin(); tmptype != this->analysedfuns.end(); tmptype++){
        Function* curfun = *tmptype;
        string fname = curfun->getName().data();
        for(auto it_global = this->extenv_globals[curfun].begin(); it_global !=  this->extenv_globals[curfun].end(); it_global++){
            Type* it_global_type = (*it_global)->getType();
            int it_global_typepid = this->typemaps[it_global_type];
            type_t* it_global_irtype = this->find_type_by_index(it_global_typepid);

            json subtype = type_dump(*it_global_irtype); 
            json_types[fname]["globals"].push_back(subtype);
            //////////////////////////////////////////////////////////////////////
            if((*it_global)->hasName()){
                string subname = (*it_global)->getName().data();
                json_names[fname]["globals"].push_back(subname);
            }
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        for(auto it_arg = this->extenv_funargs[curfun].begin(); it_arg !=  this->extenv_funargs[curfun].end(); it_arg++){
            Type* it_arg_type = (*it_arg)->getType();
            int it_arg_typepid = this->typemaps[it_arg_type];
            type_t* it_arg_irtype = this->find_type_by_index(it_arg_typepid);

            json subtype = type_dump(*it_arg_irtype); 
            json_types[fname]["funargs"].push_back(subtype);
            //////////////////////////////////////////////////////////////////////
            if((*it_arg)->hasName()){
                string subname = (*it_arg)->getName().data();
                json_names[fname]["funargs"].push_back(subname);
            }
        }


        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////

        for(auto it_ret = this->extenv_retvals[curfun].begin(); it_ret !=  this->extenv_retvals[curfun].end(); it_ret++){
            Type* it_ret_type = (*it_ret)->getType();
            int it_ret_typepid = this->typemaps[it_ret_type];
            type_t* it_ret_irtype = this->find_type_by_index(it_ret_typepid);

            json subtype = type_dump(*it_ret_irtype); 
            json_types[fname]["retvals"].push_back(subtype);
            //////////////////////////////////////////////////////////////////////
            /*                     
                if((*it_ret)->hasName()){
                    string subname = (*it_ret)->getName().data();
                    json_names[fname]["retvals"].push_back(subname);
                } 
            */
        }    


    }
    all["types"] = json_types;
    all["names"] = json_names;

    std::ofstream outstream(modulename);

    outstream << all << std::endl;

}


json TypeAnalysis::type_dump(const type_t tmptype){
    char tmpbuf[128];
    char* append = "";
    int len = 0;

    json typeobj;
    switch(tmptype.typecode){
        
        case Type::VoidTyID:
            typeobj["typename"] = "void";
            break; 
        case Type::IntegerTyID:
            switch(tmptype.intxbits){
                case 1:
                    typeobj["typename"] = "i1";
                    break;   
                case 8:
                    typeobj["typename"] = "i8";
                    break; 
                case 16:
                    typeobj["typename"] = "i16";
                    break; 
                case 32:
                    typeobj["typename"] = "i32";
                    break;
                case 64:
                    typeobj["typename"] = "i64";
                    break;
                default:
                    snprintf(tmpbuf, sizeof(tmpbuf), "i%d", tmptype.intxbits);
                    typeobj["typename"] = tmpbuf;
            } 
            break;

        case Type::FloatTyID: 
            typeobj["typename"] = "float";
            break;   
        case Type::DoubleTyID:
            typeobj["typename"] = "double";
            break;  
        case Type::MetadataTyID:
            typeobj["typename"] = "metadata";
            break;  
        case Type::LabelTyID :      
            typeobj["typename"] = "label";
            break;          
        case Type::StructTyID:{
            typeobj["typename"] = "struct";
            typeobj["length"] = tmptype.istruct.struct_num;

            
            for(int i = 0; i < tmptype.istruct.struct_num; i++) {
                int tmptypeindex = tmptype.istruct.struct_elements[i].element_type;
                if(tmptypeindex > this->analysedtypes.size()){
                    analysis_error("dump struct type error!\n");
                }
                json subtypeobj = type_dump(this->analysedtypes[tmptypeindex]);
                typeobj[std::to_string(i)]["data"] = subtypeobj;
                typeobj[std::to_string(i)]["offset"] = tmptype.istruct.struct_elements[i].element_offset;
            }
            break;
        } 
        case Type::ArrayTyID:{
            int typdepid = tmptype.iarray.array_type;
            if(typdepid > this->analysedtypes.size()){
                analysis_error("dump array type error!\n");
            }
            json subtypeobj = type_dump(this->analysedtypes[typdepid]);
            typeobj["typename"] = "array";
            typeobj["length"] = tmptype.iarray.array_len;
            typeobj["type"] = subtypeobj;
            break;
        } 
        case Type::PointerTyID:{
            typeobj["typename"] = "pointer";
            if(tmptype.ipointer.pointee_type == -1) {
                typeobj["pointee"] = "void";
            } else {
                int typdepid = tmptype.ipointer.pointee_type;
                if(typdepid > this->analysedtypes.size()){
                    analysis_error("dump pointer type error!\n");
                }               
                json subtypeobj = type_dump(this->analysedtypes[typdepid]);
                typeobj["pointee"] = subtypeobj;
            }
            break; 
        }
        case Type::FunctionTyID:{
            typeobj["typename"] = "funtype";
            int typdepid = tmptype.ifunction.func_returntype;
            if(typdepid > this->analysedtypes.size()){
                snprintf(tmpbuf, sizeof(tmpbuf), "[TypeId-%d]", typdepid);
                typeobj["rettype"] = tmpbuf;
               
            }else{
                json subtypeobj = type_dump(this->analysedtypes[typdepid]);
                typeobj["rettype"] = subtypeobj;
            }

            typeobj["length"] = tmptype.ifunction.func_num_parameters;
            for(int i = 0; i < tmptype.ifunction.func_num_parameters; i++) {
                int typdepid = tmptype.ifunction.func_parameters[i];
                if(typdepid > this->analysedtypes.size()){
                    snprintf(tmpbuf, sizeof(tmpbuf), "[TypeId-%d]", typdepid);
                    typeobj[std::to_string(i)] = tmpbuf;
                }else{
                    json subtypeobj = type_dump(this->analysedtypes[typdepid]);
                    typeobj[std::to_string(i)] = subtypeobj;
                }

            }
            break;
        }
        default:
            analysis_error("unsupport type error!\n");
    }

    return typeobj;
}

void analysis_error(const char *fmt, ...){
    char err_buf[256];
    
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err_buf, sizeof(err_buf), fmt, ap);
    va_end(ap);

    cout << "###############################################################################" << endl;
    cout << "###############################################################################" << endl;
    cout << "###############################################################################" << endl;

    std::cout << err_buf << std::endl;
    std::cout << boost::stacktrace::stacktrace();

    cout << "###############################################################################" << endl;
    cout << "###############################################################################" << endl;
    cout << "###############################################################################" << endl;

    exit(0);
}