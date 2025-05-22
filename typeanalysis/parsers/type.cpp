
#include "type.h"

std::string TypeId2String(Type::TypeID tmptypeid) {
    switch (tmptypeid) {
        ENUM_TO_STRING_CASE(Type::HalfTyID)
        ENUM_TO_STRING_CASE(Type::BFloatTyID)
        ENUM_TO_STRING_CASE(Type::FloatTyID)
        ENUM_TO_STRING_CASE(Type::DoubleTyID)
        ENUM_TO_STRING_CASE(Type::X86_FP80TyID)
        ENUM_TO_STRING_CASE(Type::FP128TyID)
        ENUM_TO_STRING_CASE(Type::PPC_FP128TyID)
        ENUM_TO_STRING_CASE(Type::VoidTyID)
        ENUM_TO_STRING_CASE(Type::LabelTyID)
        ENUM_TO_STRING_CASE(Type::MetadataTyID)
        ENUM_TO_STRING_CASE(Type::X86_MMXTyID)
        ENUM_TO_STRING_CASE(Type::X86_AMXTyID)
        ENUM_TO_STRING_CASE(Type::TokenTyID)
        ENUM_TO_STRING_CASE(Type::IntegerTyID)
        ENUM_TO_STRING_CASE(Type::FunctionTyID)
        ENUM_TO_STRING_CASE(Type::PointerTyID)
        ENUM_TO_STRING_CASE(Type::StructTyID)
        ENUM_TO_STRING_CASE(Type::ArrayTyID)
        ENUM_TO_STRING_CASE(Type::FixedVectorTyID)
        ENUM_TO_STRING_CASE(Type::ScalableVectorTyID)
        default: return "Unknown";
    }
}