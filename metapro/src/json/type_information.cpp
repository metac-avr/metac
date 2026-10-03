#include "json/type_information.h"
#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/Basic/SourceManager.h>
#include <iomanip>

namespace {

/*
    Name used in the "<type>:<size>" descriptor of the variable table. Primitives and pointers are named
    by their category, structs by their struct type name and anything else by its canonical name.
*/
std::string getDescriptorName(clang::QualType qualType) {
    TypeInformation::TypeCategory category = TypeInformation::getCategory(qualType);
    if (category == TypeInformation::Struct || category == TypeInformation::Array ||
            category == TypeInformation::Unknown) {
        return TypeInformation::getStructTypeName(qualType);
    }
    return TypeInformation::getCategoryName(category);
}

/* Size in bytes. Types without a statically known size (void, forward declared structs, VLAs, ...) have size 0 */
uint64_t getTypeSizeInBytes(clang::ASTContext* ctxt, clang::QualType qualType) {
    if (qualType->isIncompleteType() || qualType->isSizelessType() ||
            qualType->isDependentType() || qualType->isVariableArrayType()) {
        return 0;
    }
    return ctxt->getTypeSize(qualType) / 8;
}

/*
    Store this type, then every type it is built from: the underlying type of a typedef, the pointee of a
    pointer, the element of an array and the type of each field of a struct. Recursion stops as soon as a
    type is already stored, which also terminates self referencing structs.
*/
void collectType(clang::ASTContext* ctxt, clang::QualType qualType, std::set<TypeInformation::TypeInfo>& types) {
    if (qualType.isNull() || qualType->isFunctionType()) {
        return; // Function types have no storage information to record
    }

    std::string typeName = TypeInformation::getTypeName(qualType);
    if (typeName == "") {
        return;
    }

    /*
        What a pointer points at, or what an array holds. Named the same way its own entry is named, so
        that looking the name up in this file finds it, which is how a consumer resolves it recursively.
    */
    clang::QualType elementQualType;
    if (qualType->isPointerType()) {
        elementQualType = qualType->getPointeeType();
    }
    else if (qualType->isArrayType()) {
        const clang::ArrayType* arrayType = ctxt->getAsArrayType(qualType);
        if (arrayType) {
            elementQualType = arrayType->getElementType();
        }
    }
    std::string elementName = elementQualType.isNull() ? "" : TypeInformation::getTypeName(elementQualType);

    TypeInformation::TypeInfo typeInfo(typeName, getTypeSizeInBytes(ctxt, qualType),
                                       TypeInformation::getCategory(qualType), elementName);
    if (!types.insert(typeInfo).second) {
        return; // Already stored
    }

    if (const clang::TypedefType* typedefType = qualType->getAs<clang::TypedefType>()) {
        collectType(ctxt, typedefType->getDecl()->getUnderlyingType(), types);
    }

    if (!elementQualType.isNull()) {
        collectType(ctxt, elementQualType, types);
    }
    else if (qualType->isRecordType()) {
        clang::RecordDecl* recordDecl = qualType->getAs<clang::RecordType>()->getDecl()->getDefinition();
        if (recordDecl) {
            for (clang::FieldDecl* fieldDecl : recordDecl->fields()) {
                collectType(ctxt, fieldDecl->getType(), types);
            }
        }
    }
}

} // namespace

TypeInformation::TypeCategory TypeInformation::getCategory(clang::QualType qualType) {
    if (qualType->isSignedIntegerOrEnumerationType()) {
        return SignedInteger;
    }
    else if (qualType->isUnsignedIntegerType()) {
        return UnsignedInteger;
    }
    else if (qualType->isFloatingType()) {
        return FloatingPoint;
    }
    else if (qualType->isPointerType()) {
        return Pointer;
    }
    else if (qualType->isArrayType()) {
        return Array;
    }
    else if (qualType->isRecordType()) {
        return Struct;
    }
    else {
        return Unknown;
    }
}

std::string TypeInformation::getCategoryName(TypeCategory category) {
    switch (category) {
        case SignedInteger: return "int";
        case UnsignedInteger: return "uint";
        case FloatingPoint: return "double";
        case Pointer: return "ptr";
        case Array: return "array";
        case Struct: return "struct";
        default: return "unknown";
    }
}

std::string TypeInformation::getTypeName(clang::QualType qualType) {
    if (qualType->isRecordType()) {
        clang::RecordDecl* recordDecl = qualType->getAs<clang::RecordType>()->getDecl();
        if (recordDecl->getNameAsString() == "") {
            // Anonymous struct is named by the typedef declaring it, if any
            return getStructTypeName(qualType);
        }
    }

    std::string typeName = qualType.getUnqualifiedType().getAsString();
    // Prune qualifiers that getUnqualifiedType() cannot remove, e.g. "const char *"
    for (const std::string& qualifier : { "const ", "volatile ", "restrict " }) {
        size_t pos;
        while ((pos = typeName.find(qualifier)) != std::string::npos) {
            typeName.erase(pos, qualifier.length());
        }
    }
    return typeName;
}

std::string TypeInformation::getStructTypeName(clang::QualType qualType) {
    if (const clang::RecordType* recordType = qualType->getAs<clang::RecordType>()) {
        const clang::RecordDecl* recordDecl = recordType->getDecl();
        if (recordDecl->getIdentifier() != nullptr && !recordDecl->getName().empty()) {
            return recordDecl->getKindName().str() + " " + recordDecl->getNameAsString();
        }
        if (const clang::TypedefType* typedefType = qualType->getAs<clang::TypedefType>()) {
            return typedefType->getDecl()->getNameAsString();
        }
        if (recordDecl->getTypedefNameForAnonDecl()) {
            return recordDecl->getTypedefNameForAnonDecl()->getNameAsString();
        }
        /*
            A truly unnamed record is named after where it is written, because the canonical name clang
            prints for it, "struct (anonymous at <file>:<line>:<col>)", holds a colon and a path, and the
            variable table stores a "<type>:<size>" descriptor in a 50 byte field.

            The range of the definition is used, not only its start, to keep two records written at the
            same position of different files apart. Two records of the same extent at the same position of
            different files still collide, which StructInformationFile reports when it happens.
        */
        clang::SourceManager& sm = recordDecl->getASTContext().getSourceManager();
        clang::PresumedLoc begin = sm.getPresumedLoc(recordDecl->getBeginLoc());
        clang::PresumedLoc end = sm.getPresumedLoc(recordDecl->getEndLoc());
        if (begin.isValid() && end.isValid()) {
            return "anon_struct_" + std::to_string(begin.getLine()) + "_" + std::to_string(begin.getColumn()) +
                    "_" + std::to_string(end.getLine()) + "_" + std::to_string(end.getColumn());
        }
        return "anon_struct";
    }
    return qualType.getUnqualifiedType().getCanonicalType().getAsString();
}

std::string TypeInformation::getVarTypeName(clang::QualType qualType, bool isCXX) {
    std::string varTypeName;
    switch (getCategory(qualType)) {
        case SignedInteger:
            varTypeName = "MetaproVarTypeInt";
            break;
        case UnsignedInteger:
            varTypeName = "MetaproVarTypeUInt";
            break;
        case FloatingPoint:
            varTypeName = "MetaproVarTypeDouble";
            break;
        case Pointer:
            // Struct pointer has its own type to let the runtime handle arrow expressions
            varTypeName = qualType->getPointeeType()->isStructureOrClassType() ? "MetaproVarTypeStructPointer"
                                                                              : "MetaproVarTypePointer";
            break;
        case Array:
            // An array is registered as itself, not as a variable holding its address, so that the
            // runtime can hand the interpreter a reference that points at the elements
            varTypeName = "MetaproVarTypeArray";
            break;
        case Struct:
            varTypeName = "MetaproVarTypeStruct";
            break;
        default:
            varTypeName = "MetaproVarTypeUnknown";
            break;
    }
    // The enumerators are members of __metapro_var_info in C++, but plain enumerators in C
    return isCXX ? "__metapro_var_info::" + varTypeName : varTypeName;
}

std::string TypeInformation::getTypeDescriptor(clang::ASTContext* ctxt, clang::QualType qualType) {
    return getDescriptorName(qualType) + ":" + std::to_string(getTypeSizeInBytes(ctxt, qualType));
}

uint64_t TypeInformation::getVarSize(clang::ASTContext* ctxt, clang::QualType qualType) {
    return getTypeSizeInBytes(ctxt, qualType);
}

std::string TypeInformation::getVarDescriptor(clang::ASTContext* ctxt, clang::QualType qualType) {
    switch (getCategory(qualType)) {
        case SignedInteger:
        case UnsignedInteger:
        case FloatingPoint:
            return ""; // Primitive types are registered with no descriptor
        case Pointer: {
            clang::QualType pointeeType = qualType->getPointeeType();
            if (pointeeType->isStructureOrClassType() && pointeeType->isIncompleteType()) {
                return "unknown:0"; // Fields of an incomplete struct are unknown
            }
            return getTypeDescriptor(ctxt, pointeeType);
        }
        case Array: {
            // Array is registered as a pointer to its first element
            const clang::ArrayType* arrayType = ctxt->getAsArrayType(qualType);
            return (arrayType != nullptr) ? getTypeDescriptor(ctxt, arrayType->getElementType()) : "";
        }
        default:
            return getTypeDescriptor(ctxt, qualType); // Struct and unknown types describe themselves
    }
}

void TypeInformation::addType(clang::ASTContext* ctxt, clang::QualType qualType) {
    if (!ctxt) {
        return;
    }
    // qualType is passed as is, keeping its sugar so that a typedef is stored under its own name
    collectType(ctxt, qualType, types);
}

void TypeInformation::store() {
    root = json::array();
    for (const TypeInfo& typeInfo : types) {
        json typeJson;
        typeJson["type"] = typeInfo.type;
        typeJson["size"] = typeInfo.size;
        typeJson["category"] = getCategoryName(typeInfo.category);
        if (typeInfo.elementType != "") {
            typeJson["element_type"] = typeInfo.elementType;
        }
        root.push_back(typeJson);
    }

    std::ofstream out(jsonFile);
    out << root.dump(4);
    out.close();
}
