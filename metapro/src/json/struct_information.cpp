#include "json/struct_information.h"
#include "json/type_information.h"
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecordLayout.h>
#include <fstream>
#include <spdlog/spdlog.h>
#include <iomanip>

void StructInformationFile::addStructFieldInfo(clang::ASTContext* ctxt, clang::RecordDecl* recordDecl) {
    const clang::ASTRecordLayout& layout=ctxt->getASTRecordLayout(recordDecl);
    /*
        Named with TypeInformation::getStructTypeName(), the same way every reference to a record is named,
        so that a "<type>" of the variable table and a "type_name" of a field below are keys of this table.
    */
    std::string recordName = TypeInformation::getStructTypeName(clang::QualType(recordDecl->getTypeForDecl(), 0));
    if (structs.find("struct") != structs.end() && structs["struct"].find(recordName)!=structs["struct"].end()) {
        /*
            An unnamed record is named after the range of its definition, which two records of the same
            extent at the same position of different files share. Report a differing field count instead of
            dropping one of them silently. Records that collide with the same field count still slip by.
        */
        size_t fieldCount = std::distance(recordDecl->field_begin(), recordDecl->field_end());
        if (structs["struct"][recordName].size() != fieldCount) {
            spdlog::warn("Two different records are named {}: one has {} fields, the other {}. Keeping the first",
                         recordName, structs["struct"][recordName].size(), fieldCount);
        }
        return; // Already added
    }
    if (structs.find("struct") == structs.end()) {
        structs["struct"] = json::object();
    }
    structs["struct"][recordName]=json::object();
    json& curRecord=structs["struct"][recordName];

    for (clang::FieldDecl* fieldDecl:recordDecl->fields()) {
        size_t fieldIndex=fieldDecl->getFieldIndex();
        size_t offsetInBits=layout.getFieldOffset(fieldIndex);
        size_t sizeInBits=ctxt->getTypeSize(fieldDecl->getType());
        std::string fieldName=fieldDecl->getNameAsString();

        curRecord[fieldName]=json::object();
        json& fieldInfo=curRecord[fieldName];

        fieldInfo["offset"]=offsetInBits/8;
        fieldInfo["size"]=sizeInBits/8;
        fieldInfo["index"]=fieldIndex;
        // Category of the field type, named as in type-info.json, so both files can be consumed together
        fieldInfo["category"]=TypeInformation::getCategoryName(TypeInformation::getCategory(fieldDecl->getType()));
        /*
            Name of the field type. A record is named by its tag, the same way the keys of "struct" above
            are named, so the name of a struct field looks its record up directly. Any other type keeps its
            own spelling, which is how it is named in type-info.json.
        */
        if (fieldDecl->getType()->isRecordType()) {
            fieldInfo["type_name"]=TypeInformation::getStructTypeName(fieldDecl->getType());
        }
        else {
            fieldInfo["type_name"]=TypeInformation::getTypeName(fieldDecl->getType());
        }
        if (fieldDecl->getType()->isSignedIntegerOrEnumerationType()) {
            fieldInfo["type"]="int";
        }
        else if (fieldDecl->getType()->isUnsignedIntegerType()) {
            fieldInfo["type"]="uint";
        }
        else if (fieldDecl->getType()->isFloatingType()) {
            fieldInfo["type"]="double";
        }
        else if (fieldDecl->getType()->isPointerType()) {
            if (fieldDecl->getType()->getPointeeType()->isRecordType()) {
                fieldInfo["type"]="struct_ptr";
                fieldInfo["struct_type"]=TypeInformation::getStructTypeName(fieldDecl->getType()->getPointeeType());
            } else {
                fieldInfo["type"]="ptr";
                clang::QualType pointeeType = fieldDecl->getType()->getPointeeType();
                std::string elemTypeName;
                if (pointeeType->isSignedIntegerOrEnumerationType())
                    elemTypeName = "int";
                else if (pointeeType->isUnsignedIntegerType())
                    elemTypeName = "uint";
                else if (pointeeType->isFloatingType())
                    elemTypeName = "double";
                else if (pointeeType->isPointerType())
                    elemTypeName = "ptr";
                else if (pointeeType->isRecordType()) {
                    elemTypeName = "struct";
                    fieldInfo["struct_type"] = TypeInformation::getStructTypeName(pointeeType);
                }
                else
                    elemTypeName = "unknown";
                std::string elemSize = pointeeType->isIncompleteType() ? "0" : std::to_string(ctxt->getTypeSize(pointeeType) / 8);
                fieldInfo["element_type"] = elemTypeName;
            }

            if (fieldDecl->getType()->getPointeeType()->isIncompleteType()) {
                fieldInfo["element_size"]=0;
            }
            else {
                fieldInfo["element_size"]=ctxt->getTypeSize(fieldDecl->getType()->getPointeeType())/8;
            }
        }
        else if (fieldDecl->getType()->isRecordType()) {
            fieldInfo["type"]="struct";
            fieldInfo["struct_type"]=TypeInformation::getStructTypeName(fieldDecl->getType());
        }
        else if (fieldDecl->getType()->isArrayType()) {
            // Create a new type if we need subscript. Now we just handle same as primitive types
            clang::QualType elementType=ctxt->getAsArrayType(fieldDecl->getType())->getElementType().getUnqualifiedType();
            if (elementType->isRecordType()) 
                fieldInfo["type"] = "struct_array";
            else
                fieldInfo["type"] = "array";

            if (elementType->isSignedIntegerOrEnumerationType())
                fieldInfo["struct_type"] = "int";
            else if (elementType->isUnsignedIntegerType())
                fieldInfo["struct_type"] = "uint";
            else if (elementType->isFloatingType())
                fieldInfo["struct_type"] = "double";
            else if (elementType->isPointerType()) {
                if (elementType->getPointeeType()->isRecordType()) {
                    fieldInfo["struct_type"]="struct_ptr";
                    fieldInfo["element_type"]=TypeInformation::getStructTypeName(elementType->getPointeeType());
                } else {
                    fieldInfo["struct_type"]="ptr";
                }
            }
            else if (elementType->isRecordType()) {
                fieldInfo["struct_type"]="struct";
                fieldInfo["element_type"]=TypeInformation::getStructTypeName(elementType);
            }
            else {
                fieldInfo["struct_type"]="other";
            }

            if (elementType->isIncompleteType()) {
                fieldInfo["element_size"]=0;
            }
            else {
                fieldInfo["element_size"]=ctxt->getTypeSize(elementType)/8;
            }
        }
        else {
            fieldInfo["type"]="other";
        }
    }
}

void StructInformationFile::addTypeInfo(clang::ASTContext* ctxt, std::string funcName, std::string varName, clang::QualType qualType) {
    std::string typeName;
    if (qualType->isPointerType()) {
        typeName = qualType.getUnqualifiedType()->getPointeeType().getCanonicalType().getAsString();
    }
    else {
        typeName = qualType.getUnqualifiedType().getCanonicalType().getAsString();
    }
    if (typeName.find("const ") != std::string::npos) {
        // Prune "const " from some types
        size_t pos = typeName.find("const ");
        typeName.erase(pos, 6);
    }

    if (typeName == "" || (structs.find("type") != structs.end() && structs["type"].find(typeName)!=structs["type"].end())) {
        return; // Already added
    }
    if (qualType->isPointerType() && (qualType->getPointeeType()->isSizelessType() || qualType->getPointeeType()->isIncompleteType() ||
                                      qualType->getPointeeType()->isFunctionPointerType() || qualType->getPointeeType()->isVoidPointerType())) {
        return; // Ignore pointer to incomplete types
    }
    if (qualType->isArrayType()) {
        // Ignore array of incomplete types
        const clang::ArrayType* arrayType = ctxt->getAsArrayType(qualType);
        if (arrayType) {
            const clang::QualType elementType = arrayType->getElementType();
            if (elementType->isIncompleteType() || elementType->isSizelessType() ||
                    elementType->isFunctionPointerType() || elementType->isVoidPointerType()) {
                return; // Ignore array of incomplete types
            }
        }
    }
    if (qualType->isIncompleteType() || qualType->isSizelessType() || qualType->isFunctionPointerType() || qualType->isVoidPointerType()) {
        return; // Ignore incomplete types
    }

    if (structs.find("type") == structs.end()) {
        structs["type"] = json::object();
    }
    if (structs["type"].find(funcName) == structs["type"].end()) {
        structs["type"][funcName]=json::object();
    }
    if (structs["type"][funcName].find(varName) == structs["type"][funcName].end()) {
        structs["type"][funcName][varName]=json::object();
    }
    json& typeInfo=structs["type"][funcName][varName];

    if (qualType->isPointerType()) {
        typeInfo["size"] = ctxt->getTypeSize(qualType->getPointeeType()) / 8;
    }
    else if (qualType->isArrayType()) {
        const clang::ArrayType* arrayType = ctxt->getAsArrayType(qualType);
        if (arrayType) {
            uint64_t elementSize = ctxt->getTypeSize(arrayType->getElementType()) / 8;
            typeInfo["size"] = elementSize;
        }
    }
    else {
        typeInfo["size"] = ctxt->getTypeSize(qualType) / 8;
    }
}

void StructInformationFile::store(std::string filename) {
    std::ofstream f(filename);
    f << std::setw(2) << structs << std::endl; // Set indent to 2
    f.close();
}