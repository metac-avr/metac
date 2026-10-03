#pragma once

#include "clang/AST/Type.h"
#include <string>
#include <nlohmann/json.hpp>
#include <set>
#include <fstream>

using json=nlohmann::json;

class TypeInformation {
public:
    enum TypeCategory {
        SignedInteger,
        UnsignedInteger,
        FloatingPoint,
        Pointer,
        Array,
        Struct,
        Unknown
    };

    struct TypeInfo {
        std::string type;
        uint64_t size;
        TypeCategory category;
        /*
            Name of what a pointer points at, or of what an array holds, and empty for any other type.
            Only the name is stored: it names another entry of this file, so a consumer that needs the
            size or the category of the element looks that entry up in turn.
        */
        std::string elementType;

        TypeInfo(const std::string& type, uint64_t size, TypeCategory category,
                 const std::string& elementType = "")
            : type(type), size(size), category(category), elementType(elementType) {}

        bool operator<(const TypeInfo& other) const {
            if (type != other.type) {
                return type < other.type;
            } else if (size != other.size) {
                return size < other.size;
            } else {
                return category < other.category;
            }
        }
    };

private:
    json root;
    std::set<TypeInfo> types;
    std::string jsonFile;

public:
    TypeInformation(std::string outputFile): root(json::array()), jsonFile(outputFile) {}

    /* Category of a type. Enums are handled as integers of their underlying type */
    static TypeCategory getCategory(clang::QualType qualType);

    /* Name of a category, shared with StructInformationFile so that both files can be consumed together */
    static std::string getCategoryName(TypeCategory category);

    /*
        Name a type is stored under. Unlike getStructTypeName(), the sugar of qualType is kept, so that a
        typedef is named after itself instead of after its underlying type.
    */
    static std::string getTypeName(clang::QualType qualType);

    /*
        Printable name of a struct/class/union type, matching the keys of struct-info.json:
          1. Named tag              -> "<kind> <name>" (e.g. "struct Foo", "union Bar")
          2. Unnamed tag w/ typedef -> typedef name    (e.g. typedef struct {...} Foo; -> "Foo")
          3. Truly unnamed          -> "anon_struct"   (avoids clang's location-tagged
                                                        `(anonymous struct at ...)` form)
        Any other type falls back to its canonical name.
    */
    static std::string getStructTypeName(clang::QualType qualType);

    /* MetaproVarType* enumerator of _runtime_c.h/_runtime_cxx.h holding a variable of this type */
    static std::string getVarTypeName(clang::QualType qualType, bool isCXX);

    /*
        "<type>:<size in bytes>" descriptor of the variable table of the instrumented program, where
        <type> is the category name for primitives and pointers and the struct type name for structs.
        The runtime reads the size into __metapro_var_info::array_element_size, which is a byte stride.
    */
    static std::string getTypeDescriptor(clang::ASTContext* ctxt, clang::QualType qualType);

    /*
        The three arguments __metapro_table_insert_var_*() is called with for a variable of this type.
        VarInformation stores what these return, so that <function>-vars.json describes a variable exactly
        as the instrumented program registers it. Keep them the single source of both.

        getVarSize():       var_size, the size of the variable itself in bytes.
        getVarDescriptor(): struct_type, which describes the pointee of a pointer, the element of an array
                            and the type itself otherwise. Empty for the primitive types, which are
                            registered with no descriptor at all.
    */
    static uint64_t getVarSize(clang::ASTContext* ctxt, clang::QualType qualType);
    static std::string getVarDescriptor(clang::ASTContext* ctxt, clang::QualType qualType);

    void addType(clang::ASTContext* ctxt, clang::QualType qualType);
    void store();
};