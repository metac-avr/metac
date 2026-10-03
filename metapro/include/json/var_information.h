#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include <set>
#include <map>
#include <clang/AST/AST.h>
#include <clang/AST/Decl.h>
#include "patch/template.h"
#include "fl/fl.h"
#include "json/type_information.h"

using json=nlohmann::json;

class VarInformation {
public:
    struct VariableInfo {
        std::string type;
        TypeInformation::TypeCategory category;

        /*
            The arguments __metapro_table_insert_var_*() registers this variable with, so that the file
            describes it exactly as the instrumented program does. All three come from TypeInformation,
            which PatchGenerator::genVarTableInsert() emits the call from.
        */
        uint64_t size; // var_size, in bytes
        std::string varType; // var_type, a MetaproVarType* enumerator
        std::string descriptor; // struct_type, empty when the variable is registered without one
    };
private:
    std::map<std::string,std::map<std::string,VariableInfo>> functionVariables;
    std::string jsonFile;
public:
    VarInformation(std::string outputFile): jsonFile(outputFile) {}
    void addVariable(std::string funcName, clang::VarDecl* varDecl);
    void store();
};
