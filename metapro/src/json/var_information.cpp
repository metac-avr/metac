#include "json/var_information.h"
#include "utils/path.h"
#include "utils/string.h"

#include <fstream>
#include <iostream>
#include <clang/AST/ASTContext.h>
#include <clang/Basic/SourceManager.h>
#include <clang/AST/RecordLayout.h>
#include <spdlog/spdlog.h>
#include <iomanip>

using json=nlohmann::json;

/*
    Records a variable of funcName. Variables are keyed by their name, so a name declared more than once
    in a function keeps its first declaration, the same way the variable table of the runtime resolves a
    name within a function.
*/
void VarInformation::addVariable(std::string funcName, clang::VarDecl* varDecl) {
    if (varDecl == nullptr || varDecl->getType().isNull()) {
        return;
    }
    std::string varName = varDecl->getNameAsString();
    if (varName == "") {
        return; // Unnamed variable cannot be looked up
    }
    clang::QualType varType = varDecl->getType();
    clang::ASTContext* ctxt = &varDecl->getASTContext();

    VariableInfo varInfo;
    varInfo.type = TypeInformation::getTypeName(varType);
    varInfo.category = TypeInformation::getCategory(varType);
    // The same three values PatchGenerator::genVarTableInsert() passes to the insert call
    varInfo.size = TypeInformation::getVarSize(ctxt, varType);
    varInfo.varType = TypeInformation::getVarTypeName(varType, false);
    varInfo.descriptor = TypeInformation::getVarDescriptor(ctxt, varType);

    std::map<std::string,VariableInfo>& curFunction = functionVariables[funcName];
    std::map<std::string,VariableInfo>::iterator existing = curFunction.find(varName);
    if (existing != curFunction.end()) {
        // A name declared twice in a function can only be stored once. The variable table of the runtime
        // holds whichever declaration was registered last, so warn instead of silently disagreeing.
        if (existing->second.type != varInfo.type) {
            spdlog::warn("Variable {} of {} is declared as both {} and {}, keeping {}",
                         varName, funcName, existing->second.type, varInfo.type, existing->second.type);
        }
        return;
    }
    curFunction[varName] = varInfo;
}

/*
    Writes the variables of each function into its own file, so that a consumer only reads the variables
    of the function it cares about. jsonFile is the directory holding them, and each file is named
    <function>-vars.json:
        [
            {
                "name": <name>,
                "type": <type>,
                "category": <int|uint|double|ptr|array|struct|unknown>,
                "size": <size in bytes>,
                "var_type": <MetaproVarType* enumerator>,
                "descriptor": <"<type>:<size>", only if the variable is registered with one>
            },
            ...
        ]
*/
void VarInformation::store() {
    for (std::pair<const std::string,std::map<std::string,VariableInfo>>& function : functionVariables) {
        json variables = json::array();
        for (std::pair<const std::string,VariableInfo>& variable : function.second) {
            json varInfo = json::object();
            varInfo["name"] = variable.first;
            varInfo["type"] = variable.second.type;
            varInfo["category"] = TypeInformation::getCategoryName(variable.second.category);
            varInfo["size"] = variable.second.size;
            varInfo["var_type"] = variable.second.varType;
            if (variable.second.descriptor != "") {
                varInfo["descriptor"] = variable.second.descriptor;
            }
            variables.push_back(varInfo);
        }

        // A function name may contain characters that cannot be used in a file name, e.g. operator/ or A::f
        std::string filename = replaceString(replaceString(function.first, "/", "#"), ":", "#");
        std::ofstream f(jsonFile + "/" + filename + "-vars.json");
        f << std::setw(2) << variables << std::endl; // Set indent to 2
        f.close();
    }
}
