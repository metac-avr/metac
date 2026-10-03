#include "json/function_information.h"

#include <fstream>
#include <iomanip>
#include <spdlog/spdlog.h>

void FunctionInformation::addFunction(clang::FunctionDecl* funcDecl) {
    if (funcDecl == nullptr) {
        return;
    }
    std::string funcName = funcDecl->getNameAsString();
    if (funcName == "") {
        return; // Cannot be named in an expression
    }

    clang::QualType returnType = funcDecl->getReturnType();
    json function = json::object();
    if (returnType->isSignedIntegerOrEnumerationType()) {
        function["category"] = "int";
    }
    else if (returnType->isUnsignedIntegerType()) {
        function["category"] = "uint";
    }
    else if (returnType->isPointerType()) {
        function["category"] = "ptr";
        // What the result points at, the same descriptor a pointer variable is registered with
        function["descriptor"] = returnType.getUnqualifiedType()->getPointeeType().getUnqualifiedType()
                    .getCanonicalType().getAsString();
    }
    else if (returnType->isVoidType()) {
        function["category"] = "void";
    }
    else {
        return; // The interpreter has no result to hand back
    }

    std::map<std::string,json>::iterator existing = functions.find(funcName);
    if (existing != functions.end()) {
        // Two declarations of one name, e.g. in different files. The runtime resolves a name once, so the
        // first one is kept and a disagreement is worth knowing about
        if (existing->second["category"] != function["category"]) {
            spdlog::debug("Function {} is declared to return both {} and {}, keeping {}", funcName,
                          existing->second["category"].get<std::string>(),
                          function["category"].get<std::string>(),
                          existing->second["category"].get<std::string>());
        }
        return;
    }
    functions[funcName] = function;
}

void FunctionInformation::store() {
    json root = json::object();
    for (const std::pair<const std::string,json>& function : functions) {
        root[function.first] = function.second;
    }

    std::ofstream f(jsonFile);
    f << std::setw(2) << root << std::endl; // Set indent to 2
    f.close();
}
