#pragma once

#include <map>
#include <string>
#include <nlohmann/json.hpp>
#include <clang/AST/AST.h>
#include <clang/AST/Decl.h>

using json=nlohmann::json;

/*
    The functions a patch expression may call, written to function-info.json.

    The runtime resolves a callee by name while it evaluates the expression, instead of the meta-program
    taking its address at every function entry, so a function this build does not have is left unresolved
    rather than breaking the link of the meta-program. The interpreter builds the arguments of a call from
    the expression itself and only needs to know what to do with the result, so an entry is the category of
    the return type and, for a pointer, what it points at:
        {
            "helper_add": { "category": "int" },
            "fopen": { "category": "ptr", "descriptor": "struct _IO_FILE" }
        }
    A function whose result the interpreter cannot handle, e.g. one returning a struct or a double, is not
    stored, and neither is one without a name.
*/
class FunctionInformation {
private:
    std::map<std::string,json> functions;
    std::string jsonFile;

public:
    FunctionInformation(std::string outputFile): jsonFile(outputFile) {}
    void addFunction(clang::FunctionDecl* funcDecl);
    void store();
};
