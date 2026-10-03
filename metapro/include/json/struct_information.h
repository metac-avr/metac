#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include <set>
#include <clang/AST/AST.h>
#include <clang/AST/Decl.h>

using json=nlohmann::json;

class StructInformationFile {
private:
    json structs;

public:
    void addStructFieldInfo(clang::ASTContext* ctxt, clang::RecordDecl* recordDecl);
    void addTypeInfo(clang::ASTContext* ctxt, std::string funcName, std::string varName, clang::QualType qualType);
    void store(std::string filename);
};