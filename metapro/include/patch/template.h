#pragma once

#include <string>
#include <nlohmann/json.hpp>

#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include <clang/Basic/SourceLocation.h>

using json=nlohmann::json;

class PatchTemplate{
public:
    typedef enum PatchTemplateKind {
        REPLACE_CONDITION,
        INSERT,
        INSERT_NOT_NULL_CHECKER
    } PatchTemplateKind;

private:
    PatchTemplateKind kind;

public:
    PatchTemplate(PatchTemplateKind kind) : kind(kind) {}
    std::string toString();
    bool isInsert();
    bool isReplace();
    bool operator==(const PatchTemplateKind& other) const { return kind==other; }
    bool operator!=(const PatchTemplateKind& other) const { return kind!=other; }
    bool operator==(const PatchTemplate& other) const { return kind==other.kind; }
    bool operator!=(const PatchTemplate& other) const { return kind!=other.kind; }
    PatchTemplateKind getKind() { return kind; }
};

class Patch {
public:
    clang::ASTContext* ctxt;
    std::string parent;
    PatchTemplate patchTemplate;
    std::string patchString;
    std::string patchStringInMetaProgram;
    uint64_t id;
    std::string code;
    uint64_t origLine;

    Patch(clang::ASTContext* ctxt, std::string parent, PatchTemplate patchTemplate, uint64_t id,
                std::string metaProgramPatch, uint64_t origLine, std::string code, std::string patchString):
        ctxt(ctxt), patchTemplate(patchTemplate),id(id),parent(parent),patchStringInMetaProgram(metaProgramPatch),origLine(origLine-1), code(code),
        patchString(patchString) {};
};

class VariablePatch : public Patch {
public:
    struct VariableInfo {
        std::string name;
        uint32_t size;
        std::string pointeeType;

        VariableInfo(std::string name,uint32_t size, std::string pointeeType = ""): name(name),size(size),
                pointeeType(pointeeType) {}
    };
public:
    std::vector<VariableInfo> intVars;
    std::vector<VariableInfo> uintVars;
    std::vector<VariableInfo> doubleVars;
    std::vector<VariableInfo> ptrVars;
    std::vector<VariableInfo> intLits;
    std::vector<VariableInfo> uintLits;
    std::vector<VariableInfo> floatLits;

    VariablePatch(clang::ASTContext* ctxt, std::string parent, PatchTemplate patchTemplate, uint64_t id,
                std::string patchString, uint64_t origLine, std::string code, std::string metaString=""):
                    Patch(ctxt,parent,patchTemplate,id,metaString != "" ? metaString : patchString,origLine, code,patchString) {}
};


class InsertPatch : public VariablePatch {
public:
    clang::SourceLocation insertLoc;
    bool insertAfter;

    InsertPatch(clang::ASTContext* ctxt, std::string parent, std::string code, uint64_t id,
                    std::string newStmt,clang::SourceLocation loc, uint64_t origLine, std::string metaString="", bool insertAfter=false);
};

class InsertNotNullChecker : public VariablePatch {
public:
    clang::SourceLocation insertLoc;
    InsertNotNullChecker(clang::ASTContext* ctxt, std::string parent, std::string newStmt,uint64_t id,std::string code,uint64_t origLine,
                    clang::SourceLocation loc);
};

class ReplaceConditionPatch : public VariablePatch {
public:
    enum ReplaceConditionKind {
        REPLACE_IF,
        REPLACE_WHILE,
        REPLACE_FOR
    };
    ReplaceConditionKind replaceKind;
    std::string origStmt;
    clang::CharSourceRange range;

    ReplaceConditionPatch(clang::ASTContext* ctxt, std::string parent, std::string origStmt, std::string code,
                        uint64_t id, std::string newStmt, ReplaceConditionKind kind,clang::CharSourceRange range, uint64_t origLine);
};