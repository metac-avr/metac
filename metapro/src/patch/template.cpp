#include "patch/template.h"
#include "utils/string.h"
#include "config/config.h"

#include <string>
#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/Basic/SourceManager.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <spdlog/spdlog.h>
#include <clang/AST/RecursiveASTVisitor.h>

using json=nlohmann::json;

json response_json;

static size_t write_str(void* content, size_t size, size_t nmemb, void* userp) { // userp: json_object**
    size_t realsize=size*nmemb;
    std::string result((char*)content);
    response_json=json::parse(result);
    return realsize;
}

std::string PatchTemplate::toString() {
    switch (kind) {
        case REPLACE_CONDITION:
            return "REPLACE_CONDITION";
        case INSERT:
            return "INSERT";
        case INSERT_NOT_NULL_CHECKER:
            return "INSERT_NOT_NULL_CHECKER";
        default:
            return "UNKNOWN";
    }
}

bool PatchTemplate::isInsert() {
    switch (kind) {
        case INSERT:
            return true;
        default:
            return false;
    }
}

bool PatchTemplate::isReplace() {
    switch (kind) {
        case REPLACE_CONDITION:
            return true;
        default:
            return false;
    }
}

InsertPatch::InsertPatch(clang::ASTContext* ctxt, std::string parent, std::string code, uint64_t id, std::string newStmt,
            clang::SourceLocation loc, uint64_t origLine, std::string metaString, bool insertAfter):
            VariablePatch(ctxt, parent, PatchTemplate::INSERT, id, newStmt, origLine, code, metaString),insertAfter(insertAfter),insertLoc(loc) { }

InsertNotNullChecker::InsertNotNullChecker(clang::ASTContext* ctxt, std::string parent, std::string newStmt,uint64_t id,std::string code, uint64_t origLine,
                    clang::SourceLocation loc):
                    VariablePatch(ctxt,parent,PatchTemplate::INSERT_NOT_NULL_CHECKER,id,newStmt,origLine,code),insertLoc(loc) {}

ReplaceConditionPatch::ReplaceConditionPatch(clang::ASTContext* ctxt, std::string parent, std::string origStmt, std::string code,
                        uint64_t id, std::string newStmt, ReplaceConditionKind kind,clang::CharSourceRange range, uint64_t origLine): 
                    VariablePatch(ctxt,parent,PatchTemplate(PatchTemplate::REPLACE_CONDITION),id,newStmt,origLine, code),
                    origStmt(origStmt),range(range), replaceKind(kind) {}