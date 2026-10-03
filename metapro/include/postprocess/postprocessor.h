#pragma once

#include "clang/Frontend/ASTUnit.h"
#include <clang/Rewrite/Core/Rewriter.h>
#include <clang/Basic/SourceManager.h>
#include <clang/AST/AST.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <cstdint>
#include <vector>
#include <clang/Tooling/Core/Replacement.h>
#include "json/location_information.h"
#include "fl/fl.h"

class PostProcessor : public clang::RecursiveASTVisitor<PostProcessor> {
private:
    std::string filename;
    LocationInformation& locInfo;
    std::string code;
    std::unique_ptr<clang::ASTUnit> preunit;
    clang::ASTContext* ctxt;
    std::vector<FaultLocalizer::ResultRecord> &flResult;

    std::map<uint64_t, uint64_t>& jmpIDs; // For longjmp for continue/break, map line number to jmpID
public:
    PostProcessor(std::string filename, LocationInformation& locInfo, std::map<uint64_t, uint64_t>& jmpIDs, std::vector<FaultLocalizer::ResultRecord> &flResult);
    bool startTraverse();
    bool VisitIfStmt(clang::IfStmt* ifStmt);
    bool VisitWhileStmt(clang::WhileStmt* whileStmt);
    bool VisitForStmt(clang::ForStmt* forStmt);
    bool shouldTraversePostOrder() const { return true; }
    bool VisitCompoundStmt(clang::CompoundStmt* compoundStmt);
};