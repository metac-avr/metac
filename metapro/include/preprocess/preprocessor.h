#pragma once

#include "clang/Rewrite/Core/Rewriter.h"
#include <clang/Basic/SourceManager.h>
#include <clang/AST/AST.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <vector>
#include <clang/Tooling/Core/Replacement.h>


class Preprocessor : public clang::RecursiveASTVisitor<Preprocessor> {
private:
    clang::ASTContext* ctxt;
    std::string filename;
    std::string code;
    uint64_t patchOffset;
    clang::Rewriter rewriter;
public:
    Preprocessor(clang::ASTContext* ctxt,std::string filename,std::string code);
    bool VisitDeclStmt(clang::DeclStmt* declStmt);
    bool VisitIfStmt(clang::IfStmt* ifStmt);
    bool VisitWhileStmt(clang::WhileStmt* whileStmt);
    bool VisitForStmt(clang::ForStmt* forStmt);
    bool shouldTraversePostOrder() const { return true; }
    std::string applyPreprocess();
};