#include "preprocess/preprocessor.h"
#include "utils/string.h"
#include "utils/path.h"
#include "config/clang_macro.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/Core/Replacement.h"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <iostream>
#include <llvm-12/llvm/Support/raw_ostream.h>
#include <sys/types.h>
#include <clang/Rewrite/Core/Rewriter.h>


Preprocessor::Preprocessor(clang::ASTContext* ctxt,std::string filename,std::string code):
        ctxt(ctxt), filename(filename), code(code),patchOffset(0), rewriter(ctxt->getSourceManager(), ctxt->getLangOpts()) { }

bool Preprocessor::VisitDeclStmt(clang::DeclStmt* declStmt) {
    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::CharSourceRange charRange = clang::CharSourceRange::getTokenRange(declStmt->getSourceRange());
    clang::SourceLocation startLoc=sm.getExpansionLoc(charRange.getBegin());
    clang::SourceLocation endLoc=sm.getExpansionLoc(charRange.getEnd());
    clang::SourceLocation startSpellLoc=sm.getSpellingLoc(declStmt->getBeginLoc());
    if (sm.getFilename(startLoc)!=filename || sm.getFilename(startSpellLoc)!=filename) return true;  // Ignore headers
    if (sm.getFileOffset(startLoc)!=sm.getFileOffset(startSpellLoc)) return true;  // Ignore macro expansion

    clang::Decl* newDecls[10];
    unsigned int newSizes=0;
    bool changed=false;

    uint64_t startOffset=sm.getFileOffset(startLoc);
    uint64_t endOffset=sm.getFileOffset(endLoc);
    size_t end=std::min(code.find(",",endOffset),code.find(";",endOffset));
    endOffset=end+2;
    std::string origDecl = code.substr(startOffset,endOffset-startOffset);
    std::string newDecl = origDecl;
    
    for (clang::Decl* decl:declStmt->decls()) {
        if (clang::VarDecl::classof(decl)) {
            clang::VarDecl* varDecl=llvm::dyn_cast<clang::VarDecl>(decl);
            if (!varDecl->hasInit() && varDecl->getType()->isPointerType() && !varDecl->getType()->isFunctionPointerType()) {
                clang::CharSourceRange declRange = clang::CharSourceRange::getTokenRange(decl->getSourceRange());
                clang::SourceLocation nameEndLoc = clang::Lexer::getLocForEndOfToken(varDecl->getLocation(), 0, sm, ctxt->getLangOpts());
                if (varDecl->getType()->getPointeeType()->isArrayType()) {
                    clang::TypeSourceInfo* typeInfo = varDecl->getTypeSourceInfo();
                    nameEndLoc = clang::Lexer::getLocForEndOfToken(typeInfo->getTypeLoc().getEndLoc(), 0, sm, ctxt->getLangOpts());
                }
                if (nameEndLoc.isMacroID()) continue;  // Ignore macros
                if (isCXX(filename))
                    rewriter.InsertTextAfter(nameEndLoc, " = nullptr");
                else
                    rewriter.InsertTextAfter(nameEndLoc, " = NULL");
                continue;
            }
        }
    }

    return true;
}

bool Preprocessor::VisitIfStmt(clang::IfStmt *ifStmt) {
    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::SourceLocation startLoc=sm.getExpansionLoc(ifStmt->getBeginLoc());
    clang::SourceLocation startSpellLoc=sm.getSpellingLoc(ifStmt->getBeginLoc());
    if (sm.getFilename(startLoc)!=filename || sm.getFilename(startSpellLoc)!=filename) return true;  // Ignore headers
    if (ifStmt->getBeginLoc().isMacroID()) return true;  // Ignore macro expansion

    // Then branch: if it's not a compound statement, add braces around it
    clang::Stmt* then = ifStmt->getThen();
    if (!clang::CompoundStmt::classof(then) || then->getBeginLoc().isMacroID()) {
        clang::SourceRange tokenRange = then->getSourceRange();
        clang::CharSourceRange charRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(tokenRange));
        clang::SourceLocation startLoc = charRange.getBegin();
        clang::SourceLocation endLoc = clang::Lexer::getLocForEndOfToken(charRange.getEnd(), 0, sm, ctxt->getLangOpts());
        auto nextTok = clang::Lexer::findNextToken(charRange.getEnd(), sm, ctxt->getLangOpts());
        if (nextTok.hasValue() && nextTok->is(clang::tok::semi)) {
            endLoc = clang::Lexer::getLocForEndOfToken(nextTok->getLocation(), 0, sm, ctxt->getLangOpts());
        }

        rewriter.InsertTextAfter(startLoc, "{ ");
        if (ifStmt->getElse() == nullptr)
            rewriter.InsertTextAfter(endLoc, " } else if (1) { ; } else { ; }");
        else
            rewriter.InsertTextAfter(endLoc, " } ");
    }

    // Else branch
    if (clang::CompoundStmt::classof(then) && ifStmt->getElse() == nullptr && !then->getBeginLoc().isMacroID()) {
        // Add an empty else branch if not exists
        clang::CharSourceRange range = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(then->getSourceRange()));
        clang::SourceLocation startLoc=range.getBegin();
        clang::SourceLocation endLoc=clang::Lexer::getLocForEndOfToken(range.getEnd(), 0, sm, ctxt->getLangOpts());
        std::string newThen = " else if (1) { ; } else { ; }";
        rewriter.InsertTextAfter(endLoc, newThen);
    }
    else if (ifStmt->getElse() != nullptr && !clang::IfStmt::classof(ifStmt->getElse())) {
        // If the else branch is not an another if stmt, add new if stmt
        clang::CharSourceRange range = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(ifStmt->getElse()->getSourceRange()));
        clang::SourceLocation startLoc=range.getBegin();
        clang::SourceLocation endLoc=clang::Lexer::getLocForEndOfToken(range.getEnd(), 0, sm, ctxt->getLangOpts());
        auto nextTok = clang::Lexer::findNextToken(range.getEnd(), sm, ctxt->getLangOpts());
        if (nextTok.hasValue() && nextTok->is(clang::tok::semi)) {
            endLoc = clang::Lexer::getLocForEndOfToken(nextTok->getLocation(), 0, sm, ctxt->getLangOpts());
        }
        
        std::string beforeStr = " { if (";
        if (isCXX(filename))
            beforeStr += "false";
        else
            beforeStr += "0";
        beforeStr += ") { ; } else { if (";
        if (isCXX(filename))
            beforeStr += "true";
        else
            beforeStr += "1";
        if (clang::CompoundStmt::classof(ifStmt->getElse()) && !ifStmt->getElse()->getBeginLoc().isMacroID()) beforeStr += ") ";
        else beforeStr += ") { ";
        rewriter.InsertTextAfter(startLoc, beforeStr);
        if (clang::CompoundStmt::classof(ifStmt->getElse()) && !ifStmt->getElse()->getBeginLoc().isMacroID())
            rewriter.InsertTextAfter(endLoc, " } } ");
        else
            rewriter.InsertTextAfter(endLoc, " } } } ");
    }

    return true;
}

bool Preprocessor::VisitWhileStmt(clang::WhileStmt *whileStmt) {
    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::CharSourceRange charRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(whileStmt->getSourceRange()));
    clang::SourceLocation startLoc=charRange.getBegin();
    clang::SourceLocation startSpellLoc=sm.getSpellingLoc(charRange.getBegin());

    if (sm.getFilename(startLoc)!=filename || sm.getFilename(startSpellLoc)!=filename) return true;  // Ignore headers
    if (whileStmt->getBeginLoc().isMacroID()) return true;  // Ignore macro expansion

    clang::Stmt* body = whileStmt->getBody();
    if (!clang::CompoundStmt::classof(body) || body->getBeginLoc().isMacroID()) {
        clang::CharSourceRange bodyRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(body->getSourceRange()));
        clang::SourceLocation bodyStartLoc=bodyRange.getBegin();
        clang::SourceLocation bodyEndLoc=clang::Lexer::getLocForEndOfToken(bodyRange.getEnd(), 0, sm, ctxt->getLangOpts());
        auto nextTok = clang::Lexer::findNextToken(bodyRange.getEnd(), sm, ctxt->getLangOpts());
        if (nextTok.hasValue() && nextTok->is(clang::tok::semi)) {
            bodyEndLoc = clang::Lexer::getLocForEndOfToken(nextTok->getLocation(), 0, sm, ctxt->getLangOpts());
        }

        rewriter.InsertTextAfter(bodyStartLoc, " { ");
        rewriter.InsertTextAfter(bodyEndLoc, " } ");
    }

    return true;
}

bool Preprocessor::VisitForStmt(clang::ForStmt *forStmt) {
    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::CharSourceRange charRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(forStmt->getSourceRange()));
    clang::SourceLocation startLoc=charRange.getBegin();
    clang::SourceLocation startSpellLoc=sm.getSpellingLoc(charRange.getBegin());

    if (sm.getFilename(startLoc)!=filename || sm.getFilename(startSpellLoc)!=filename) return true;  // Ignore headers
    if (forStmt->getBeginLoc().isMacroID()) return true;  // Ignore macro expansion

    if (forStmt->getCond() == nullptr) {
        // Insert temp 1 or true literal if condition is empty
        clang::SourceLocation loc = sm.getExpansionLoc(forStmt->getBeginLoc());
        while (true) {
            auto next = clang::Lexer::findNextToken(loc, sm, ctxt->getLangOpts());
            if (!next.hasValue()) break;
            if (next->is(clang::tok::semi)) {
                clang::SourceLocation insertLoc = clang::Lexer::getLocForEndOfToken(
                    next->getLocation(), 0, sm, ctxt->getLangOpts());
                rewriter.InsertTextAfter(insertLoc,
                    ctxt->getLangOpts().CPlusPlus ? " true" : " 1");
                break;
            }
            loc = next->getLocation();
        }
    }

    clang::Stmt* body = forStmt->getBody();
    if (!clang::CompoundStmt::classof(body) || body->getBeginLoc().isMacroID()) {
        clang::CharSourceRange bodyRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(body->getSourceRange()));
        clang::SourceLocation bodyStartLoc=bodyRange.getBegin();
        clang::SourceLocation bodyEndLoc=clang::Lexer::getLocForEndOfToken(bodyRange.getEnd(), 0, sm, ctxt->getLangOpts());
        auto nextTok = clang::Lexer::findNextToken(bodyRange.getEnd(), sm, ctxt->getLangOpts());
        if (nextTok.hasValue() && nextTok->is(clang::tok::semi)) {
            bodyEndLoc = clang::Lexer::getLocForEndOfToken(nextTok->getLocation(), 0, sm, ctxt->getLangOpts());
        }

        rewriter.InsertTextAfter(bodyStartLoc, " { ");
        rewriter.InsertTextAfter(bodyEndLoc, " } ");
    }

    return true;
}

std::string Preprocessor::applyPreprocess() {
    rewriter.overwriteChangedFiles();
    return rewriter.getRewrittenText(ctxt->getTranslationUnitDecl()->getSourceRange());
}