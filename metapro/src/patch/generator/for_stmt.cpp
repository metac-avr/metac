#include "patch/patch_generator.h"
#include "utils/string.h"
#include "utils/path.h"
#include <llvm-12/llvm/Support/Casting.h>
#include <string>
#include "config/config.h"
#include "patch/patch.h"
#include "patch/finders.h"
#include "config/clang_macro.h"

#include "clang/AST/AST.h"
#include "clang/AST/Expr.h"
#include "clang/AST/NestedNameSpecifier.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/SourceManager.h"
#include "spdlog/spdlog.h"

bool PatchGenerator::VisitForStmt(clang::ForStmt* forStmt) {
    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::CharSourceRange forRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(forStmt->getSourceRange()));
    clang::SourceLocation startLoc = forRange.getBegin();
    clang::SourceLocation endLoc = clang::Lexer::getLocForEndOfToken(forRange.getEnd(), 0, sm, ctxt->getLangOpts());
    auto nextTok = clang::Lexer::findNextToken(endLoc, sm, ctxt->getLangOpts());
    if (nextTok.hasValue() && nextTok->is(clang::tok::semi)) {
        endLoc = clang::Lexer::getLocForEndOfToken(nextTok->getLocation(), 0, sm, ctxt->getLangOpts());
    }

    if (sm.getFileID(sm.getSpellingLoc(forStmt->getBeginLoc())) != sm.getMainFileID()) return true; // Ignore macros
    if (sm.getSpellingLoc(forStmt->getBeginLoc()) != sm.getExpansionLoc(forStmt->getBeginLoc())) return true; // Ignore macros
    if (startLoc.isMacroID()) return true; // Ignore macros

    /*
        Register the variables of the init part. The registration is wrapped around the initializer of each
        variable, so that the condition can already use it on the first iteration: a declaration cannot be
        followed by a statement here, and a registration inserted into the body only runs after the
        condition has been evaluated once. A variable declared without an initializer has nothing to wrap
        and is left unregistered.
    */
    clang::Stmt* init = forStmt->getInit();
    if (init != nullptr && clang::DeclStmt::classof(init)) {
        clang::DeclStmt* declStmt = llvm::dyn_cast<clang::DeclStmt>(init);
        for (clang::Decl* decl:declStmt->decls()) {
            if (!clang::VarDecl::classof(decl)) continue;
            clang::VarDecl* var=llvm::dyn_cast<clang::VarDecl>(decl);
            if (var->getStorageClass() == clang::SC_Register) continue;
            if (var->getNameAsString() == "pcre2_dfa_match_") continue; // PHP blacklist
            if (var->getType()->isFunctionPointerType()) continue;
            TypeInformation::TypeCategory category = TypeInformation::getCategory(var->getType());
            if (category != TypeInformation::SignedInteger && category != TypeInformation::UnsignedInteger &&
                    category != TypeInformation::FloatingPoint)
                continue; // Only support int/double for now. The others are quite rare in for init

            // Only "= <expr>" can hold the registration. A braced or parenthesized initializer is not an
            // expression the macro could evaluate to
            clang::Expr* initExpr = var->getInit();
            if (initExpr == nullptr || var->getInitStyle() != clang::VarDecl::CInit) continue;
            if (clang::InitListExpr::classof(initExpr)) continue;
            clang::CharSourceRange initRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(initExpr->getSourceRange()));
            clang::SourceLocation initStartLoc = initRange.getBegin();
            clang::SourceLocation initEndLoc = clang::Lexer::getLocForEndOfToken(initRange.getEnd(), 0, sm, ctxt->getLangOpts());
            if (initStartLoc.isInvalid() || initEndLoc.isInvalid()) continue;
            if (initStartLoc.isMacroID() || initEndLoc.isMacroID()) continue; // Ignore macros

            typeInfo.addType(ctxt, var->getType());
            // The initializer of var stays as it is, between the opening of the macro call and this ")"
            patches.push_back(new InsertPatch(ctxt,stmtToString(ctxt,init),code,0,genVarInitRegister(var),
                        initStartLoc,sm.getExpansionLineNumber(initStartLoc)));
            patches.push_back(new InsertPatch(ctxt,stmtToString(ctxt,init),code,0,")",
                        initEndLoc,sm.getExpansionLineNumber(initEndLoc)));
        }
    }

    // Insert patch location to info
    clang::Expr* cond = forStmt->getCond();
    clang::CharSourceRange condRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(cond->getSourceRange()));
    clang::SourceLocation condStartLoc = condRange.getBegin();

    if (forStmt->getCond()==nullptr) return true; // for statement sometimes has no condition


    if (cond->containsErrors()) return true;
    LocalDeclFinder declFinder(ctxt,forStmt);
    declFinder.TraverseDecl(curFuncDecl);
    std::vector<clang::VarDecl*> curIntVars;
    std::vector<clang::VarDecl*> curUIntVars;
    std::vector<clang::VarDecl*> curDoubleVars;
    std::vector<clang::VarDecl*> curPtrVars;
    if (isCXX(filename) || true){
        GlobalDeclFinderCXX glbDeclFinder(ctxt);
        glbDeclFinder.TraverseDecl(curFuncDecl);
        curIntVars=glbDeclFinder.getIntVars();
        curUIntVars=glbDeclFinder.getUIntVars();
        curDoubleVars=glbDeclFinder.getDoubleVars();
        curPtrVars=glbDeclFinder.getPtrVars();
    }
    else {
        for (clang::VarDecl* var:intVars) {
            if (sm.getExpansionLineNumber(var->getBeginLoc())<=sm.getExpansionLineNumber(startLoc))
                curIntVars.push_back(var);
        }
        for (clang::VarDecl* var:uintVars) {
            if (sm.getExpansionLineNumber(var->getBeginLoc())<=sm.getExpansionLineNumber(startLoc))
                curUIntVars.push_back(var);
        }
        for (clang::VarDecl* var:doubleVars) {
            if (sm.getExpansionLineNumber(var->getBeginLoc())<=sm.getExpansionLineNumber(startLoc))
                curDoubleVars.push_back(var);
        }
        for (clang::VarDecl* var:ptrVars) {
            if (sm.getExpansionLineNumber(var->getBeginLoc())<=sm.getExpansionLineNumber(startLoc))
                curPtrVars.push_back(var);
        }
    }

    for (clang::VarDecl* var:declFinder.getIntVars()) curIntVars.push_back(var);
    for (clang::VarDecl* var:declFinder.getUIntVars()) curUIntVars.push_back(var);
    for (clang::VarDecl* var:declFinder.getDoubleVars()) curDoubleVars.push_back(var);
    for (clang::VarDecl* var:declFinder.getPtrVars()) curPtrVars.push_back(var);

    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> intFields=declFinder.getIntFields();
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> uintFields=declFinder.getUIntFields();
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> doubleFields=declFinder.getDoubleFields();
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> ptrFields=declFinder.getPtrFields();

    unsigned int int_var_size=curIntVars.size()+intFields.size();
    unsigned int uint_var_size=curUIntVars.size()+uintFields.size();
    unsigned int double_var_size=curDoubleVars.size()+doubleFields.size();
    unsigned int ptr_var_size=curPtrVars.size()+ptrFields.size();

    /* REPLACE_CONDITION at for stmt */
    if (Config::getConfig().noTemplates.find("REPLACE_CONDITION")==Config::getConfig().noTemplates.end()) {
        clang::CharSourceRange condRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(forStmt->getCond()->getSourceRange()));
        clang::SourceLocation condEndLoc = clang::Lexer::getLocForEndOfToken(condRange.getEnd(), 0, sm, ctxt->getLangOpts());
        // For condition should not include semi-colon
        uint64_t startOffset = sm.getFileOffset(condRange.getBegin());
        uint64_t endOffset = sm.getFileOffset(condEndLoc);
        std::string origCond = code.substr(startOffset, endOffset - startOffset);
        if (origCond.find("#") != std::string::npos && origCond.find("if") != std::string::npos) {
            // Now we skip if condition contains #if stuffs. Later maybe count the number of #if and #endif and skip if the number is mismatch
            return true;
        }

        // Collect variable info
#if 0
        std::vector<VariablePatch::VariableInfo> intInfoList;
        for (clang::VarDecl* var:curIntVars) {
            intInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(),ctxt->getTypeSize(var->getType())));
        }
        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:intFields) {
            intInfoList.push_back(VariablePatch::VariableInfo(field.second, ctxt->getTypeSize(field.first.second->getType())));
        }
        std::vector<VariablePatch::VariableInfo> uintInfoList;
        for (clang::VarDecl* var:curUIntVars) {
            uintInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(),ctxt->getTypeSize(var->getType())));
        }
        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:uintFields) {
            uintInfoList.push_back(VariablePatch::VariableInfo(field.second, ctxt->getTypeSize(field.first.second->getType())));
        }
        std::vector<VariablePatch::VariableInfo> doubleInfoList;
        for (clang::VarDecl* var:curDoubleVars) {
            doubleInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(),ctxt->getTypeSize(var->getType())));
        }
        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:doubleFields) {
            doubleInfoList.push_back(VariablePatch::VariableInfo(field.second, ctxt->getTypeSize(field.first.second->getType())));
        }
        std::vector<VariablePatch::VariableInfo> ptrInfoList;
        for (clang::VarDecl* var:curPtrVars) {
            ptrInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(),ctxt->getTypeSize(var->getType())));
        }
        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:ptrFields) {
            ptrInfoList.push_back(VariablePatch::VariableInfo(field.second, ctxt->getTypeSize(field.first.second->getType())));
        }
        // Int literals
        std::vector<VariablePatch::VariableInfo> intLitInfos;
        for (clang::IntegerLiteral* var:intLiterals) {
            intLitInfos.push_back(VariablePatch::VariableInfo(stmtToString(ctxt,var),ctxt->getTypeSize(var->getType())));
        }
        // Uint literals
        std::vector<VariablePatch::VariableInfo> uintLitInfos;
        for (clang::IntegerLiteral* var:uintLiterals) {
            uintLitInfos.push_back(VariablePatch::VariableInfo(stmtToString(ctxt,var),ctxt->getTypeSize(var->getType())));
        }
        // Float literals
        std::vector<VariablePatch::VariableInfo> floatLitInfos;
        for (clang::FloatingLiteral* var:floatLiterals) {
            floatLitInfos.push_back(VariablePatch::VariableInfo(stmtToString(ctxt,var),ctxt->getTypeSize(var->getType())));
        }
#endif

        std::string callExpr = "__metapro_replace_cond_c(" + std::to_string(Config::getConfig().patchId) + ", ";
        callExpr += "\"" + escapeForCStringLiteral(origCond) + "\"";
        callExpr += ", (unsigned int)(" + origCond + "), \"";
        callExpr += curFuncDecl->getNameAsString() + "\")";

        std::string origCode=code.substr(sm.getFileOffset(startLoc),
                    sm.getFileOffset(endLoc) - sm.getFileOffset(startLoc));
        std::string condCode=code.substr(startOffset, endOffset - startOffset);
        std::string newCode=callExpr;
        ReplaceConditionPatch* patch=new ReplaceConditionPatch(ctxt,origCode,condCode,code,Config::getConfig().patchId,newCode,
                    ReplaceConditionPatch::ReplaceConditionKind::REPLACE_FOR,condRange,sm.getExpansionLineNumber(startLoc));
#if 0
        patch->intVars=intInfoList;
        patch->uintVars=uintInfoList;
        patch->doubleVars=doubleInfoList;
        patch->ptrVars=ptrInfoList;
        patch->intLits=intLitInfos;
        patch->uintLits=uintLitInfos;
        patch->floatLits=floatLitInfos;
#endif

        patches.push_back(patch);

        Config::getConfig().patchId++;
    }

    return true;
}