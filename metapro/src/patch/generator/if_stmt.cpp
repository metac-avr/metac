#include "patch/patch_generator.h"
#include "utils/string.h"
#include "utils/path.h"
#include "config/config.h"
#include "patch/patch.h"
#include "patch/finders.h"
#include "config/clang_macro.h"

#include "clang/AST/AST.h"
#include "clang/AST/NestedNameSpecifier.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/SourceManager.h"
#include <clang/Lex/Lexer.h>
#include "spdlog/spdlog.h"

bool PatchGenerator::VisitIfStmt(clang::IfStmt *ifStmt) {
    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::CharSourceRange ifRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(ifStmt->getSourceRange()));
    clang::SourceLocation startLoc = ifRange.getBegin();
    clang::SourceLocation endLoc = clang::Lexer::getLocForEndOfToken(ifRange.getEnd(), 0, sm, ctxt->getLangOpts());
    auto nextTok = clang::Lexer::findNextToken(endLoc, sm, ctxt->getLangOpts());
    if (nextTok.hasValue() && nextTok->is(clang::tok::semi)) {
        endLoc = clang::Lexer::getLocForEndOfToken(nextTok->getLocation(), 0, sm, ctxt->getLangOpts());
    }
    uint64_t cur_line=sm.getExpansionLineNumber(startLoc);

    clang::Expr* cond = ifStmt->getCond();
    clang::CharSourceRange condRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(cond->getSourceRange()));
    // We only generate patches for the suspicious line
    bool suspicious=false;
    for (unsigned int line:suspiciousLines) {
        size_t declLines=1;

        if (sm.getFileID(startLoc) == sm.getMainFileID() && sm.getExpansionLineNumber(startLoc) == line+declLines) {
            suspicious=true;
            break;
        }
    }
    // if (!suspicious) return true;

    if (cond->containsErrors()) {
        spdlog::warn("Condition contains errors, skip patching");
        return true;
    }

    clang::SourceLocation condEndLoc = clang::Lexer::getLocForEndOfToken(condRange.getEnd(), 0, sm, ctxt->getLangOpts());
    uint32_t startOffset=sm.getFileOffset(condRange.getBegin());
    uint32_t endOffset=sm.getFileOffset(condEndLoc);

    uint32_t expLine=sm.getExpansionLineNumber(startLoc);
    uint32_t spellingLine=sm.getSpellingLineNumber(startLoc);
    std::string expFile=sm.getFilename(sm.getExpansionLoc(startLoc)).str();
    std::string spellingFile=sm.getFilename(sm.getSpellingLoc(startLoc)).str();
    if (expFile!=spellingFile || expLine!=spellingLine) return true; // Ignore macros
    if (sm.getFileID(sm.getSpellingLoc(ifStmt->getBeginLoc())) != sm.getMainFileID()) return true; // Ignore macros
    if (sm.getSpellingLoc(ifStmt->getBeginLoc()) != sm.getExpansionLoc(ifStmt->getBeginLoc())) return true; // Ignore macros
    if (startLoc.isMacroID()) return true; // Ignore macros


    LocalDeclFinder declFinder(ctxt,ifStmt);
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

    /* REPLACE_CONDITION at if stmt */
    if (Config::getConfig().noTemplates.find("REPLACE_CONDITION")==Config::getConfig().noTemplates.end() &&
                        !clang::OpaqueValueExpr::classof(cond)) {
        // Check if there is assignment in condition
        CondExprAssignChecker assignChecker;
        assignChecker.TraverseStmt(cond);
        if (assignChecker.foundAssignInCond) return true;
        
        std::string origCond = code.substr(startOffset, endOffset - startOffset);
        if (origCond.find("#") != std::string::npos && origCond.find("if") != std::string::npos) {
            // Now we skip if condition contains #if stuffs. Later maybe count the number of #if and #endif and skip if the number is mismatch
            return true;
        }
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
                        ReplaceConditionPatch::ReplaceConditionKind::REPLACE_IF,condRange,expLine);
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