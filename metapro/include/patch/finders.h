#pragma once

#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include <stack>

class LiteralFinder : public clang::RecursiveASTVisitor<LiteralFinder> {
private:
    clang::ASTContext* ctxt;
    std::vector<clang::IntegerLiteral*> intLiterals;
    std::vector<clang::IntegerLiteral*> uintLiterals;
    std::vector<clang::FloatingLiteral*> floatLiterals;
public:
    LiteralFinder(clang::ASTContext* ctxt): ctxt(ctxt) {};
    bool VisitIntegerLiteral(clang::IntegerLiteral *intLiteral);
    bool VisitFloatingLiteral(clang::FloatingLiteral *floatLiteral);
    std::vector<clang::IntegerLiteral*> getIntLiterals();
    std::vector<clang::IntegerLiteral*> getUIntLiterals();
    std::vector<clang::FloatingLiteral*> getFloatLiterals();
};

class GlobalDeclFinderC : public clang::RecursiveASTVisitor<GlobalDeclFinderC> {
private:
    clang::ASTContext* ctxt;
    std::vector<clang::VarDecl*> intVars;
    std::vector<clang::VarDecl*> uintVars;
    std::vector<clang::VarDecl*> doubleVars;
    std::vector<clang::VarDecl*> ptrVars;
    std::vector<clang::VarDecl*> structVars;
    std::vector<clang::VarDecl*> structPtrVars;
    std::vector<clang::VarDecl*> arrayVars;
public:
    GlobalDeclFinderC(clang::ASTContext* ctxt): ctxt(ctxt) {};
    bool VisitVarDecl(clang::VarDecl *varDecl);
    std::vector<clang::VarDecl*> getIntVars();
    std::vector<clang::VarDecl*> getUIntVars();
    std::vector<clang::VarDecl*> getDoubleVars();
    std::vector<clang::VarDecl*> getPtrVars();
    std::vector<clang::VarDecl*> getStructVars();
    std::vector<clang::VarDecl*> getStructPtrVars();
    std::vector<clang::VarDecl*> getArrayVars();
};

class GlobalDeclFinderCXX : public clang::RecursiveASTVisitor<GlobalDeclFinderCXX> {
private:
    clang::ASTContext* ctxt;
    std::vector<clang::VarDecl*> intVars;
    std::vector<clang::VarDecl*> uintVars;
    std::vector<clang::VarDecl*> doubleVars;
    std::vector<clang::VarDecl*> ptrVars;
    std::vector<clang::FunctionDecl*> functions;
public:
    GlobalDeclFinderCXX(clang::ASTContext* ctxt): ctxt(ctxt) {};
    bool VisitDeclRefExpr(clang::DeclRefExpr *declRefExpr);
    std::vector<clang::VarDecl*> getIntVars();
    std::vector<clang::VarDecl*> getUIntVars();
    std::vector<clang::VarDecl*> getDoubleVars();
    std::vector<clang::VarDecl*> getPtrVars();
    std::vector<clang::FunctionDecl*> getFunctions();
};

class LocalDeclFinder : public clang::RecursiveASTVisitor<LocalDeclFinder> {
private:
    clang::ASTContext* ctxt;
    clang::Stmt* targetStmt;

    std::map<clang::Stmt*,std::vector<clang::VarDecl*>> intVarStack;
    std::map<clang::Stmt*,std::vector<clang::VarDecl*>> uintVarStack;
    std::map<clang::Stmt*,std::vector<clang::VarDecl*>> doubleVarStack;
    std::map<clang::Stmt*,std::vector<clang::VarDecl*>> ptrVarStack;
    std::map<clang::Stmt*,std::vector<clang::VarDecl*>> intPtrVarStack;
    std::map<clang::Stmt*,std::vector<clang::VarDecl*>> uintPtrVarStack;
    std::map<clang::Stmt*,std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>>> intFieldStack;
    std::map<clang::Stmt*,std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>>> uintFieldStack;
    std::map<clang::Stmt*,std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>>> doubleFieldStack;
    std::map<clang::Stmt*,std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>>> ptrFieldStack;

    std::vector<clang::VarDecl*> intParams;
    std::vector<clang::VarDecl*> uintParams;
    std::vector<clang::VarDecl*> doubleParams;
    std::vector<clang::VarDecl*> ptrParams;
    std::vector<clang::VarDecl*> intPtrParams;
    std::vector<clang::VarDecl*> uintPtrParams;

    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> intFieldParams;
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> uintFieldParams;
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> doubleFieldParams;
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> ptrFieldParams;
    std::vector<clang::Stmt*> stmtStack;
    
    uint32_t funcPtrTypeParamSize;
public:
    /* Used for placeholder of pointer field */
    const int64_t INT_UNIQUE_NUMBER=0xAAAAAAAA;
    const double FLOAT_UNIQUE_NUMBER=0.65548156;

    LocalDeclFinder(clang::ASTContext* ctxt,clang::Stmt* targetStmt): ctxt(ctxt),targetStmt(targetStmt),funcPtrTypeParamSize(0) {};
    bool VisitVarDecl(clang::VarDecl *varDecl);
    bool TraverseCompoundStmt(clang::CompoundStmt *compoundStmt);
    bool TraverseIfStmt(clang::IfStmt *ifStmt);
    bool TraverseForStmt(clang::ForStmt *forStmt);
    bool TraverseWhileStmt(clang::WhileStmt *whileStmt);
    bool TraverseStmt(clang::Stmt *stmt);
    bool TraverseLambdaExpr(clang::LambdaExpr *lambdaExpr);
    void getAvailableFields(std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>>& members,clang::FieldDecl* curField,clang::Expr* baseExpr,bool isBaseArrow,uint32_t depth=0);
    std::vector<clang::VarDecl*> getIntVars();
    std::vector<clang::VarDecl*> getUIntVars();
    std::vector<clang::VarDecl*> getDoubleVars();
    std::vector<clang::VarDecl*> getPtrVars();
    std::vector<clang::VarDecl*> getIntPtrVars();
    std::vector<clang::VarDecl*> getUIntPtrVars();

    /* <<basic_ternary, ptr_ternary>, code */
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> getIntFields();
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> getUIntFields();
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> getDoubleFields();
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> getPtrFields();
};

class FunctionFinder : public clang::RecursiveASTVisitor<FunctionFinder> {
private:
    clang::ASTContext* ctxt;
    std::string filename;
    std::set<clang::FunctionDecl*> visitedFunctions;

    // bool isBlacklisted(std::string funcName); // See finders.cpp

public:
    // Functions: FunctionDecl*, <filename, line>
    std::vector<std::pair<clang::FunctionDecl*, std::pair<std::string, uint32_t>>> voidFunctions, intFunctions, uintFunctions, ptrFunctions;
    FunctionFinder(clang::ASTContext* ctxt, const std::string& filename)
        : ctxt(ctxt), filename(filename) {};
    bool VisitCallExpr(clang::CallExpr *callExpr);
    bool VisitFunctionDecl(clang::FunctionDecl *funcDecl);
};

class LabelFinder : public clang::RecursiveASTVisitor<LabelFinder> {
public:
    std::vector<std::string> labels;
    bool VisitLabelStmt(clang::LabelStmt* labelStmt);
};