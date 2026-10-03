#pragma once

#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include <vector>
#include <set>
#include <clang/Lex/Preprocessor.h>

#include "patch/template.h"
#include "json/struct_information.h"
#include "json/location_information.h"
#include "json/type_information.h"
#include "json/var_information.h"
#include "json/function_information.h"

// When generate patches, we use pointer of Patch class to handle pure abstract methods
class PatchGenerator : public clang::RecursiveASTVisitor<PatchGenerator> {
private:
    clang::ASTContext* ctxt;
    std::string filename;
    std::string origFilename;
    std::string code;
    std::vector<uint32_t> suspiciousLines;
    std::vector<Patch*> patches;
    clang::Preprocessor& preprocessor;

    clang::FunctionDecl* curFuncDecl;
    std::vector<clang::Stmt*> stmtStack;
    std::vector<clang::NamespaceDecl*> namespaceStack;
    // Global ingredients
    std::vector<clang::VarDecl*> intVars;
    std::vector<clang::VarDecl*> uintVars;
    std::vector<clang::VarDecl*> doubleVars;
    std::vector<clang::VarDecl*> ptrVars;
    std::vector<clang::VarDecl*> arrayVars; // Global arrays, registered as themselves
    std::vector<clang::VarDecl*> structVars;
    std::vector<clang::VarDecl*> structPtrVars;

    std::vector<clang::IntegerLiteral*> intLiterals;
    std::vector<clang::IntegerLiteral*> uintLiterals;
    std::vector<clang::FloatingLiteral*> floatLiterals;

    std::vector<std::pair<clang::FunctionDecl*, std::pair<std::string, uint32_t>>> voidFunctions, intFunctions, uintFunctions, ptrFunctions;

    std::map<clang::VarDecl*,std::vector<clang::NamespaceDecl*>> varNamespaceMap;
    std::map<std::string,std::set<uint64_t>> triedSourceLocs;
    std::set<clang::CompoundStmt*> isLoopBodyAndPatched;
    std::set<clang::CompoundStmt*> isSwitchBodyAndPatched;
    // The switch a body belongs to, recorded only for a switch's *own* body. A braced
    // `case`/`default` body is registered in isSwitchBodyAndPatched too but not here, because it
    // is reachable and keeps its setjmp arms inside itself.
    std::map<clang::CompoundStmt*, clang::SwitchStmt*> switchStmtBodies;
    // Loop/switch bodies that a loop encloses, i.e. where a `continue;` is available.
    std::set<clang::CompoundStmt*> scopeInsideLoop;
    // jmp id given to each loop/switch body, to map the statements inside it to its buffers.
    std::map<clang::CompoundStmt*, uint64_t> compoundScopeIDs;

    // Helper function decls
    clang::FunctionDecl* selectMinorIdFunction; // select minor id
    clang::FunctionDecl* exitFunction; // exit() function
    clang::TypedefDecl* intFuncPtrType; // helper type of function pointer for replace_func
    clang::TypedefDecl* uintFuncPtrType; // helper type of function pointer for replace_func
    clang::TypedefDecl* voidFuncPtrType; // helper type of function pointer for replace_func
    clang::FunctionDecl* envToIntFunction; // env_to_int() function
    clang::FunctionDecl* markerFunction = nullptr; // marker function to mark this block is added by metapro
    clang::CallExpr* markerCall = nullptr;

    // Helper decls
    clang::QualType int64ArrayType;
    clang::QualType uint64ArrayType;
    clang::QualType doubleArrayType;
    clang::QualType ptrArrayType;
    clang::QualType strArrayType;

    // Meta-info
    StructInformationFile& structInfo;
    LocationInformation& locationInfo;
    TypeInformation& typeInfo;
    VarInformation& varInfo;
    FunctionInformation& functionInfo;
    std::map<clang::Stmt*,std::vector<std::string>> intVarsInStmt;
    std::map<clang::Stmt*,std::vector<std::string>> uintVarsInStmt;
    std::map<clang::Stmt*,std::vector<std::string>> doubleVarsInStmt;
    std::map<clang::Stmt*,std::vector<std::string>> ptrVarsInStmt;

    // Helper field for specific templates
    bool insideLoop = false; // To check continue/break stmt available
    bool insideSwitchCase = false; // To check break stmt available

    bool containMacro(clang::Stmt* stmt);
    /*
        Code registering var in the variable table of the current function. Every insert of the generated
        code goes through here, and the size/type/descriptor arguments come from TypeInformation, which
        VarInformation stores as well, so that <function>-vars.json cannot disagree with what the
        instrumented program registers.
    */
    std::string genVarTableInsert(std::string insertFunction, clang::VarDecl* var);
    std::string genVarInitRegister(clang::VarDecl* var);
    /* Mark a `static inline` definition of this file `used`, so the compiler emits it even when the
       file never calls it and a patch expression can reach it. See the definition */
    void genUsedAttribute(clang::FunctionDecl* functionDecl);
    /* What the function a variable of function pointer type holds returns, or a null type when it is
       not one. It is what the interpreter needs to call through the variable, see genFuncPtrRegister */
    static clang::QualType getFuncPtrReturnType(clang::QualType varType);
    /* The __metapro_register_func_ptrs_c() call handing the global variables that hold a function to
       the runtime, grouped by what they return, or "" when the function sees none */
    std::string genFuncPtrRegister(const std::vector<clang::VarDecl*>& voidFuncPtrVars,
                                   const std::vector<clang::VarDecl*>& intFuncPtrVars,
                                   const std::vector<clang::VarDecl*>& uintFuncPtrVars,
                                   const std::vector<clang::VarDecl*>& ptrFuncPtrVars);
    /*
        Whether a loop encloses the statement currently being traversed, so that a `continue;`
        written beside it compiles and belongs to that loop.
    */
    bool hasEnclosingLoop();
    /*
        jmp id of the innermost loop/switch body enclosing the statement being traversed, if any.
    */
    bool findEnclosingScopeID(uint64_t& scopeID);
    /*
        Arm the continue/break buffers of a switch scope around its switch statement.
    */
    void insertSwitchScopeArms(clang::SwitchStmt* switchStmt, clang::CompoundStmt* body, uint64_t scopeID);
public:
    static uint64_t loopID; // To handle continue/break stmt with longjmp
    std::map<uint64_t, uint64_t> jmpIDs; // For longjmp for continue/break, map line number to jmpID
    
    PatchGenerator(clang::ASTContext* ctxt,std::vector<unsigned int> lines,std::string filename,std::string origFilename,
                    clang::Preprocessor& preprocessor, StructInformationFile& structInfo, LocationInformation& locationInfo,
                    TypeInformation& typeInfo, VarInformation& varInfo, FunctionInformation& functionInfo);
    bool VisitFunctionDecl(clang::FunctionDecl *functionDecl);

    // To set current function decl
    bool TraverseFunctionDecl(clang::FunctionDecl *functionDecl);
    bool TraverseStmt(clang::Stmt* stmt);
    bool TraverseCXXMethodDecl(clang::CXXMethodDecl *methodDecl); // C++ class method
    bool TraverseCXXConstructorDecl(clang::CXXConstructorDecl *methodDecl); // C++ class constructor
    bool TraverseCXXDestructorDecl(clang::CXXDestructorDecl *methodDecl); // C++ class destructor
    bool TraverseCXXConversionDecl(clang::CXXConversionDecl *methodDecl); // C++ class operator overloading (e.g. operator+())
    bool TraverseNamespaceDecl(clang::NamespaceDecl* namespaceDecl); // C++ namespace decl
    bool TraverseVarDecl(clang::VarDecl* varDecl); // VarDecl to handle C++ namespace
    bool TraverseForStmt(clang::ForStmt* forStmt); // To set insideLoop
    bool TraverseWhileStmt(clang::WhileStmt* whileStmt); // To set insideLoop
    bool TraverseDoStmt(clang::DoStmt* doStmt); // To set insideLoop
    bool TraverseSwitchStmt(clang::SwitchStmt* switchStmt); // To set insideSwtichCase
    bool TraverseCaseStmt(clang::CaseStmt* caseStmt); // To set insideSwtichCase

    bool VisitRecordDecl(clang::RecordDecl* recordDecl);
    bool VisitIfStmt(clang::IfStmt *ifStmt);
    bool VisitForStmt(clang::ForStmt* forStmt);
    bool VisitWhileStmt(clang::WhileStmt* whileStmt);
    bool VisitCompoundStmt(clang::CompoundStmt *compoundStmt);
    bool VisitTypedefDecl(clang::TypedefDecl* typedefDecl);

    std::vector<Patch*> genReplaceVarForCallExpr(clang::CallExpr* callExpr, uint64_t minorId);
    std::vector<Patch*> genReplaceStrLitForCallExpr(clang::CallExpr* callExpr, uint64_t minorId);

    clang::ConditionalOperator* genCallOrigFuncOrPatch(clang::Expr* origExpr, uint64_t majorId, uint64_t minorId, clang::Expr* newExpr);

    std::vector<Patch*> getPatches() { return patches; }
};

class CondExprAssignChecker : public clang::RecursiveASTVisitor<CondExprAssignChecker> {
public:
    bool VisitBinaryOperator(clang::BinaryOperator* binaryOperator);
    bool foundAssignInCond = false;
};