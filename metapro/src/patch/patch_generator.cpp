#include "patch/patch_generator.h"
#include "patch/patch.h"
#include "patch/finders.h"
#include "utils/path.h"
#include "utils/string.h"
#include "config/config.h"
#include "config/clang_macro.h"

#include "clang/AST/AST.h"
#include "clang/AST/NestedNameSpecifier.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/SourceManager.h"
#include "spdlog/spdlog.h"
#include <fstream>
#include <set>
#include <iostream>
#include <clang/Lex/Lexer.h>
#include <clang/Lex/Preprocessor.h>

uint64_t PatchGenerator::loopID = 0;

PatchGenerator::PatchGenerator(clang::ASTContext* ctxt,std::vector<unsigned int> lines,std::string filename,
                    std::string origFilename,clang::Preprocessor& preprocessor, StructInformationFile &structInfo, LocationInformation &locationInfo,
                    TypeInformation &typeInfo, VarInformation &varInfo,
                    FunctionInformation &functionInfo): ctxt(ctxt),
                                suspiciousLines(lines),origFilename(origFilename),structInfo(structInfo),
                                filename(filename),curFuncDecl(nullptr),
                                exitFunction(nullptr),preprocessor(preprocessor),
                                int64ArrayType(ctxt->getIncompleteArrayType(ctxt->LongLongTy,clang::ArrayType::Normal,0)),
                                uint64ArrayType(ctxt->getIncompleteArrayType(ctxt->UnsignedLongLongTy,clang::ArrayType::Normal,0)),
                                doubleArrayType(ctxt->getIncompleteArrayType(ctxt->LongDoubleTy,clang::ArrayType::Normal,0)),
                                ptrArrayType(ctxt->getIncompleteArrayType(ctxt->VoidPtrTy,clang::ArrayType::Normal,0)),
                                strArrayType(ctxt->getIncompleteArrayType(ctxt->getPointerType(ctxt->CharTy),clang::ArrayType::Normal,0)),
                                locationInfo(locationInfo),typeInfo(typeInfo),varInfo(varInfo),
                                functionInfo(functionInfo) {
    // Find all available global variables and functions
    GlobalDeclFinderC declFinder(ctxt);
    declFinder.TraverseDecl(ctxt->getTranslationUnitDecl());
    intVars=declFinder.getIntVars();
    uintVars=declFinder.getUIntVars();
    doubleVars=declFinder.getDoubleVars();
    ptrVars=declFinder.getPtrVars();
    structVars=declFinder.getStructVars();
    structPtrVars=declFinder.getStructPtrVars();
    arrayVars=declFinder.getArrayVars();

    spdlog::debug("Found {} global int variables",intVars.size());
    spdlog::debug("Found {} global unsigned int variables",uintVars.size());
    spdlog::debug("Found {} global double variables",doubleVars.size());
    spdlog::debug("Found {} global pointer variables",ptrVars.size());
    spdlog::debug("Found {} global struct variables",structVars.size());
    spdlog::debug("Found {} global struct pointer variables",structPtrVars.size());
    spdlog::debug("Found {} global array variables",arrayVars.size());

    // Find all available literals
    LiteralFinder literalFinder(ctxt);
    literalFinder.TraverseDecl(ctxt->getTranslationUnitDecl());
    intLiterals=literalFinder.getIntLiterals();
    uintLiterals=literalFinder.getUIntLiterals();
    floatLiterals=literalFinder.getFloatLiterals();

    // Find all available functions
    FunctionFinder functionFinder(ctxt,filename);
    functionFinder.TraverseDecl(ctxt->getTranslationUnitDecl());
    voidFunctions=functionFinder.voidFunctions;
    intFunctions=functionFinder.intFunctions;
    uintFunctions=functionFinder.uintFunctions;
    ptrFunctions=functionFinder.ptrFunctions;
    /*
        Store what a patch expression needs to call these: the runtime resolves a callee by name while
        it evaluates the expression, so the meta-program neither takes their addresses nor registers
        them at every function entry
    */
    for (auto& funcPair:voidFunctions) functionInfo.addFunction(funcPair.first);
    for (auto& funcPair:intFunctions) functionInfo.addFunction(funcPair.first);
    for (auto& funcPair:uintFunctions) functionInfo.addFunction(funcPair.first);
    for (auto& funcPair:ptrFunctions) functionInfo.addFunction(funcPair.first);

    std::ifstream ifs(filename);
    std::string content((std::istreambuf_iterator<char>(ifs)),(std::istreambuf_iterator<char>()));
    ifs.close();
    code=content;
}

std::string PatchGenerator::genVarTableInsert(std::string insertFunction, clang::VarDecl* var) {
    clang::QualType varType = var->getType();
    std::string varName = var->getNameAsString();
    std::string code = "";

    // An array is registered as itself (MetaproVarTypeArray): `&array` is the address of the
    // elements, which is what the interpreter subscripts off the reference it is given. A temp
    // holding that address would make the reference point at the temp, so indexing it would walk
    // the frame around the temp instead of the array.
    std::string refExpr = "&" + varName;

    code += insertFunction + "(\"" + curFuncDecl->getNameAsString() + "\", ";
    code += "\"" + varName + "\", " + refExpr + ", ";
    code += std::to_string(TypeInformation::getVarSize(ctxt, varType)) + ", ";
    code += TypeInformation::getVarTypeName(varType, isCXX(filename)) + ", ";
    std::string descriptor = TypeInformation::getVarDescriptor(ctxt, varType);
    code += (descriptor == "") ? "NULL); " : "\"" + descriptor + "\"); ";
    return code;
}

clang::QualType PatchGenerator::getFuncPtrReturnType(clang::QualType varType) {
    if (!varType->isFunctionPointerType()) return clang::QualType();
    const clang::FunctionType* funcType = varType->getPointeeType()->getAs<clang::FunctionType>();
    return (funcType == nullptr) ? clang::QualType() : funcType->getReturnType();
}

/*
    One group of the __metapro_register_func_ptrs_c() call: the number of variables, their names and their
    addresses, as the two array arguments the call takes. An empty group passes nothing to walk.
*/
static std::string genFuncPtrGroup(const std::vector<clang::VarDecl*>& vars) {
    if (vars.empty()) return "0, NULL, NULL";
    std::string names, refs;
    for (clang::VarDecl* var:vars) {
        std::string varName = var->getNameAsString();
        if (!names.empty()) { names += ", "; refs += ", "; }
        names += "\"" + varName + "\"";
        refs += "(void*)&" + varName;
    }
    return std::to_string(vars.size()) + ", (char*[]){" + names + "}, (void*[]){" + refs + "}";
}

std::string PatchGenerator::genFuncPtrRegister(const std::vector<clang::VarDecl*>& voidFuncPtrVars,
                                               const std::vector<clang::VarDecl*>& intFuncPtrVars,
                                               const std::vector<clang::VarDecl*>& uintFuncPtrVars,
                                               const std::vector<clang::VarDecl*>& ptrFuncPtrVars) {
    if (voidFuncPtrVars.empty() && intFuncPtrVars.empty() &&
            uintFuncPtrVars.empty() && ptrFuncPtrVars.empty()) {
        return "";
    }
    // The arrays are compound literals, so this is C only; the C++ runtime has no counterpart
    if (isCXX(filename)) return "";

    std::string code = "__metapro_register_func_ptrs_c(\"" + curFuncDecl->getNameAsString() + "\", ";
    code += genFuncPtrGroup(voidFuncPtrVars) + ", ";
    code += genFuncPtrGroup(intFuncPtrVars) + ", ";
    code += genFuncPtrGroup(uintFuncPtrVars) + ", ";
    code += genFuncPtrGroup(ptrFuncPtrVars) + "); ";
    return code;
}

/*
    Opening of the __metapro_init_var_*() call registering var while it is initialized, up to and including
    the comma before the initializer. The initializer of var follows it, then ")": the init clause of a for
    statement declares a variable without a statement to register it in, so the registration rides along in
    the initializer, which the macro evaluates to. Only a scalar variable fits, as the temp holding the
    address of an array needs a declaration of its own.
*/
std::string PatchGenerator::genVarInitRegister(clang::VarDecl* var) {
    clang::QualType varType = var->getType();
    std::string varName = var->getNameAsString();

    std::string code = isCXX(filename) ? "__metapro_init_var_cxx(\"" : "__metapro_init_var_c(\"";
    code += curFuncDecl->getNameAsString() + "\", ";
    code += "\"" + varName + "\", &" + varName + ", ";
    code += std::to_string(TypeInformation::getVarSize(ctxt, varType)) + ", ";
    code += TypeInformation::getVarTypeName(varType, isCXX(filename)) + ", ";
    std::string descriptor = TypeInformation::getVarDescriptor(ctxt, varType);
    code += (descriptor == "") ? "NULL, " : "\"" + descriptor + "\", ";
    return code;
}

bool PatchGenerator::TraverseStmt(clang::Stmt* stmt) {
    stmtStack.push_back(stmt);
    bool result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseStmt(stmt);
    stmtStack.pop_back();
    return result;

}

/*
    Keep a `static inline` function in the binary, so that a patch expression can call it.

    Nothing emits such a function unless its own file calls it: it has internal linkage, so an
    unreferenced one is dead code the compiler drops before the linker ever sees it -- clang does at every
    optimization level, and -fno-inline changes nothing, because a function nothing calls has no call site
    to inline. `used` forces it into the object file. Its symbol is local, which dlsym cannot see, but
    find_local_symbol() reads the symbol table of the program itself for exactly that case.

    The attribute goes in front of the declaration specifiers and brings no newline with it, so every line
    of the file keeps the number it had: the patch config maps a source line onto the meta-program by line.
*/
void PatchGenerator::genUsedAttribute(clang::FunctionDecl* functionDecl) {
    if (!functionDecl->isThisDeclarationADefinition()) return;
    if (functionDecl->getStorageClass() != clang::SC_Static) return;
    if (functionDecl->hasAttr<clang::UsedAttr>()) return; // The program asked for it itself

    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::SourceLocation beginLoc = functionDecl->getBeginLoc();
    // A location the preprocessor made up is not a place to write at, and only this file is written out:
    // a static inline function of a header keeps being dropped, there is no copy of it to rewrite
    if (beginLoc.isInvalid() || beginLoc.isMacroID()) return;
    if (sm.getFilename(beginLoc).str() != filename) return;

    patches.push_back(new InsertPatch(ctxt, functionDecl->getNameAsString(), code, 0,
                                      "__attribute__((used)) ", beginLoc,
                                      sm.getExpansionLineNumber(beginLoc)));
}

bool PatchGenerator::TraverseFunctionDecl(clang::FunctionDecl* functionDecl) {
    bool result;
    clang::SourceManager& sm = ctxt->getSourceManager();
    genUsedAttribute(functionDecl);
    // Do not traverse functions not in the suspicious lines
    // bool gen_patch = false;
    // for (uint32_t line : suspiciousLines) {
    //     if (filename == sm.getFilename(sm.getExpansionLoc(functionDecl->getBeginLoc())).str()) {
    //         uint32_t start_line = sm.getExpansionLineNumber(functionDecl->getBeginLoc());
    //         uint32_t end_line = sm.getExpansionLineNumber(functionDecl->getEndLoc());
    //         if (line>=start_line && line<=end_line) {
    //             gen_patch = true;
    //             break;
    //         }
    //     }
    // }
    // if (!gen_patch) {
    //     return true;
    // }

    if (curFuncDecl == nullptr) {
        curFuncDecl=functionDecl;
        result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseFunctionDecl(functionDecl);
        curFuncDecl=nullptr;
    }
    else {
        result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseFunctionDecl(functionDecl);
    }
    return result;
}

bool PatchGenerator::TraverseCXXMethodDecl(clang::CXXMethodDecl *methodDecl) {
    bool result;
    clang::SourceManager& sm = ctxt->getSourceManager();
    // // Do not traverse functions not in the suspicious lines
    // bool gen_patch = false;
    // for (uint32_t line : suspiciousLines) {
    //     if (filename == sm.getFilename(sm.getExpansionLoc(methodDecl->getBeginLoc())).str()) {
    //         uint32_t start_line = sm.getExpansionLineNumber(methodDecl->getBeginLoc());
    //         uint32_t end_line = sm.getExpansionLineNumber(methodDecl->getEndLoc());
    //         if (line>=start_line && line<=end_line) {
    //             gen_patch = true;
    //             break;
    //         }
    //     }
    // }
    // if (!gen_patch) {
    //     return true;
    // }

    if (curFuncDecl == nullptr) {
        curFuncDecl=methodDecl;
        result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseCXXMethodDecl(methodDecl);
        curFuncDecl=nullptr;
    }
    else {
        result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseCXXMethodDecl(methodDecl);
    }
    return result;
}

bool PatchGenerator::TraverseCXXConstructorDecl(clang::CXXConstructorDecl *methodDecl) {
    bool result;
    clang::SourceManager& sm = ctxt->getSourceManager();
    // // Do not traverse functions not in the suspicious lines
    // bool gen_patch = false;
    // for (uint32_t line : suspiciousLines) {
    //     if (filename == sm.getFilename(sm.getExpansionLoc(methodDecl->getBeginLoc())).str()) {
    //         uint32_t start_line = sm.getExpansionLineNumber(methodDecl->getBeginLoc());
    //         uint32_t end_line = sm.getExpansionLineNumber(methodDecl->getEndLoc());
    //         if (line>=start_line && line<=end_line) {
    //             gen_patch = true;
    //             break;
    //         }
    //     }
    // }
    // if (!gen_patch) {
    //     return true;
    // }

    if (curFuncDecl == nullptr) {
        curFuncDecl=methodDecl;
        result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseCXXConstructorDecl(methodDecl);
        curFuncDecl=nullptr;
    }
    else {
        result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseCXXConstructorDecl(methodDecl);
    }
    return result;
}

bool PatchGenerator::TraverseCXXDestructorDecl(clang::CXXDestructorDecl *methodDecl) {
    bool result;
    clang::SourceManager& sm = ctxt->getSourceManager();
    // // Do not traverse functions not in the suspicious lines
    // bool gen_patch = false;
    // for (uint32_t line : suspiciousLines) {
    //     if (filename == sm.getFilename(sm.getExpansionLoc(methodDecl->getBeginLoc())).str()) {
    //         uint32_t start_line = sm.getExpansionLineNumber(methodDecl->getBeginLoc());
    //         uint32_t end_line = sm.getExpansionLineNumber(methodDecl->getEndLoc());
    //         if (line>=start_line && line<=end_line) {
    //             gen_patch = true;
    //             break;
    //         }
    //     }
    // }
    // if (!gen_patch) {
    //     return true;
    // }

    if (curFuncDecl == nullptr) {
        curFuncDecl=methodDecl;
        result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseCXXDestructorDecl(methodDecl);
        curFuncDecl=nullptr;
    }
    else {
        result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseCXXDestructorDecl(methodDecl);
    }
    return result;
}

bool PatchGenerator::TraverseCXXConversionDecl(clang::CXXConversionDecl *methodDecl) {
    bool result;
    clang::SourceManager& sm = ctxt->getSourceManager();
    // // Do not traverse functions not in the suspicious lines
    // bool gen_patch = false;
    // for (uint32_t line : suspiciousLines) {
    //     if (filename == sm.getFilename(sm.getExpansionLoc(methodDecl->getBeginLoc())).str()) {
    //         uint32_t start_line = sm.getExpansionLineNumber(methodDecl->getBeginLoc());
    //         uint32_t end_line = sm.getExpansionLineNumber(methodDecl->getEndLoc());
    //         if (line>=start_line && line<=end_line) {
    //             gen_patch = true;
    //             break;
    //         }
    //     }
    // }
    // if (!gen_patch) {
    //     return true;
    // }

    if (curFuncDecl == nullptr) {
        curFuncDecl=methodDecl;
        result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseCXXConversionDecl(methodDecl);
        curFuncDecl=nullptr;
    }
    else {
        result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseCXXConversionDecl(methodDecl);
    }
    return result;
}

bool PatchGenerator::TraverseNamespaceDecl(clang::NamespaceDecl* namespaceDecl) {
    namespaceStack.push_back(namespaceDecl);
    bool result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseNamespaceDecl(namespaceDecl);
    namespaceStack.pop_back();
    return result;
}

bool PatchGenerator::TraverseVarDecl(clang::VarDecl* varDecl) {
    if (namespaceStack.size()>0) {
        varNamespaceMap[varDecl]=std::vector<clang::NamespaceDecl*>(namespaceStack);
    }
    if (curFuncDecl != nullptr)
        structInfo.addTypeInfo(ctxt, curFuncDecl->getNameAsString(), varDecl->getNameAsString(), varDecl->getType());
    else
        structInfo.addTypeInfo(ctxt, "global", varDecl->getNameAsString(), varDecl->getType());
    typeInfo.addType(ctxt, varDecl->getType());
    if (curFuncDecl != nullptr) {
        // Locals of this file only. A local of a header belongs to a function this file does not patch
        clang::SourceManager& sm = ctxt->getSourceManager();
        if (sm.getFileID(sm.getExpansionLoc(varDecl->getBeginLoc())) == sm.getMainFileID()) {
            varInfo.addVariable(curFuncDecl->getNameAsString(), varDecl);
        }
    }
    else {
        // Globals of the headers too, because GlobalDeclFinderC registers every global of the translation
        // unit in the variable table, no matter which file declares it
        varInfo.addVariable("global", varDecl);
    }
    return true;
}

bool PatchGenerator::TraverseForStmt(clang::ForStmt* forStmt) {
    bool alreadyInLoop = insideLoop;
    if (!alreadyInLoop) insideLoop=true;
    clang::SourceManager& sm = ctxt->getSourceManager();
    if (filename == sm.getFilename(sm.getExpansionLoc(forStmt->getBeginLoc())).str() && clang::CompoundStmt::classof(forStmt->getBody())) {
        isLoopBodyAndPatched.insert(llvm::dyn_cast<clang::CompoundStmt>(forStmt->getBody()));

    }
    bool result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseForStmt(forStmt);
    if (!alreadyInLoop) insideLoop=false;
    return result;
}

bool PatchGenerator::TraverseWhileStmt(clang::WhileStmt* whileStmt) {
    bool alreadyInLoop = insideLoop;
    if (!alreadyInLoop) insideLoop=true;
    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::CharSourceRange range = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(whileStmt->getSourceRange()));
    if (filename == sm.getFilename(sm.getExpansionLoc(range.getBegin())).str() && clang::CompoundStmt::classof(whileStmt->getBody())) {
        isLoopBodyAndPatched.insert(llvm::dyn_cast<clang::CompoundStmt>(whileStmt->getBody()));
    }
    bool result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseWhileStmt(whileStmt);
    if (!alreadyInLoop) insideLoop=false;
    return result;
}

bool PatchGenerator::TraverseDoStmt(clang::DoStmt* doStmt) {
    bool alreadyInLoop = insideLoop;
    if (!alreadyInLoop) insideLoop=true;
    clang::SourceManager& sm = ctxt->getSourceManager();
    if (filename == sm.getFilename(sm.getExpansionLoc(doStmt->getBeginLoc())).str() && clang::CompoundStmt::classof(doStmt->getBody())) {
        isLoopBodyAndPatched.insert(llvm::dyn_cast<clang::CompoundStmt>(doStmt->getBody()));
    }
    bool result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseDoStmt(doStmt);
    if (!alreadyInLoop) insideLoop=false;
    return result;
}

bool PatchGenerator::TraverseSwitchStmt(clang::SwitchStmt* switchStmt) {
    clang::SourceManager& sm = ctxt->getSourceManager();
    if (filename == sm.getFilename(sm.getExpansionLoc(switchStmt->getBeginLoc())).str() && clang::CompoundStmt::classof(switchStmt->getBody())) {
        clang::CompoundStmt* body = llvm::dyn_cast<clang::CompoundStmt>(switchStmt->getBody());
        isSwitchBodyAndPatched.insert(body);
        // Remember the switch itself: its body cannot hold the setjmp arms, because everything
        // before the first `case` label is unreachable, so they are wrapped around the switch
        // statement instead (see insertSwitchScopeArms).
        switchStmtBodies[body] = switchStmt;
        if (hasEnclosingLoop()) scopeInsideLoop.insert(body);
    }
    bool result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseSwitchStmt(switchStmt);
    return result;
}

bool PatchGenerator::TraverseCaseStmt(clang::CaseStmt *caseStmt) {
    clang::SourceManager& sm = ctxt->getSourceManager();
    if (filename == sm.getFilename(sm.getExpansionLoc(caseStmt->getBeginLoc())).str() &&
            clang::CompoundStmt::classof(caseStmt->getSubStmt())) {
        clang::CompoundStmt* body = llvm::dyn_cast<clang::CompoundStmt>(caseStmt->getSubStmt());
        isSwitchBodyAndPatched.insert(body);
        // A braced case body is reachable, so its arms stay inside it; it still needs to know
        // whether a `continue;` is available there.
        if (hasEnclosingLoop()) scopeInsideLoop.insert(body);
    }
    bool result = clang::RecursiveASTVisitor<PatchGenerator>::TraverseCaseStmt(caseStmt);
    return result;
}

/*
    Whether a loop encloses the statement currently being traversed.

    Read off stmtStack rather than the insideLoop flag, so that a lambda body inside a loop does
    not count: a `continue;` there would not compile.
*/
bool PatchGenerator::hasEnclosingLoop() {
    for (size_t i = stmtStack.size(); i-- > 0;) {
        clang::Stmt* stmt = stmtStack[i];
        if (stmt == nullptr) continue;
        if (clang::ForStmt::classof(stmt) || clang::WhileStmt::classof(stmt) ||
                clang::DoStmt::classof(stmt) || clang::CXXForRangeStmt::classof(stmt)) {
            return true;
        }
        if (clang::LambdaExpr::classof(stmt)) {
            return false; // a continue cannot leave a lambda body
        }
    }
    return false;
}

/*
    jmp id of the innermost loop/switch body that encloses (or is) the statement being traversed.

    The statements of a scope longjmp through that scope's buffers, so this is what jmpIDs maps a
    line to. Returns false when no loop or switch encloses the statement, in which case there is
    no scope to continue or break out of and no id to record.
*/
bool PatchGenerator::findEnclosingScopeID(uint64_t& scopeID) {
    for (size_t i = stmtStack.size(); i-- > 0;) {
        clang::CompoundStmt* compound = llvm::dyn_cast_or_null<clang::CompoundStmt>(stmtStack[i]);
        if (compound == nullptr) continue;
        auto it = compoundScopeIDs.find(compound);
        if (it != compoundScopeIDs.end()) {
            scopeID = it->second;
            return true;
        }
    }
    return false;
}

bool PatchGenerator::VisitRecordDecl(clang::RecordDecl* recordDecl) {
    // Record the struct field info
    std::string structName = recordDecl->getNameAsString();
    if (recordDecl->isThisDeclarationADefinition()) {
        structInfo.addStructFieldInfo(ctxt, recordDecl);
        // Records the struct itself and, recursively, the type of every field
        if (recordDecl->getTypeForDecl() != nullptr) {
            typeInfo.addType(ctxt, clang::QualType(recordDecl->getTypeForDecl(), 0));
        }
    }

    return true;
}

bool PatchGenerator::VisitFunctionDecl(clang::FunctionDecl *functionDecl) {
    // Record the return/parameter types of every function
    typeInfo.addType(ctxt, functionDecl->getReturnType());
    // Parameters are local variables of the function, but are not traversed by TraverseVarDecl()
    clang::SourceManager& sm = ctxt->getSourceManager();
    bool inMainFile = sm.getFileID(sm.getExpansionLoc(functionDecl->getBeginLoc())) == sm.getMainFileID();
    for (clang::ParmVarDecl* paramDecl : functionDecl->parameters()) {
        typeInfo.addType(ctxt, paramDecl->getType());
        if (inMainFile) {
            varInfo.addVariable(functionDecl->getNameAsString(), paramDecl);
        }
    }

    // Find helper functions
    if (isCXX(filename)){
        if (functionDecl->getNameAsString()=="__metapro_env_to_int_cxx") {
            envToIntFunction=functionDecl;
        }
        else if (functionDecl->getNameAsString()==METAPROGRAM_CXX_MARKER) {
            markerFunction=functionDecl;
        }
    }
    else{
        if (functionDecl->getNameAsString()=="__metapro_env_to_int_c") {
            envToIntFunction=functionDecl;
        }
        else if (functionDecl->getNameAsString()==METAPROGRAM_C_MARKER) {
            markerFunction=functionDecl;
        }
    }

    if (markerFunction!=nullptr) {
        std::vector<clang::Expr*> emptyVector;
        emptyVector.clear();
        clang::DeclRefExpr* markerRefExpr=clang::DeclRefExpr::Create(*ctxt,clang::NestedNameSpecifierLoc(),clang::SourceLocation(),
                                            markerFunction,false,clang::SourceLocation(),markerFunction->getType(),clang::ExprValueKind::VK_LValue);
        markerCall=clang::CallExpr::Create(*ctxt,markerRefExpr,emptyVector,ctxt->VoidTy,CLANG_VALUE_KIND_RVALUE,clang::SourceLocation(),
                        clang::FPOptionsOverride());
    }
    return true;
}

bool PatchGenerator::VisitTypedefDecl(clang::TypedefDecl* typedefDecl) {
    // Record the typedef under its own name, together with its underlying type
    typeInfo.addType(ctxt, ctxt->getTypedefType(typedefDecl));

    if (isCXX(filename)){
        if (typedefDecl->getNameAsString()==METAPROGRAM_CXX_INT_FUNC_PTR_TYPE) {
            intFuncPtrType=typedefDecl;
        }
        else if (typedefDecl->getNameAsString()==METAPROGRAM_CXX_UINT_FUNC_PTR_TYPE) {
            uintFuncPtrType=typedefDecl;
        }
        else if (typedefDecl->getNameAsString()==METAPROGRAM_CXX_VOID_FUNC_PTR_TYPE) {
            voidFuncPtrType=typedefDecl;
        }
    }
    else{
        if (typedefDecl->getNameAsString()==METAPROGRAM_C_INT_FUNC_PTR_TYPE) {
            intFuncPtrType=typedefDecl;
        }
        else if (typedefDecl->getNameAsString()==METAPROGRAM_C_UINT_FUNC_PTR_TYPE) {
            uintFuncPtrType=typedefDecl;
        }
        else if (typedefDecl->getNameAsString()==METAPROGRAM_C_VOID_FUNC_PTR_TYPE) {
            voidFuncPtrType=typedefDecl;
        }
    }
    return true;
}

clang::ConditionalOperator* PatchGenerator::genCallOrigFuncOrPatch(clang::Expr* origExpr, uint64_t majorId, uint64_t minorId,
                clang::Expr* newExpr) {
    clang::StringLiteral* majorIdLiteral=clang::StringLiteral::Create(*ctxt, "METAPRO_PATCH_MAJOR_ID",
                    CLANG_STRING_KIND_ORDINARY, false, ctxt->CharTy, clang::SourceLocation());
    clang::StringLiteral* minorIdLiteral=clang::StringLiteral::Create(*ctxt, "METAPRO_PATCH_MINOR_ID",
                    CLANG_STRING_KIND_ORDINARY, false, ctxt->CharTy, clang::SourceLocation());

    clang::DeclRefExpr* majorIdRef=new(*ctxt) clang::DeclRefExpr(*ctxt,envToIntFunction,false,ctxt->IntTy,
                    CLANG_VALUE_KIND_RVALUE,clang::SourceLocation());
    clang::DeclRefExpr* minorIdRef=new(*ctxt) clang::DeclRefExpr(*ctxt,envToIntFunction,false,ctxt->IntTy,
                    CLANG_VALUE_KIND_RVALUE,clang::SourceLocation());

    std::vector<clang::Expr*> majorIdargs;
    majorIdargs.push_back(majorIdLiteral);
    clang::CallExpr* majorIdCall=clang::CallExpr::Create(*ctxt,majorIdRef,majorIdargs,ctxt->IntTy,CLANG_VALUE_KIND_RVALUE,
                    clang::SourceLocation(),clang::FPOptionsOverride());

    std::vector<clang::Expr*> minorIdargs;
    minorIdargs.push_back(minorIdLiteral);
    clang::CallExpr* minorIdCall=clang::CallExpr::Create(*ctxt,minorIdRef,minorIdargs,ctxt->IntTy,CLANG_VALUE_KIND_RVALUE,
                    clang::SourceLocation(),clang::FPOptionsOverride());

    clang::IntegerLiteral* majorIdInt=clang::IntegerLiteral::Create(*ctxt,llvm::APInt(64,majorId),ctxt->LongLongTy,
                    clang::SourceLocation());
    clang::BinaryOperator* majorCompare=clang::BinaryOperator::Create(*ctxt,majorIdCall,majorIdInt,clang::BO_EQ,
                    ctxt->IntTy,CLANG_VALUE_KIND_RVALUE,clang::OK_Ordinary,clang::SourceLocation(),clang::FPOptionsOverride());
    clang::IntegerLiteral* minorIdInt=clang::IntegerLiteral::Create(*ctxt,llvm::APInt(64,minorId),ctxt->LongLongTy,
                    clang::SourceLocation());
    clang::BinaryOperator* minorCompare=clang::BinaryOperator::Create(*ctxt,minorIdCall,minorIdInt,clang::BO_EQ,
                    ctxt->IntTy,CLANG_VALUE_KIND_RVALUE,clang::OK_Ordinary,clang::SourceLocation(),clang::FPOptionsOverride());
    
    clang::BinaryOperator* andOp=clang::BinaryOperator::Create(*ctxt,majorCompare,minorCompare,clang::BO_LAnd,
                    ctxt->IntTy,CLANG_VALUE_KIND_RVALUE,clang::OK_Ordinary,clang::SourceLocation(),clang::FPOptionsOverride());

    return new(*ctxt) clang::ConditionalOperator(andOp,clang::SourceLocation(),newExpr,clang::SourceLocation(),origExpr,origExpr->getType(),
                    CLANG_VALUE_KIND_RVALUE,clang::ExprObjectKind::OK_Ordinary);
}

bool PatchGenerator::containMacro(clang::Stmt* stmt) {
    clang::CharSourceRange charRange=clang::Lexer::getAsCharRange(stmt->getSourceRange(),
                    ctxt->getSourceManager(),ctxt->getLangOpts());
    std::string condText=clang::Lexer::getSourceText(charRange,ctxt->getSourceManager(),ctxt->getLangOpts()).str();
    for (clang::Preprocessor::macro_iterator it=preprocessor.macro_begin();it!=preprocessor.macro_end();it++) {
        if (preprocessor.getMacroInfo(it->first)) {
            if (!preprocessor.getMacroInfo(it->first)->isFunctionLike()) continue;
            if (condText.find(it->first->getName().str())!=std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

bool CondExprAssignChecker::VisitBinaryOperator(clang::BinaryOperator* binaryOperator) {
    if (binaryOperator->isAssignmentOp() || binaryOperator->isCompoundAssignmentOp() || binaryOperator->isShiftAssignOp()) {
        foundAssignInCond = true;
        return false; // Stop traversal
    }
    return true;
}