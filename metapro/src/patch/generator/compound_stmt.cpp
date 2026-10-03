#include "patch/patch_generator.h"
#include "utils/string.h"
#include "utils/path.h"
#include "config/config.h"
#include "patch/patch.h"
#include "patch/finders.h"
#include "config/clang_macro.h"

#include "clang/AST/AST.h"
#include "clang/AST/NestedNameSpecifier.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "spdlog/spdlog.h"
#include <fstream>
#include <cstring>
#include <iostream>
#include <string>

clang::SourceLocation getIncludeChain(clang::SourceManager &SM, clang::SourceLocation loc) {
    clang::FileID fileID = SM.getFileID(loc);
    clang::SourceLocation includeLoc = loc;
    clang::SourceLocation prevLoc = loc;
    
    while (fileID.isValid()) {
        prevLoc = includeLoc;
        includeLoc = SM.getIncludeLoc(fileID);
        if (includeLoc.isInvalid()) break;  // reached the top-level source file
        fileID = SM.getFileID(includeLoc);
    }
    return prevLoc;
}

/*
    Arm the continue/break jmp_bufs of a switch scope around the switch statement:

        { if (setjmp(__metapro_break_jmp_bufs[id])) goto <end>;      // break leaves the switch
          if (setjmp(__metapro_continue_jmp_bufs[id])) continue;     // continue is the loop's
          switch (...) { ... }
          <end>: ; }

    They cannot sit at the top of the switch body, where the rest of the loop/switch bookkeeping
    goes: a statement before the first `case` label of a switch is unreachable, so the setjmp never
    runs and a longjmp from an inserted patch lands in a buffer that was never armed.

    The wrapping braces keep this valid where the switch is the single statement of an `if`, `else`,
    loop or `case` label, and the label after the switch is where a `break` has to land. The
    continue arm is only emitted when a loop encloses the switch, since a bare `continue;` would
    not compile otherwise; C gives it the enclosing loop, which is exactly what a `continue` inside
    a switch means. Both arms are re-armed every time the switch is reached.

    A switch that a macro wrote has no source range of its own to wrap, so it is left unarmed
    rather than rewriting the macro invocation.
*/
void PatchGenerator::insertSwitchScopeArms(clang::SwitchStmt* switchStmt, clang::CompoundStmt* body,
                                           uint64_t scopeID) {
    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::SourceLocation beginLoc = switchStmt->getBeginLoc();
    clang::SourceLocation lastTokenLoc = switchStmt->getEndLoc();
    if (beginLoc.isInvalid() || lastTokenLoc.isInvalid() ||
            beginLoc.isMacroID() || lastTokenLoc.isMacroID()) {
        return;
    }
    clang::SourceLocation endLoc = clang::Lexer::getLocForEndOfToken(lastTokenLoc, 0, sm,
                                                                     ctxt->getLangOpts());
    if (endLoc.isInvalid()) {
        return;
    }

    std::string label = "__metapro_switch_end_" + std::to_string(scopeID);
    std::string beforeCode = "{ if (setjmp(__metapro_break_jmp_bufs[" + std::to_string(scopeID) +
                             "])) goto " + label + "; ";
    if (scopeInsideLoop.find(body) != scopeInsideLoop.end()) {
        beforeCode += "if (setjmp(__metapro_continue_jmp_bufs[" + std::to_string(scopeID) +
                      "])) continue; ";
    }
    std::string afterCode = " " + label + ": ; }";

    std::string switchString = stmtToString(ctxt, switchStmt);
    patches.push_back(new InsertPatch(ctxt, switchString, code, 0, beforeCode, beginLoc,
                                      sm.getExpansionLineNumber(beginLoc)));
    patches.push_back(new InsertPatch(ctxt, switchString, code, 0, afterCode, endLoc,
                                      sm.getExpansionLineNumber(endLoc)));
}

bool PatchGenerator::VisitCompoundStmt(clang::CompoundStmt *compoundStmt) {
    clang::SourceManager& sm = ctxt->getSourceManager();

    clang::Stmt* first = nullptr;
    clang::Stmt* first_stmt = *(compoundStmt->body_begin());
    clang::Stmt* last_stmt = *(compoundStmt->body_rbegin());
    std::string varTableInitCode = "";
    std::string varTableInsertFunction;
    if (sm.getFileID(sm.getSpellingLoc(compoundStmt->getLBracLoc())) != sm.getMainFileID() || compoundStmt->size() == 0) {
        return true;
    }
    // Skip if the function body is produced by a macro expansion (e.g. DEF_CMATH_METHOD(exp)).
    // isMacroID() must be checked on the raw location before getSpellingLoc() resolves it
    // to a plain file position, which always has isMacroID() == false.
    if (compoundStmt->getLBracLoc().isMacroID()) {
        return true;
    }

    LabelFinder labelFinder;
    labelFinder.TraverseDecl(curFuncDecl);
    for (std::string label : labelFinder.labels) {
        if (label == "L_INT_OVERFLOW") continue; // Terrible label in mruby
        varTableInitCode += "__metapro_add_goto(\"__metapro_" + curFuncDecl->getNameAsString() + "_" + label + "\"); ";
        varTableInitCode += "if (setjmp(__metapro_goto_jmps[__metapro_find_goto_jmp(\"__metapro_" +
                            curFuncDecl->getNameAsString() + "_" + label + "\")])) ";
        varTableInitCode += "goto " + label + "; ";
    }
    if (curFuncDecl->getReturnType()->isSignedIntegerOrEnumerationType() || curFuncDecl->getReturnType()->isVoidType() ||
            curFuncDecl->getReturnType()->isUnsignedIntegerType() || curFuncDecl->getReturnType()->isPointerType()) {
        varTableInitCode += "__metapro_add_return(\"" + curFuncDecl->getNameAsString() + "\"); ";
        varTableInitCode += "unsigned int __metapro_return_id; if (__metapro_return_id = (unsigned int)setjmp(__metapro_find_return_label(\"";
        varTableInitCode += curFuncDecl->getNameAsString() + "\")->jmpbuf)) ";
        if (curFuncDecl->getReturnType()->isSignedIntegerOrEnumerationType()) {
            if (isCXX(origFilename))
                varTableInitCode += "return __metapro_get_int_var_cxx(";
            else
                varTableInitCode += "return __metapro_get_int_var_c(";
            varTableInitCode += "__metapro_return_id, \"" + curFuncDecl->getNameAsString() + "\"); ";
        }
        else if (curFuncDecl->getReturnType()->isUnsignedIntegerType()) {
            if (isCXX(origFilename))
                varTableInitCode += "return __metapro_get_uint_var_cxx(";
            else
                varTableInitCode += "return __metapro_get_uint_var_c(";
            varTableInitCode += "__metapro_return_id, \"" + curFuncDecl->getNameAsString() + "\"); ";
        }
        else if (curFuncDecl->getReturnType()->isPointerType()) {
            if (isCXX(origFilename))
                varTableInitCode += "return __metapro_get_ptr_var_cxx(";
            else
                varTableInitCode += "return __metapro_get_ptr_var_c(";
            varTableInitCode += "__metapro_return_id, \"" + curFuncDecl->getNameAsString() + "\"); ";
        }
        else {
            // void
            varTableInitCode += "return; ";
        }
    }
    

    if (isCXX(filename)) {
        varTableInsertFunction = "__metapro_table_insert_var_cxx";
    }
    else {
        varTableInsertFunction = "__metapro_table_insert_var_c";
    }
    if (curFuncDecl != nullptr) {
        clang::Stmt* bodyStmt = curFuncDecl->getBody();
        clang::CompoundStmt* compoundBody = llvm::dyn_cast<clang::CompoundStmt>(bodyStmt);
        first = *compoundBody->body_begin();
        if (bodyStmt == compoundStmt) {
            // This is the function body, insert variable table init code here
            clang::SourceLocation firstLoc = first->getBeginLoc();
            clang::SourceManager& sm = ctxt->getSourceManager();
            std::vector<clang::VarDecl*> curIntVars;
            std::vector<clang::VarDecl*> curUIntVars;
            std::vector<clang::VarDecl*> curDoubleVars;
            std::vector<clang::VarDecl*> curPtrVars;
            std::vector<clang::VarDecl*> curStructVars;
            std::vector<clang::VarDecl*> curStructPtrVars;
            std::vector<clang::VarDecl*> curArrayVars;
            // Global variables holding a function, grouped by what that function returns. They are not
            // variables to the interpreter but callees, so they are registered on their own (see
            // genFuncPtrRegister); only globals belong here, a parameter holding a function is local.
            std::vector<clang::VarDecl*> curVoidFuncPtrVars;
            std::vector<clang::VarDecl*> curIntFuncPtrVars;
            std::vector<clang::VarDecl*> curUIntFuncPtrVars;
            std::vector<clang::VarDecl*> curPtrFuncPtrVars;

            // Global variables
            for (clang::VarDecl* var:intVars) {
                clang::SourceLocation varLoc = getIncludeChain(sm, sm.getSpellingLoc(var->getBeginLoc()));
                if (sm.getFilename(sm.getExpansionLoc(var->getBeginLoc())).str() == filename &&
                    sm.getExpansionLineNumber(var->getBeginLoc()) > sm.getExpansionLineNumber(firstLoc)) {
                    // If the global var is declared after the target location in the same file, skip
                    continue;
                }
                if (sm.getExpansionLineNumber(varLoc)<=sm.getExpansionLineNumber(firstLoc))
                    curIntVars.push_back(var);
            }
            for (clang::VarDecl* var:uintVars) {
                clang::SourceLocation varLoc = getIncludeChain(sm, sm.getSpellingLoc(var->getBeginLoc()));
                if (sm.getFilename(sm.getExpansionLoc(var->getBeginLoc())).str() == filename &&
                    sm.getExpansionLineNumber(var->getBeginLoc()) > sm.getExpansionLineNumber(firstLoc)) {
                    // If the global var is declared after the target location in the same file, skip
                    continue;
                }
                if (sm.getExpansionLineNumber(varLoc)<=sm.getExpansionLineNumber(firstLoc))
                    curUIntVars.push_back(var);
            }
            for (clang::VarDecl* var:doubleVars) {
                clang::SourceLocation varLoc = getIncludeChain(sm, sm.getSpellingLoc(var->getBeginLoc()));
                if (sm.getFilename(sm.getExpansionLoc(var->getBeginLoc())).str() == filename &&
                    sm.getExpansionLineNumber(var->getBeginLoc()) > sm.getExpansionLineNumber(firstLoc)) {
                    // If the global var is declared after the target location in the same file, skip
                    continue;
                }
                if (sm.getExpansionLineNumber(varLoc)<=sm.getExpansionLineNumber(firstLoc))
                    curDoubleVars.push_back(var);
            }
            for (clang::VarDecl* var:ptrVars) {
                clang::SourceLocation varLoc = getIncludeChain(sm, sm.getSpellingLoc(var->getBeginLoc()));
                if (sm.getFilename(sm.getExpansionLoc(var->getBeginLoc())).str() == filename &&
                    sm.getExpansionLineNumber(var->getBeginLoc()) > sm.getExpansionLineNumber(firstLoc)) {
                    // If the global var is declared after the target location in the same file, skip
                    continue;
                }
                if (sm.getExpansionLineNumber(varLoc)>sm.getExpansionLineNumber(firstLoc)) continue;
                if (var->getType()->isFunctionPointerType()) {
                    // A variable holding a function: registered as a callee, by what it returns
                    clang::QualType returnType = getFuncPtrReturnType(var->getType());
                    if (returnType.isNull()) continue;
                    if (returnType->isSignedIntegerOrEnumerationType())
                        curIntFuncPtrVars.push_back(var);
                    else if (returnType->isUnsignedIntegerType())
                        curUIntFuncPtrVars.push_back(var);
                    else if (returnType->isPointerType())
                        curPtrFuncPtrVars.push_back(var);
                    else if (returnType->isVoidType())
                        curVoidFuncPtrVars.push_back(var);
                    // Anything else (a float, a record) is a return the interpreter cannot hand back
                    continue;
                }
                curPtrVars.push_back(var);
            }
            for (clang::VarDecl* var:structVars) {
                clang::SourceLocation varLoc = getIncludeChain(sm, sm.getSpellingLoc(var->getBeginLoc()));
                if (sm.getFilename(sm.getExpansionLoc(var->getBeginLoc())).str() == filename &&
                    sm.getExpansionLineNumber(var->getBeginLoc()) > sm.getExpansionLineNumber(firstLoc)) {
                    // If the global var is declared after the target location in the same file, skip
                    continue;
                }
                if (sm.getExpansionLineNumber(varLoc)<=sm.getExpansionLineNumber(firstLoc))
                    curStructVars.push_back(var);
            }
            for (clang::VarDecl* var:structPtrVars) {
                clang::SourceLocation varLoc = getIncludeChain(sm, sm.getSpellingLoc(var->getBeginLoc()));
                if (sm.getFilename(sm.getExpansionLoc(var->getBeginLoc())).str() == filename &&
                    sm.getExpansionLineNumber(var->getBeginLoc()) > sm.getExpansionLineNumber(firstLoc)) {
                    // If the global var is declared after the target location in the same file, skip
                    continue;
                }
                if (sm.getExpansionLineNumber(varLoc)<=sm.getExpansionLineNumber(firstLoc))
                    curStructPtrVars.push_back(var);
            }
            for (clang::VarDecl* var:arrayVars) {
                /*
                    Only the arrays of this file. One that a header declares is there in the
                    configuration this file was parsed in, but a build may compile the same file again
                    under another: mruby declares its presym tables in a header it includes inside
                    `#ifndef MRB_NO_PRESYM`, and the pass building `mrbc` -- which runs before the
                    tables are generated -- has neither, so a registration naming them does not compile.
                    A patch takes its ingredients from the file it is written in anyway.
                */
                if (sm.getFilename(sm.getExpansionLoc(var->getBeginLoc())).str() != filename) continue;
                if (sm.getExpansionLineNumber(var->getBeginLoc()) > sm.getExpansionLineNumber(firstLoc)) {
                    // Declared after the function: not in scope there
                    continue;
                }
                curArrayVars.push_back(var);
            }

            // Function parameters
            for (clang::ParmVarDecl* param:curFuncDecl->parameters()) {
                if (param->getType()->isSignedIntegerOrEnumerationType()) {
                    curIntVars.push_back(param);
                } else if (param->getType()->isUnsignedIntegerType()) {
                    curUIntVars.push_back(param);
                } else if (param->getType()->isFloatingType()) {
                    curDoubleVars.push_back(param);
                } else if (param->getType()->isPointerType()) {
                    clang::QualType pointeeType = param->getType()->getPointeeType();
                    if (pointeeType->isStructureOrClassType()) {
                        curStructPtrVars.push_back(param);
                    } else {
                        curPtrVars.push_back(param);
                    }
                } else if (param->getType()->isStructureOrClassType()) {
                    curStructVars.push_back(param);
                }
            }

            // Init current function in variable table
            if (isCXX(filename))
                varTableInitCode += "__metapro_func_var_init_cxx(\"";
            else
                varTableInitCode += "__metapro_func_var_init_c(\"";
            varTableInitCode += curFuncDecl->getNameAsString() + "\"); ";

            /*
                A function a patch expression calls is resolved by name at run time, from
                function-info.json, so nothing is registered here: the meta-program does not take the
                address of any function, and this no longer runs once per entry to the function.

                A global variable *holding* a function is not in that file and has no symbol of its own,
                so it is the one callee the runtime cannot resolve by name. Those are handed over here.
            */
            varTableInitCode += genFuncPtrRegister(curVoidFuncPtrVars, curIntFuncPtrVars,
                                                   curUIntFuncPtrVars, curPtrFuncPtrVars);

            // Insert Global variable registers
            for (clang::VarDecl* var:curIntVars) {
                if (var->getStorageClass() == clang::SC_Register) continue;
                if (var->getNameAsString() == "pcre2_dfa_match_") continue; // PHP blacklist
                varTableInitCode += genVarTableInsert(varTableInsertFunction, var);
            }
            for (clang::VarDecl* var:curUIntVars) {
                if (var->getStorageClass() == clang::SC_Register) continue;
                varTableInitCode += genVarTableInsert(varTableInsertFunction, var);
            }
            for (clang::VarDecl* var:curDoubleVars) {
                if (var->getStorageClass() == clang::SC_Register) continue;
                varTableInitCode += genVarTableInsert(varTableInsertFunction, var);
            }
            for (clang::VarDecl* var:curPtrVars) {
                if (var->getStorageClass() == clang::SC_Register) continue;
                // A parameter holding a function: a global one was taken out above and registered as a
                // callee, and a local one cannot be, because the table outlives the call
                if (var->getType()->isFunctionPointerType()) continue;
                varTableInitCode += genVarTableInsert(varTableInsertFunction, var);
            }
            for (clang::VarDecl* var:curStructVars) {
                if (var->getStorageClass() == clang::SC_Register) continue;
                if (var->getType()->isIncompleteType()) continue; // Skip incomplete types
                varTableInitCode += genVarTableInsert(varTableInsertFunction, var);
            }
            for (clang::VarDecl* var:curStructPtrVars) {
                if (var->getStorageClass() == clang::SC_Register) continue;
                varTableInitCode += genVarTableInsert(varTableInsertFunction, var);
            }
            for (clang::VarDecl* var:curArrayVars) {
                // `extern int a[];` has no size to register, and no elements of its own to reach
                if (var->getType()->isIncompleteArrayType() || var->getType()->isIncompleteType()) continue;
                varTableInitCode += genVarTableInsert(varTableInsertFunction, var);
            }
            // For debugging: remove in actual use
            // if (isCXX(filename))
            //     varTableInitCode += "__metapro_print_var_table_cxx(\"" + curFuncDecl->getNameAsString() + "\"); ";
            // else
            //     varTableInitCode += "__metapro_print_var_table_c(\"" + curFuncDecl->getNameAsString() + "\"); ";
        }
    }

    std::vector<clang::VarDecl*> localVars; // Store all local variables in this compound to delete from hashtable when leaving scope
    clang::Stmt* firstBody = *compoundStmt->body_begin();
    for (clang::CompoundStmt::body_iterator it=compoundStmt->body_begin();it!=compoundStmt->body_end();it++) {
        clang::Stmt* body=*it;
        if (compoundStmt->size() > 1 && clang::NullStmt::classof(body)) continue; // Skip null statement which may be generated by macros and cause problem for line number checking
        clang::CharSourceRange bodyRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(body->getSourceRange()));
        clang::SourceLocation startLoc = bodyRange.getBegin();
        clang::SourceLocation endLoc = clang::Lexer::getLocForEndOfToken(bodyRange.getEnd(), 0, sm, ctxt->getLangOpts());
        auto nextTok = clang::Lexer::findNextToken(bodyRange.getEnd(), sm, ctxt->getLangOpts());
        if (nextTok.hasValue() && nextTok->is(clang::tok::semi)) {
            endLoc = clang::Lexer::getLocForEndOfToken(nextTok->getLocation(), 0, sm, ctxt->getLangOpts());
        }
        size_t cur_line=sm.getExpansionLineNumber(startLoc);
        bool suspicious=false;

        // Insert setjmp code for loop/switch body
        std::string setjmpCode = "";
        if (body == first_stmt && isLoopBodyAndPatched.find(compoundStmt) != isLoopBodyAndPatched.end()) {
            uint64_t scopeID = PatchGenerator::loopID++;
            compoundScopeIDs[compoundStmt] = scopeID;
            setjmpCode += "if (setjmp(__metapro_continue_jmp_bufs[" + std::to_string(scopeID) + "])) continue; ";
            setjmpCode += "if (setjmp(__metapro_break_jmp_bufs[" + std::to_string(scopeID) + "])) break; ";
        }
        else if (body == first_stmt && isSwitchBodyAndPatched.find(compoundStmt) != isSwitchBodyAndPatched.end()) {
            uint64_t scopeID = PatchGenerator::loopID++;
            compoundScopeIDs[compoundStmt] = scopeID;
            auto switchIt = switchStmtBodies.find(compoundStmt);
            if (switchIt == switchStmtBodies.end()) {
                // A braced `case`/`default` body. This block is reachable and a `break` in it
                // leaves the switch, so both arms belong here.
                setjmpCode += "if (setjmp(__metapro_break_jmp_bufs[" + std::to_string(scopeID) + "])) break; ";
                if (scopeInsideLoop.find(compoundStmt) != scopeInsideLoop.end()) {
                    setjmpCode += "if (setjmp(__metapro_continue_jmp_bufs[" + std::to_string(scopeID) + "])) continue; ";
                }
            }
            else {
                // The switch's own body: statements before its first `case` label are unreachable,
                // so the arms are wrapped around the switch statement instead.
                insertSwitchScopeArms(switchIt->second, compoundStmt, scopeID);
            }
        }

        // Instrumentation to track local variables
        std::string insertVarInfoCode = "";
        if (clang::DeclStmt::classof(body)) {
            clang::DeclStmt* declStmt = llvm::dyn_cast<clang::DeclStmt>(body);
            for (clang::DeclStmt::decl_iterator declIt=declStmt->decl_begin(); declIt!=declStmt->decl_end(); declIt++) {
                if (clang::VarDecl::classof(*declIt)) {
                    clang::VarDecl* varDecl = llvm::dyn_cast<clang::VarDecl>(*declIt);
                    if (varDecl->isLocalVarDecl() && varDecl->getStorageClass() != clang::SC_Register) {
                        if (varDecl->getType()->isFunctionPointerType()) continue; // Skip function pointers
                        localVars.push_back(varDecl);
                        insertVarInfoCode += genVarTableInsert(varTableInsertFunction, varDecl);
                    }
                }
            }
        }

        if (first != nullptr && body == first) {
            // First stmt not patched, but need to insert var table init code
            InsertPatch* insertPatch=new InsertPatch(ctxt,stmtToString(ctxt,body),code,0,
                        varTableInitCode + setjmpCode,startLoc,cur_line);
            patches.push_back(insertPatch);
        }
        else if (firstBody != nullptr && body == firstBody && setjmpCode != "") {
                // First stmt in this compound not patched, but need to insert setjmp code for loop/switch
            InsertPatch* insertPatch=new InsertPatch(ctxt,stmtToString(ctxt,body),code,0,
                        setjmpCode,startLoc,cur_line);
            patches.push_back(insertPatch);
        }
        if (insertVarInfoCode!="") {
            // Insert variable info code for local variables at LAST in this stmt
            InsertPatch* insertPatch=new InsertPatch(ctxt,stmtToString(ctxt,body),code,0,
                        insertVarInfoCode,endLoc,cur_line, "", true);
            patches.push_back(insertPatch);
        }

        // Map every line of this statement to the innermost loop/switch scope it sits in, so that a
        // patch anywhere inside it longjmps through that scope's buffers. Whole line spans are
        // covered rather than only the statement's first line: a statement can span several lines,
        // and the first statement after a `case` label is nested in the label statement, so its own
        // line would otherwise get no entry at all and the patcher would fall back to a placeholder.
        uint64_t enclosingScopeID = 0;
        if (endLoc.isValid() && findEnclosingScopeID(enclosingScopeID)) {
            size_t lastLine = sm.getExpansionLineNumber(endLoc);
            for (size_t line = cur_line; line <= lastLine; line++) {
                jmpIDs[line] = enclosingScopeID;
            }
        }
        continue;
        // TODO: Remove patch apply

        uint32_t startOffset=sm.getFileOffset(sm.getExpansionLoc(startLoc));
        uint32_t endOffset=sm.getFileOffset(sm.getExpansionLoc(endLoc));


        // Get all candidate variables
        LocalDeclFinder declFinder(ctxt,body);
        declFinder.TraverseDecl(curFuncDecl);
        std::vector<clang::VarDecl*> curIntVars;
        std::vector<clang::VarDecl*> curUIntVars;
        std::vector<clang::VarDecl*> curDoubleVars;
        std::vector<clang::VarDecl*> curPtrVars;
        std::vector<clang::VarDecl*> curIntPtrVars;
        std::vector<clang::VarDecl*> curUIntPtrVars;
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
        for (clang::VarDecl* var:declFinder.getIntPtrVars()) curIntPtrVars.push_back(var);
        for (clang::VarDecl* var:declFinder.getUIntPtrVars()) curUIntPtrVars.push_back(var);

        std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> intFields=declFinder.getIntFields();
        std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> uintFields=declFinder.getUIntFields();
        std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> doubleFields=declFinder.getDoubleFields();
        std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> ptrFields=declFinder.getPtrFields();

        unsigned int int_var_size=curIntVars.size()+intFields.size();
        unsigned int uint_var_size=curUIntVars.size()+uintFields.size();
        unsigned int double_var_size=curDoubleVars.size()+doubleFields.size();
        unsigned int ptr_var_size=curPtrVars.size()+ptrFields.size();
        
        clang::QualType int64PtrArrayType=ctxt->getIncompleteArrayType(ctxt->getPointerType(ctxt->LongLongTy),clang::ArrayType::Normal,0);
        clang::QualType uint64PtrArrayType=ctxt->getIncompleteArrayType(ctxt->getPointerType(ctxt->UnsignedLongLongTy),clang::ArrayType::Normal,0);
        clang::QualType doublePtrArrayType=ctxt->getIncompleteArrayType(ctxt->getPointerType(ctxt->LongDoubleTy),clang::ArrayType::Normal,0);
        clang::QualType ptrPtrArrayType=ctxt->getIncompleteArrayType(ctxt->getPointerType(ctxt->VoidPtrTy),clang::ArrayType::Normal,0);
        clang::QualType intPtrPtrArrayType=ctxt->getIncompleteArrayType(ctxt->getPointerType(ctxt->getPointerType(ctxt->LongLongTy)),
                            clang::ArrayType::Normal,0);
        clang::QualType uintPtrPtrArrayType=ctxt->getIncompleteArrayType(ctxt->getPointerType(ctxt->getPointerType(ctxt->UnsignedLongLongTy)),
                            clang::ArrayType::Normal,0);

        // Make var info
#if 0
        std::vector<VariablePatch::VariableInfo> intInfoList;
        for (clang::VarDecl* var:curIntVars) {
            intInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(), ctxt->getTypeSize(var->getType())));
        }
        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:intFields) {
            intInfoList.push_back(VariablePatch::VariableInfo(field.second, ctxt->getTypeSize(field.first.second->getType())));
        }
        std::vector<VariablePatch::VariableInfo> uintInfoList;
        for (clang::VarDecl* var:curUIntVars) {
            uintInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(), ctxt->getTypeSize(var->getType())));
        }
        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:uintFields) {
            uintInfoList.push_back(VariablePatch::VariableInfo(field.second, ctxt->getTypeSize(field.first.second->getType())));
        }
        std::vector<VariablePatch::VariableInfo> doubleInfoList;
        for (clang::VarDecl* var:curDoubleVars) {
            doubleInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(), ctxt->getTypeSize(var->getType())));
        }
        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:doubleFields) {
            doubleInfoList.push_back(VariablePatch::VariableInfo(field.second, ctxt->getTypeSize(field.first.second->getType())));
        }
        std::vector<VariablePatch::VariableInfo> ptrInfoList;
        for (clang::VarDecl* var:curPtrVars) {
            ptrInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(), ctxt->getTypeSize(var->getType())));
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

        if (curFuncDecl && (Config::getConfig().noTemplates.find("INSERT_EXPR")==Config::getConfig().noTemplates.end() ||
                            Config::getConfig().noTemplates.find("INSERT_NOT_NULL_CHECKER")==Config::getConfig().noTemplates.end())) {
            // EXPR
            std::string exprCallExpr="";
            if (Config::getConfig().noTemplates.find("INSERT_EXPR")==Config::getConfig().noTemplates.end()) {
                // Make new if stmt
                if (isCXX(filename))
                    exprCallExpr += "if (__metapro_new_cond_cxx(";
                else
                    exprCallExpr += "if (__metapro_new_cond_c(";
                exprCallExpr += std::to_string(Config::getConfig().patchId) + ", \"" +
                                curFuncDecl->getNameAsString() + "\")) ";
                // Make new expr call
                if (isCXX(filename))
                    exprCallExpr += "__metapro_exec_expr_cxx(";
                else
                    exprCallExpr += "__metapro_exec_expr_c(";
                exprCallExpr += std::to_string(Config::getConfig().patchId) + ", \"" + curFuncDecl->getNameAsString() +
                                "\", " + std::to_string(PatchGenerator::loopID - 1) + "); ";

                // Add instrumentation
                std::string instBeforeCode = "";
                if (first != nullptr && body == first) {
                    instBeforeCode += varTableInitCode + setjmpCode;
                }
                else if (firstBody != nullptr && body == firstBody && setjmpCode != "") {
                    instBeforeCode += setjmpCode;
                }

                // Create new patch
                std::string bodyStr = code.substr(startOffset, endOffset - startOffset + 1);
                InsertPatch* exprPatch = new InsertPatch(ctxt,bodyStr,code,Config::getConfig().patchId, exprCallExpr,startLoc, cur_line,
                            instBeforeCode + exprCallExpr);
#if 0
                exprPatch->intVars = intInfoList;
                exprPatch->uintVars = uintInfoList;
                exprPatch->doubleVars = doubleInfoList;
                exprPatch->ptrVars = ptrInfoList;
                exprPatch->intLits = intLitInfos;
                exprPatch->uintLits = uintLitInfos;
                exprPatch->floatLits = floatLitInfos;
#endif
                patches.push_back(exprPatch);
                Config::getConfig().patchId++;
            }
            else if (first != nullptr && body == first) {
                // If only insert not null checker for the first stmt, we also need to insert instrumentation code for variable tracking
                std::string instrumentationCode = "";
                if (first != nullptr && body == first) {
                    instrumentationCode += varTableInitCode + setjmpCode;
                }
                else if (firstBody != nullptr && body == firstBody && setjmpCode != "") {
                    instrumentationCode += setjmpCode;
                }
                if (instrumentationCode != "") {
                    InsertPatch* insertPatch=new InsertPatch(ctxt,stmtToString(ctxt,body),code,0,
                                instrumentationCode,startLoc,cur_line);
                    patches.push_back(insertPatch);
                }
            }

            /* INSERT_NOT_NULL_CHECKER */
            std::string notNullIfStmt="";
            if (curFuncDecl && Config::getConfig().noTemplates.find("INSERT_NOT_NULL_CHECKER")==Config::getConfig().noTemplates.end() &&
                            !(clang::DeclStmt::classof(body) || clang::LabelStmt::classof(body) || clang::NullStmt::classof(body))) {
                // Create new condition for new if stmt
                notNullIfStmt = "if (__metapro_new_not_null_check_c(" + std::to_string(Config::getConfig().patchId) +
                                ", \"" + curFuncDecl->getNameAsString() + "\"))";

                // Create new patch
                std::string bodyStr = code.substr(startOffset, endOffset - startOffset + 1);
                InsertNotNullChecker* notNullCheckPatch = new InsertNotNullChecker(ctxt,bodyStr,notNullIfStmt,Config::getConfig().patchId,
                            code, cur_line, startLoc);
#if 0
                notNullCheckPatch->intVars = intInfoList;
                notNullCheckPatch->uintVars = uintInfoList;
                notNullCheckPatch->doubleVars = doubleInfoList;
                notNullCheckPatch->ptrVars = ptrInfoList;
                notNullCheckPatch->intLits = intLitInfos;
                notNullCheckPatch->uintLits = uintLitInfos;
                notNullCheckPatch->floatLits = floatLitInfos;
#endif
                patches.push_back(notNullCheckPatch);
                Config::getConfig().patchId++;
            }
        }
        else if (first != nullptr && body == first) {
            // First stmt not patched, but need to insert var table init code and setjmp code
            std::string instrumentationCode = varTableInitCode + setjmpCode;
            InsertPatch* insertPatch=new InsertPatch(ctxt,stmtToString(ctxt,body),code,0,
                        instrumentationCode,startLoc,cur_line);
            patches.push_back(insertPatch);
        }
        else if (firstBody != nullptr && body == firstBody && setjmpCode != "") {
            // First stmt in this compound not patched, but need to insert setjmp code for loop/switch
            InsertPatch* insertPatch=new InsertPatch(ctxt,stmtToString(ctxt,body),code,0,
                        setjmpCode,startLoc,cur_line);
            patches.push_back(insertPatch);
        }

        std::string instAfterCode = insertVarInfoCode;
        if (instAfterCode!="") {
            InsertPatch* insertPatch=new InsertPatch(ctxt,stmtToString(ctxt,body),code,0,
                        instAfterCode,endLoc,cur_line, "", true);
            patches.push_back(insertPatch);
        }
    }

    if (compoundStmt->size()==0) return true;

    if (clang::NullStmt::classof(last_stmt)) return true; // Skip null statement which may be generated by macros and cause problem for line number checking
    if (clang::ReturnStmt::classof(last_stmt)) return true; // Avoid inserting dead code
    clang::CharSourceRange bodyRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(last_stmt->getSourceRange()));
    clang::SourceLocation startLoc = bodyRange.getBegin();
    clang::SourceLocation endLoc = clang::Lexer::getLocForEndOfToken(bodyRange.getEnd(), 0, sm, ctxt->getLangOpts());
    auto nextTok = clang::Lexer::findNextToken(bodyRange.getEnd(), sm, ctxt->getLangOpts());
    if (nextTok.hasValue() && nextTok->is(clang::tok::semi)) {
        endLoc = clang::Lexer::getLocForEndOfToken(nextTok->getLocation(), 0, sm, ctxt->getLangOpts());
    }

    bool suspicious=false;
    for (unsigned int line:suspiciousLines) {
        size_t declLines=1;
        if (sm.getFileID(sm.getExpansionLoc(startLoc))==sm.getMainFileID() && sm.getExpansionLineNumber(startLoc) == line+declLines) {
            suspicious=true;
            break;
        }
    }
    if (!suspicious) {
        return true;
    }

    uint32_t startOffset=sm.getFileOffset(sm.getExpansionLoc(startLoc));
    size_t cur_line=sm.getExpansionLineNumber(startLoc);
    uint32_t endOffset=sm.getFileOffset(sm.getExpansionLoc(endLoc));

    // Insert patch location to info (see the per-statement mapping above)
    // locationInfo.addLocation(origFilename, sm.getExpansionLineNumber(endLoc), sm.getExpansionColumnNumber(endLoc));
    uint64_t enclosingScopeID = 0;
    if (endLoc.isValid() && findEnclosingScopeID(enclosingScopeID)) {
        size_t lastLine = sm.getExpansionLineNumber(endLoc);
        for (size_t line = cur_line; line <= lastLine; line++) {
            jmpIDs[line] = enclosingScopeID;
        }
    }
    return true;

    // Get all candidate variables
    LocalDeclFinder declFinder(ctxt,compoundStmt->body_back());
    declFinder.TraverseDecl(curFuncDecl);

    std::vector<clang::VarDecl*> curIntVars;
    std::vector<clang::VarDecl*> curUIntVars;
    std::vector<clang::VarDecl*> curDoubleVars;
    std::vector<clang::VarDecl*> curPtrVars;
    if (isCXX(filename)){
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

    if (curFuncDecl && Config::getConfig().noTemplates.find("INSERT_EXPR")==Config::getConfig().noTemplates.end()) {
        // Make var info
#if 0
        std::vector<VariablePatch::VariableInfo> intInfoList;
        for (clang::VarDecl* var:curIntVars) {
            intInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(), ctxt->getTypeSize(var->getType())));
        }
        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:intFields) {
            intInfoList.push_back(VariablePatch::VariableInfo(field.second, ctxt->getTypeSize(field.first.second->getType())));
        }
        std::vector<VariablePatch::VariableInfo> uintInfoList;
        for (clang::VarDecl* var:curUIntVars) {
            uintInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(), ctxt->getTypeSize(var->getType())));
        }
        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:uintFields) {
            uintInfoList.push_back(VariablePatch::VariableInfo(field.second, ctxt->getTypeSize(field.first.second->getType())));
        }
        std::vector<VariablePatch::VariableInfo> doubleInfoList;
        for (clang::VarDecl* var:curDoubleVars) {
            doubleInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(), ctxt->getTypeSize(var->getType())));
        }
        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:doubleFields) {
            doubleInfoList.push_back(VariablePatch::VariableInfo(field.second, ctxt->getTypeSize(field.first.second->getType())));
        }
        std::vector<VariablePatch::VariableInfo> ptrInfoList;
        for (clang::VarDecl* var:curPtrVars) {
            ptrInfoList.push_back(VariablePatch::VariableInfo(var->getNameAsString(), ctxt->getTypeSize(var->getType())));
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

        // EXPR
        std::string exprCallExpr="";
        if (Config::getConfig().noTemplates.find("INSERT_EXPR")==Config::getConfig().noTemplates.end()) {
            // Make new if stmt
            if (isCXX(filename))
                exprCallExpr += "if (__metapro_new_cond_cxx(";
            else
                exprCallExpr += "if (__metapro_new_cond_c(";
            exprCallExpr += std::to_string(Config::getConfig().patchId) + ", \"" +
                            curFuncDecl->getNameAsString() + "\")) ";
            // Make new expr call
            if (isCXX(filename))
                exprCallExpr += "__metapro_exec_expr_cxx(";
            else
                exprCallExpr += "__metapro_exec_expr_c(";
            exprCallExpr += std::to_string(Config::getConfig().patchId) + ", \"" + curFuncDecl->getNameAsString() +
                            "\", " + std::to_string(PatchGenerator::loopID - 1) + "); ";

            // Create new patch
            std::string bodyStr = code.substr(startOffset, endOffset - startOffset + 1);
            InsertPatch* exprPatch = new InsertPatch(ctxt,bodyStr,code,Config::getConfig().patchId, exprCallExpr,endLoc, cur_line,
                        "", true);
#if 0
            exprPatch->intVars = intInfoList;
            exprPatch->uintVars = uintInfoList;
            exprPatch->doubleVars = doubleInfoList;
            exprPatch->ptrVars = ptrInfoList;
            exprPatch->intLits = intLitInfos;
            exprPatch->uintLits = uintLitInfos;
            exprPatch->floatLits = floatLitInfos;
#endif
            patches.push_back(exprPatch);
            Config::getConfig().patchId++;
        }
    }

    return true;
}