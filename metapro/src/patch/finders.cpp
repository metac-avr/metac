#include "patch/finders.h"
#include <llvm-12/llvm/Support/Casting.h>
#include <spdlog/spdlog.h>
#include "utils/string.h"
#include "config/config.h"
#include "config/clang_macro.h"
#include "clang/AST/DeclBase.h"
#include <iostream>
#include <clang/Basic/SourceManager.h>
#include <boost/filesystem.hpp>

bool LiteralFinder::VisitIntegerLiteral(clang::IntegerLiteral *intLiteral) {
    bool isIn=false;
    for (clang::IntegerLiteral* literal:intLiterals) {
        if (literal->getValue().getBitWidth() == intLiteral->getValue().getBitWidth() && literal->getValue() == intLiteral->getValue()) {
            isIn=true;
            break;
        }
    }

    if (!isIn){
        if (intLiteral->getType()->isUnsignedIntegerType())
            uintLiterals.push_back(intLiteral);
        else 
            intLiterals.push_back(intLiteral);
    }
    return true;
}

bool LiteralFinder::VisitFloatingLiteral(clang::FloatingLiteral *floatLiteral) {
    bool isIn=false;
    for (clang::FloatingLiteral* literal:floatLiterals) {
        if (&literal->getValue().getSemantics() == &floatLiteral->getValue().getSemantics() && literal->getValue() == floatLiteral->getValue()) {
            isIn=true;
            break;
        }
    }

    if (!isIn)
        floatLiterals.push_back(floatLiteral);
    return true;
}

std::vector<clang::IntegerLiteral*> LiteralFinder::getIntLiterals() {
    return intLiterals;
}

std::vector<clang::IntegerLiteral*> LiteralFinder::getUIntLiterals() {
    return uintLiterals;
}

std::vector<clang::FloatingLiteral*> LiteralFinder::getFloatLiterals() {
    return floatLiterals;
}

bool GlobalDeclFinderC::VisitVarDecl(clang::VarDecl *varDecl) {
    std::set<std::string> blacklistVars = {
        // "localRngInitialized", // libxml2
        "PKCS7_aux", "PKCS7_SIGNER_INFO_aux", "PKCS7_RECIP_INFO_aux", "PKCS7_ATTR_SIGN_item_tt", "PKCS7_ATTR_VERIFY_item_tt", // openssl vars
        "zend_handlers_count", "zend_spec_handlers", "zend_opcode_handlers", "zend_ce_countable" // php-src
    };
    if (blacklistVars.find(varDecl->getNameAsString())!=blacklistVars.end())
        return true;
    if (varDecl->hasGlobalStorage() && !varDecl->isLocalVarDeclOrParm() && varDecl->isThisDeclarationReferenced() &&
                varDecl->getStorageClass()!=clang::SC_Register){
        if (varDecl->getType()->isSignedIntegerOrEnumerationType())
            intVars.push_back(varDecl);
        else if (varDecl->getType()->isUnsignedIntegerType())
            uintVars.push_back(varDecl);
        else if (varDecl->getType()->isFloatingType())
            doubleVars.push_back(varDecl);
        else if (varDecl->getType()->isPointerType()) {
            if (varDecl->getType()->getPointeeType()->isRecordType())
                structPtrVars.push_back(varDecl);
            else
                ptrVars.push_back(varDecl);
        }
        else if (varDecl->getType()->isRecordType())
            structVars.push_back(varDecl);
        /* An array is none of the above to clang -- `float t[21]` is neither a pointer nor a floating
           type -- so without this it is collected nowhere and a patch expression naming it finds no
           variable. It is registered as itself (MetaproVarTypeArray), see genVarTableInsert() */
        else if (varDecl->getType()->isArrayType())
            arrayVars.push_back(varDecl);
    }
    return true;
}

std::vector<clang::VarDecl*> GlobalDeclFinderC::getIntVars() {
    return intVars;
}

std::vector<clang::VarDecl*> GlobalDeclFinderC::getUIntVars() {
    return uintVars;
}

std::vector<clang::VarDecl*> GlobalDeclFinderC::getDoubleVars() {
    return doubleVars;
}

std::vector<clang::VarDecl*> GlobalDeclFinderC::getPtrVars() {
    return ptrVars;
}

std::vector<clang::VarDecl*> GlobalDeclFinderC::getStructVars() {
    return structVars;
}

std::vector<clang::VarDecl*> GlobalDeclFinderC::getStructPtrVars() {
    return structPtrVars;
}
std::vector<clang::VarDecl*> GlobalDeclFinderC::getArrayVars() {
    return arrayVars;
}

bool GlobalDeclFinderCXX::VisitDeclRefExpr(clang::DeclRefExpr *declRefExpr) {
    if (false && clang::VarDecl::classof(declRefExpr->getDecl())) { // TODO: Now we ignore C++ global variables: namespace
        clang::VarDecl* varDecl = clang::dyn_cast<clang::VarDecl>(declRefExpr->getDecl());
        if (varDecl->hasGlobalStorage() && !varDecl->isCXXClassMember() &&
                    varDecl->getStorageClass()!=clang::SC_Register){  // TODO: Now we ignore class members
            if (varDecl->getType()->isSignedIntegerOrEnumerationType())
                intVars.push_back(varDecl);
            else if (varDecl->getType()->isUnsignedIntegerType())
                uintVars.push_back(varDecl);
            else if (varDecl->getType()->isFloatingType())
                doubleVars.push_back(varDecl);
            else if (varDecl->getType()->isPointerType())
                ptrVars.push_back(varDecl);
        }
    }

    return true;
}

std::vector<clang::VarDecl*> GlobalDeclFinderCXX::getIntVars() {
    return intVars;
}

std::vector<clang::VarDecl*> GlobalDeclFinderCXX::getUIntVars() {
    return uintVars;
}

std::vector<clang::VarDecl*> GlobalDeclFinderCXX::getDoubleVars() {
    return doubleVars;
}

std::vector<clang::VarDecl*> GlobalDeclFinderCXX::getPtrVars() {
    return ptrVars;
}

bool LocalDeclFinder::TraverseCompoundStmt(clang::CompoundStmt* compoundStmt) {
    intVarStack[compoundStmt]=std::vector<clang::VarDecl*>();
    uintVarStack[compoundStmt]=std::vector<clang::VarDecl*>();
    doubleVarStack[compoundStmt]=std::vector<clang::VarDecl*>();
    ptrVarStack[compoundStmt]=std::vector<clang::VarDecl*>();
    
    stmtStack.push_back(compoundStmt);
    bool result = clang::RecursiveASTVisitor<LocalDeclFinder>::TraverseCompoundStmt(compoundStmt);
    if (!result) return false;

    intVarStack.erase(compoundStmt);
    uintVarStack.erase(compoundStmt);
    doubleVarStack.erase(compoundStmt);
    ptrVarStack.erase(compoundStmt);
    intPtrVarStack.erase(compoundStmt);
    uintPtrVarStack.erase(compoundStmt);
    intFieldStack.erase(compoundStmt);
    uintFieldStack.erase(compoundStmt);
    doubleFieldStack.erase(compoundStmt);
    ptrFieldStack.erase(compoundStmt);
    stmtStack.pop_back();
    return result;
}

bool LocalDeclFinder::TraverseForStmt(clang::ForStmt* forStmt) {
    intVarStack[forStmt]=std::vector<clang::VarDecl*>();
    uintVarStack[forStmt]=std::vector<clang::VarDecl*>();
    doubleVarStack[forStmt]=std::vector<clang::VarDecl*>();
    ptrVarStack[forStmt]=std::vector<clang::VarDecl*>();
    
    stmtStack.push_back(forStmt);
    bool result = clang::RecursiveASTVisitor<LocalDeclFinder>::TraverseForStmt(forStmt);
    if (!result) return false;

    intVarStack.erase(forStmt);
    uintVarStack.erase(forStmt);
    doubleVarStack.erase(forStmt);
    ptrVarStack.erase(forStmt);
    intPtrVarStack.erase(forStmt);
    uintPtrVarStack.erase(forStmt);
    intFieldStack.erase(forStmt);
    uintFieldStack.erase(forStmt);
    doubleFieldStack.erase(forStmt);
    ptrFieldStack.erase(forStmt);
    stmtStack.pop_back();
    return result;
}

bool LocalDeclFinder::TraverseIfStmt(clang::IfStmt* ifStmt) {
    intVarStack[ifStmt]=std::vector<clang::VarDecl*>();
    uintVarStack[ifStmt]=std::vector<clang::VarDecl*>();
    doubleVarStack[ifStmt]=std::vector<clang::VarDecl*>();
    ptrVarStack[ifStmt]=std::vector<clang::VarDecl*>();
    
    stmtStack.push_back(ifStmt);
    bool result = clang::RecursiveASTVisitor<LocalDeclFinder>::TraverseIfStmt(ifStmt);
    if (!result) return false;

    intVarStack.erase(ifStmt);
    uintVarStack.erase(ifStmt);
    doubleVarStack.erase(ifStmt);
    ptrVarStack.erase(ifStmt);
    intPtrVarStack.erase(ifStmt);
    uintPtrVarStack.erase(ifStmt);
    intFieldStack.erase(ifStmt);
    uintFieldStack.erase(ifStmt);
    doubleFieldStack.erase(ifStmt);
    ptrFieldStack.erase(ifStmt);
    stmtStack.pop_back();
    return result;
}

bool LocalDeclFinder::TraverseWhileStmt(clang::WhileStmt* whileStmt) {
    intVarStack[whileStmt]=std::vector<clang::VarDecl*>();
    uintVarStack[whileStmt]=std::vector<clang::VarDecl*>();
    doubleVarStack[whileStmt]=std::vector<clang::VarDecl*>();
    ptrVarStack[whileStmt]=std::vector<clang::VarDecl*>();
    
    stmtStack.push_back(whileStmt);
    bool result = clang::RecursiveASTVisitor<LocalDeclFinder>::TraverseWhileStmt(whileStmt);
    if (!result) return false;

    intVarStack.erase(whileStmt);
    uintVarStack.erase(whileStmt);
    doubleVarStack.erase(whileStmt);
    ptrVarStack.erase(whileStmt);
    intPtrVarStack.erase(whileStmt);
    uintPtrVarStack.erase(whileStmt);
    intFieldStack.erase(whileStmt);
    uintFieldStack.erase(whileStmt);
    doubleFieldStack.erase(whileStmt);
    ptrFieldStack.erase(whileStmt);
    stmtStack.pop_back();
    return result;
}

bool LocalDeclFinder::TraverseStmt(clang::Stmt* stmt) {
    if (stmt == targetStmt) {
        return false;
    }
    return clang::RecursiveASTVisitor<LocalDeclFinder>::TraverseStmt(stmt);
}

bool LocalDeclFinder::TraverseLambdaExpr(clang::LambdaExpr* lambdaExpr) {
    return true; // Ignore lambda expressions
}

bool LocalDeclFinder::VisitVarDecl(clang::VarDecl* varDecl) {
    std::set<std::string> blacklistVars = {
        "PKCS7_aux", "PKCS7_SIGNER_INFO_aux", "PKCS7_RECIP_INFO_aux", "PKCS7_ATTR_SIGN_item_tt", "PKCS7_ATTR_VERIFY_item_tt", // openssl vars
        "zend_handlers_count", "zend_spec_handlers", "zend_opcode_handlers", "zend_ce_countable" // php-src
    };
    if (blacklistVars.find(varDecl->getNameAsString())!=blacklistVars.end())
        return true;
    if (varDecl->getStorageClass()!=clang::SC_Register && funcPtrTypeParamSize==0) {
        if (varDecl->getType().getAsString().find("FILE")!=std::string::npos) return true; // Ignore FILE type
        if (stmtStack.size()==0 || (clang::ParmVarDecl::classof(varDecl))) {
            if (varDecl->getNameAsString().size()==0) return true; // Parameters sometimes have no name

            if (varDecl->getType()->isSignedIntegerOrEnumerationType())
                intParams.push_back(varDecl);
            else if (varDecl->getType()->isUnsignedIntegerType())
                uintParams.push_back(varDecl);
            else if (varDecl->getType()->isFloatingType())
                doubleParams.push_back(varDecl);
            else if (varDecl->getType()->isPointerType()) {
                ptrParams.push_back(varDecl);

                // TODO: Find a better way to handle field access of uninitialized variables
                if (varDecl->getType()->getPointeeType()->isRecordType()) {
                    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> members;
                    clang::RecordDecl* recordDecl = varDecl->getType()->getPointeeType()->getAsRecordDecl();
                    if (recordDecl->isStruct() || recordDecl->isClass()) {
                        clang::DeclRefExpr* rootExpr=clang::DeclRefExpr::Create(*ctxt,clang::NestedNameSpecifierLoc(),clang::SourceLocation(),varDecl,
                                    false,clang::SourceLocation(),varDecl->getType(),clang::VK_LValue);
                        for (clang::FieldDecl* fieldDecl:recordDecl->fields()) {
                            getAvailableFields(members,fieldDecl,rootExpr,true);
                        }

                        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> memberExpr:members) {
                            if (memberExpr.first.first->getType()->isSignedIntegerOrEnumerationType())
                                intFieldParams.push_back(memberExpr);
                            else if (memberExpr.first.first->getType()->isUnsignedIntegerType())
                                uintFieldParams.push_back(memberExpr);
                            else if (memberExpr.first.first->getType()->isFloatingType())
                                doubleFieldParams.push_back(memberExpr);
                            else if (memberExpr.first.first->getType()->isPointerType())
                                ptrFieldParams.push_back(memberExpr);
                        }
                    }
                }
                else if (varDecl->getType()->getPointeeType()->isSignedIntegerOrEnumerationType()) {
                    intPtrParams.push_back(varDecl);
                }
                else if (varDecl->getType()->getPointeeType()->isUnsignedIntegerType()) {
                    uintPtrParams.push_back(varDecl);
                }
                
                clang::QualType pointeeType=varDecl->getType()->getPointeeType();
                if (clang::ParenType::classof(pointeeType.getTypePtr())) {
                    pointeeType=clang::dyn_cast<clang::ParenType>(pointeeType.getTypePtr())->getInnerType();
                }
                if (clang::FunctionProtoType::classof(pointeeType.getTypePtr())) {
                    funcPtrTypeParamSize=clang::dyn_cast<clang::FunctionProtoType>(pointeeType)->getNumParams();
                }
            }
            else if (varDecl->getType()->isRecordType() && varDecl->hasInit()) {
                std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> members;
                clang::RecordDecl* recordDecl = varDecl->getType()->getAsRecordDecl();
                if (recordDecl->isStruct() || recordDecl->isClass()) {
                    clang::DeclRefExpr* rootExpr=clang::DeclRefExpr::Create(*ctxt,clang::NestedNameSpecifierLoc(),clang::SourceLocation(),varDecl,
                                false,clang::SourceLocation(),varDecl->getType(),clang::VK_LValue);
                    for (clang::FieldDecl* fieldDecl:recordDecl->fields()) {
                        getAvailableFields(members,fieldDecl,rootExpr,false);
                    }

                    for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> memberExpr:members) {
                        if (memberExpr.first.first->getType()->isSignedIntegerOrEnumerationType())
                            intFieldParams.push_back(memberExpr);
                        else if (memberExpr.first.first->getType()->isUnsignedIntegerType())
                            uintFieldParams.push_back(memberExpr);
                        else if (memberExpr.first.first->getType()->isFloatingType())
                            doubleFieldParams.push_back(memberExpr);
                        else if (memberExpr.first.first->getType()->isPointerType())
                            ptrFieldParams.push_back(memberExpr);
                    }
                }
            }
        }
        else {
            if (varDecl->getType()->isSignedIntegerOrEnumerationType())
                intVarStack[stmtStack.back()].push_back(varDecl);
            else if (varDecl->getType()->isUnsignedIntegerType())
                uintVarStack[stmtStack.back()].push_back(varDecl);
            else if (varDecl->getType()->isFloatingType())
                doubleVarStack[stmtStack.back()].push_back(varDecl);
            else if (varDecl->getType()->isPointerType()) {
                ptrVarStack[stmtStack.back()].push_back(varDecl);

                if (varDecl->getType()->getPointeeType()->isRecordType()) {
                    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> members;
                    clang::RecordDecl* recordDecl = varDecl->getType()->getPointeeType()->getAsRecordDecl();
                    if (recordDecl->isStruct() || recordDecl->isClass()) {
                        clang::DeclRefExpr* rootExpr=clang::DeclRefExpr::Create(*ctxt,clang::NestedNameSpecifierLoc(),clang::SourceLocation(),varDecl,
                                    false,clang::SourceLocation(),varDecl->getType(),clang::VK_LValue);
                        for (clang::FieldDecl* fieldDecl:recordDecl->fields()) {
                            getAvailableFields(members,fieldDecl,rootExpr,true);
                        }

                        for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> memberExpr:members) {
                            if (memberExpr.first.first->getType()->isSignedIntegerOrEnumerationType())
                                intFieldStack[stmtStack.back()].push_back(memberExpr);
                            else if (memberExpr.first.first->getType()->isUnsignedIntegerType())
                                uintFieldStack[stmtStack.back()].push_back(memberExpr);
                            else if (memberExpr.first.first->getType()->isFloatingType())
                                doubleFieldStack[stmtStack.back()].push_back(memberExpr);
                            else if (memberExpr.first.first->getType()->isPointerType())
                                ptrFieldStack[stmtStack.back()].push_back(memberExpr);
                        }
                    }
                }
                else if (varDecl->getType()->getPointeeType()->isSignedIntegerOrEnumerationType()) {
                    intPtrVarStack[stmtStack.back()].push_back(varDecl);
                }
                else if (varDecl->getType()->getPointeeType()->isUnsignedIntegerType()) {
                    uintPtrVarStack[stmtStack.back()].push_back(varDecl);
                }
            }
            else if (varDecl->getType()->isRecordType() && varDecl->hasInit()) {
                std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> members;
                clang::RecordDecl* recordDecl = varDecl->getType()->getAsRecordDecl();
                if (recordDecl->isStruct() || recordDecl->isClass()) {
                    clang::DeclRefExpr* rootExpr=clang::DeclRefExpr::Create(*ctxt,clang::NestedNameSpecifierLoc(),clang::SourceLocation(),varDecl,
                                false,clang::SourceLocation(),varDecl->getType(),clang::VK_LValue);
                    for (clang::FieldDecl* fieldDecl:recordDecl->fields()) {
                        getAvailableFields(members,fieldDecl,rootExpr,false);
                    }

                    for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> memberExpr:members) {
                        if (memberExpr.first.first->getType()->isSignedIntegerOrEnumerationType())
                            intFieldStack[stmtStack.back()].push_back(memberExpr);
                        else if (memberExpr.first.first->getType()->isUnsignedIntegerType())
                            uintFieldStack[stmtStack.back()].push_back(memberExpr);
                        else if (memberExpr.first.first->getType()->isFloatingType())
                            doubleFieldStack[stmtStack.back()].push_back(memberExpr);
                        else if (memberExpr.first.first->getType()->isPointerType())
                            ptrFieldStack[stmtStack.back()].push_back(memberExpr);
                    }
                }
            }
        }
    }
    else if (funcPtrTypeParamSize!=0) {
        funcPtrTypeParamSize--;
    }
    return true;
}

// Generate not equal condition for all bases
clang::BinaryOperator* generateEqualForAll(clang::ASTContext* ctxt,std::vector<clang::Expr*> bases,size_t curIndex,clang::Expr* nullExpr) {
    if (curIndex==bases.size()-1) {
        // Most base
        clang::Expr* mostBase=bases[curIndex];
        clang::CompoundLiteralExpr* castToInt=new(*ctxt) clang::CompoundLiteralExpr(clang::SourceLocation(),ctxt->getTrivialTypeSourceInfo(ctxt->UnsignedLongLongTy),
                    ctxt->UnsignedLongLongTy,CLANG_VALUE_KIND_RVALUE,mostBase,false);
        return clang::BinaryOperator::Create(*ctxt,castToInt,nullExpr,clang::BO_GT,castToInt->getType(),CLANG_VALUE_KIND_RVALUE,
                    clang::OK_Ordinary,clang::SourceLocation(),clang::FPOptionsOverride());
    }
    else {
        // Recursive call
        clang::BinaryOperator* lhs=generateEqualForAll(ctxt,bases,curIndex+1,nullExpr);
        clang::CompoundLiteralExpr* castToInt=new(*ctxt) clang::CompoundLiteralExpr(clang::SourceLocation(),ctxt->getTrivialTypeSourceInfo(ctxt->UnsignedLongLongTy),
                    ctxt->UnsignedLongLongTy,CLANG_VALUE_KIND_RVALUE,bases[curIndex],false);
        clang::BinaryOperator* rhs=clang::BinaryOperator::Create(*ctxt,bases[curIndex],nullExpr,clang::BO_GT,bases[curIndex]->getType(),CLANG_VALUE_KIND_RVALUE,
                    clang::OK_Ordinary,clang::SourceLocation(),clang::FPOptionsOverride());
        return clang::BinaryOperator::Create(*ctxt,lhs,rhs,clang::BO_LAnd,ctxt->BoolTy,CLANG_VALUE_KIND_RVALUE,clang::OK_Ordinary,clang::SourceLocation(),
                    clang::FPOptionsOverride());
    }
}

void LocalDeclFinder::getAvailableFields(std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>>& members,clang::FieldDecl* curField,clang::Expr* baseExpr,bool isBaseArrow,uint32_t depth) {
    if (depth>=Config::getConfig().fieldDepth) return;
    depth++;

    if ((curField->getAccess()==clang::AccessSpecifier::AS_public || curField->getAccess()==clang::AccessSpecifier::AS_none) && !curField->isBitField()) {
        // If the field is primitive type, add to the list
        if (curField->getType()->isSignedIntegerOrEnumerationType() || curField->getType()->isUnsignedIntegerType() ||
                        curField->getType()->isFloatingType() || curField->getType()->isPointerType()) {
            clang::MemberExpr* newMember=clang::MemberExpr::Create(*ctxt,baseExpr,isBaseArrow,clang::SourceLocation(),
                        clang::NestedNameSpecifierLoc(),clang::SourceLocation(),curField,clang::DeclAccessPair::make(curField,curField->getAccess()),
                        clang::DeclarationNameInfo(curField->getDeclName(),clang::SourceLocation()),nullptr,curField->getType(),clang::VK_LValue,
                        clang::OK_Ordinary,clang::NonOdrUseReason::NOUR_None);
            std::string memberString=stmtToString(ctxt,newMember);
            if (!clang::MemberExpr::classof(baseExpr) && !isBaseArrow)
                members.push_back(std::make_pair(std::make_pair(newMember,newMember),memberString));
            else {
                // Generate unique number for pointer field
                clang::Expr* uniqueNumber=nullptr;
                if (curField->getType()->isSignedIntegerOrEnumerationType() || curField->getType()->isUnsignedIntegerType())
                    uniqueNumber=new(*ctxt) clang::IntegerLiteral(*ctxt,llvm::APInt(64,INT_UNIQUE_NUMBER),ctxt->LongLongTy,clang::SourceLocation());
                else if (curField->getType()->isFloatingType())
                    uniqueNumber=clang::FloatingLiteral::Create(*ctxt,llvm::APFloat(FLOAT_UNIQUE_NUMBER),true,ctxt->DoubleTy,clang::SourceLocation());
                else if (curField->getType()->isPointerType())
                    uniqueNumber=new(*ctxt) clang::IntegerLiteral(*ctxt,llvm::APInt(32,0), ctxt->IntTy,clang::SourceLocation());
                
                clang::IntegerLiteral* nullExpr=clang::IntegerLiteral::Create(*ctxt,llvm::APInt(32,1000),ctxt->IntTy,clang::SourceLocation());
                clang::IntegerLiteral* zeroExpr=clang::IntegerLiteral::Create(*ctxt,llvm::APInt(32,0),ctxt->IntTy,clang::SourceLocation());
                // Get all possible null pointers
                std::vector<clang::Expr*> bases;
                clang::Expr* currentBase=baseExpr;
                while (currentBase) {
                    if (currentBase->getType()->isPointerType()) {
                        bases.push_back(currentBase);
                    }
                    
                    if (clang::MemberExpr::classof(currentBase)) {
                        clang::MemberExpr* curMemberExpr=clang::dyn_cast<clang::MemberExpr>(currentBase);
                        currentBase=curMemberExpr->getBase();
                    }
                    else break;
                }

                // Condition of ternary operator (conditional operator) (baseExpr != NULL)
                clang::BinaryOperator* condition=generateEqualForAll(ctxt,bases,0,nullExpr);

                // Ternary operator (baseExpr > (void*)1000) ? baseExpr->field : uniqueNumber
                clang::ConditionalOperator* ternary=new(*ctxt) clang::ConditionalOperator(condition,clang::SourceLocation(),newMember,
                            clang::SourceLocation(),uniqueNumber,curField->getType(),CLANG_VALUE_KIND_RVALUE,clang::OK_Ordinary);
                
                // Ternary operator for pointer
                clang::ParenExpr* parenExpr=new(*ctxt) clang::ParenExpr(clang::SourceLocation(),clang::SourceLocation(),newMember);
                clang::UnaryOperator* addressExpr=clang::UnaryOperator::Create(*ctxt,parenExpr,clang::UO_AddrOf,ctxt->getPointerType(curField->getType()),
                            CLANG_VALUE_KIND_RVALUE,clang::OK_Ordinary,clang::SourceLocation(),false,clang::FPOptionsOverride());
                clang::ConditionalOperator* ptrTernary=new(*ctxt) clang::ConditionalOperator(condition,clang::SourceLocation(),addressExpr,
                            clang::SourceLocation(),zeroExpr,ctxt->getPointerType(curField->getType()),CLANG_VALUE_KIND_RVALUE,clang::OK_Ordinary);
                members.push_back(std::make_pair(std::make_pair(ternary,ptrTernary),memberString));
            }
        }

        // If the field is pointer and the pointee type is Record type, call recursive with the fields
        if (curField->getType()->isPointerType() && curField->getType()->getPointeeType()->isRecordType()) {
            clang::RecordDecl* recordDecl = curField->getType()->getPointeeType()->getAsRecordDecl();
            if (recordDecl->isStruct() || recordDecl->isClass()) {
                for (clang::FieldDecl* fieldDecl:recordDecl->fields()) {
                    getAvailableFields(members,fieldDecl,clang::MemberExpr::Create(*ctxt,baseExpr,isBaseArrow,clang::SourceLocation(),
                                clang::NestedNameSpecifierLoc(),clang::SourceLocation(),curField,clang::DeclAccessPair::make(curField,curField->getAccess()),
                                clang::DeclarationNameInfo(curField->getDeclName(),clang::SourceLocation()),nullptr,curField->getType(),clang::VK_LValue,
                                clang::OK_Ordinary,clang::NonOdrUseReason::NOUR_None),true,depth+1);
                }
            }
        }
        // If the field is Record type, call recursive with the fields
        else if (curField->getType()->isRecordType()) {
            clang::RecordDecl* recordDecl = curField->getType()->getAsRecordDecl();
            if (recordDecl->isStruct() || recordDecl->isClass() || recordDecl->isUnion()) {
                for (clang::FieldDecl* fieldDecl:recordDecl->fields()) {
                    getAvailableFields(members,fieldDecl,clang::MemberExpr::Create(*ctxt,baseExpr,isBaseArrow,clang::SourceLocation(),
                                clang::NestedNameSpecifierLoc(),clang::SourceLocation(),curField,clang::DeclAccessPair::make(curField,curField->getAccess()),
                                clang::DeclarationNameInfo(curField->getDeclName(),clang::SourceLocation()),nullptr,curField->getType(),clang::VK_LValue,
                                clang::OK_Ordinary,clang::NonOdrUseReason::NOUR_None),false,depth+1);
                }
            }
        }
    }
}

std::vector<clang::VarDecl*> LocalDeclFinder::getIntVars() {
    std::vector<clang::VarDecl*> result;
    for (std::pair<clang::Stmt*,std::vector<clang::VarDecl*>> pair:intVarStack) {
        result.insert(result.end(),pair.second.begin(),pair.second.end());
    }
    for (clang::VarDecl* varDecl:intParams) {
        result.push_back(varDecl);
    }
    return result;
}

std::vector<clang::VarDecl*> LocalDeclFinder::getUIntVars() {
    std::vector<clang::VarDecl*> result;
    for (std::pair<clang::Stmt*,std::vector<clang::VarDecl*>> pair:uintVarStack) {
        result.insert(result.end(),pair.second.begin(),pair.second.end());
    }
    for (clang::VarDecl* varDecl:uintParams) {
        result.push_back(varDecl);
    }
    return result;
}

std::vector<clang::VarDecl*> LocalDeclFinder::getDoubleVars() {
    std::vector<clang::VarDecl*> result;
    for (std::pair<clang::Stmt*,std::vector<clang::VarDecl*>> pair:doubleVarStack) {
        result.insert(result.end(),pair.second.begin(),pair.second.end());
    }
    for (clang::VarDecl* varDecl:doubleParams) {
        result.push_back(varDecl);
    }
    return result;
}

std::vector<clang::VarDecl*> LocalDeclFinder::getPtrVars() {
    std::vector<clang::VarDecl*> result;
    for (std::pair<clang::Stmt*,std::vector<clang::VarDecl*>> pair:ptrVarStack) {
        result.insert(result.end(),pair.second.begin(),pair.second.end());
    }
    for (clang::VarDecl* varDecl:ptrParams) {
        result.push_back(varDecl);
    }
    return result;
}

std::vector<clang::VarDecl*> LocalDeclFinder::getIntPtrVars() {
    std::vector<clang::VarDecl*> result;
    for (std::pair<clang::Stmt*,std::vector<clang::VarDecl*>> pair:intPtrVarStack) {
        result.insert(result.end(),pair.second.begin(),pair.second.end());
    }
    for (clang::VarDecl* varDecl:intPtrParams) {
        result.push_back(varDecl);
    }
    return result;
}

std::vector<clang::VarDecl*> LocalDeclFinder::getUIntPtrVars() {
    std::vector<clang::VarDecl*> result;
    for (std::pair<clang::Stmt*,std::vector<clang::VarDecl*>> pair:uintPtrVarStack) {
        result.insert(result.end(),pair.second.begin(),pair.second.end());
    }
    for (clang::VarDecl* varDecl:uintPtrParams) {
        result.push_back(varDecl);
    }
    return result;
}

std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> LocalDeclFinder::getIntFields() {
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> result;
    for (std::pair<clang::Stmt*,std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>>> pair:intFieldStack) {
        result.insert(result.end(),pair.second.begin(),pair.second.end());
    }
    for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:intFieldParams) {
        result.push_back(field);
    }
    return result;
}

std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> LocalDeclFinder::getUIntFields() {
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> result;
    for (std::pair<clang::Stmt*,std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>>> pair:uintFieldStack) {
        result.insert(result.end(),pair.second.begin(),pair.second.end());
    }
    for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:uintFieldParams) {
        result.push_back(field);
    }
    return result;
}

std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> LocalDeclFinder::getDoubleFields() {
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> result;
    for (std::pair<clang::Stmt*,std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>>> pair:doubleFieldStack) {
        result.insert(result.end(),pair.second.begin(),pair.second.end());
    }
    for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:doubleFieldParams) {
        result.push_back(field);
    }
    return result;
}

std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> LocalDeclFinder::getPtrFields() {
    std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>> result;
    for (std::pair<clang::Stmt*,std::vector<std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string>>> pair:ptrFieldStack) {
        result.insert(result.end(),pair.second.begin(),pair.second.end());
    }
    for (std::pair<std::pair<clang::Expr*,clang::Expr*>,std::string> field:ptrFieldParams) {
        result.push_back(field);
    }
    return result;
}

/*
    Commented out while every function of function-info.json is offered as an ingredient. A callee is now
    resolved by name at run time, so a function this build does not have is left unresolved instead of
    breaking the link of the meta-program, which is what most of these entries were about. Uncomment it,
    and its two calls below, to keep the functions that do link and run but take the program apart out of
    the patches. isStandard() is gone: it whitelisted the names worth registering at every function entry,
    and nothing is registered any more.
*/
// bool FunctionFinder::isBlacklisted(std::string funcName) {
//     std::set<std::string> blacklisted = {
//         "xmlXPathInit",
//         "init_opcode_serialiser", "ZEND_NULL_HANDLER", "zend_vm_get_opcode_handler_idx", "zend_call_method", "zend_vm_get_opcode_handler", // php
//         "snd_pcm_nonblock", // ffmpeg
//         "xmllintShell", // libxml2
//         "mrb_init_mrbgems", "mrb_bint_cmp", "mrb_gc_free_bint", "mrb_bint_memsize", "mrb_rational_copy", "mrb_bint_copy", "mrb_complex_copy", "mrb_bint_as_int", // mruby
//         "gpg_err_code_from_errno", "force_no_aesni", "fastrand", "mem_alloc_state", "set_mem_alloc_state", // ndpi
//     };
//     if (funcName.find("__builtin")!=std::string::npos) return true; // Ignore builtin functions
//     else if (funcName.size() >= 2 && funcName[0] == '_' && funcName[1] == '_') return true; // Reserved for the implementation
//     else if (blacklisted.find(funcName) != blacklisted.end()) return true;
//     else if (funcName.find("_SPEC")!=std::string::npos) return true; // Ignore php SPEC functions
//     else return false;
// }

bool FunctionFinder::VisitCallExpr(clang::CallExpr* callExpr) {
    clang::Decl* decl = callExpr->getCalleeDecl();
    clang::SourceManager& srcMgr = ctxt->getSourceManager();
    if (decl && clang::FunctionDecl::classof(decl)) {
        clang::FunctionDecl* funcDecl = clang::dyn_cast<clang::FunctionDecl>(decl);
        std::string funcName = funcDecl->getNameAsString();
        // if (isBlacklisted(funcName)) return true;
        // mruby blacklist functions
        if (funcName.find("presym_") != std::string::npos) return true;
        // ffmpeg
        if (funcName.find("ff_") != std::string::npos && funcName.find("_init") != std::string::npos) return true;
        if (visitedFunctions.find(funcDecl) != visitedFunctions.end()) return true;
        visitedFunctions.insert(funcDecl);
        clang::DeclContext* parent = funcDecl->getLexicalDeclContext();
        if (llvm::isa<clang::FunctionDecl>(parent)) return true; // Skip if the function is declared in other functions
        std::string funcFilename = srcMgr.getFilename(srcMgr.getExpansionLoc(funcDecl->getBeginLoc())).str();
        uint32_t funcLine = srcMgr.getExpansionLineNumber(srcMgr.getExpansionLoc(funcDecl->getBeginLoc()));
        if (funcFilename != filename) {
            clang::SourceLocation includedLoc = srcMgr.getIncludeLoc(srcMgr.getFileID(srcMgr.getExpansionLoc(funcDecl->getBeginLoc())));
            while (includedLoc.isValid() && srcMgr.getFileID(includedLoc) != srcMgr.getMainFileID()) {
                includedLoc = srcMgr.getIncludeLoc(srcMgr.getFileID(includedLoc));
            }
            funcLine = srcMgr.getExpansionLineNumber(includedLoc);
        }
        if ((funcFilename.substr(funcFilename.size()-2) != ".h" && funcFilename.substr(funcFilename.size()-4) != ".hpp") &&
                funcFilename != filename) {
            // Skip if the function is declared in other source files
            return true;
        }
        std::pair<clang::FunctionDecl*, std::pair<std::string, uint32_t>> funcInfo =
                    std::make_pair(funcDecl, std::make_pair(funcFilename, funcLine));
        if (funcDecl->getReturnType()->isSignedIntegerOrEnumerationType())
            intFunctions.push_back(funcInfo);
        else if (funcDecl->getReturnType()->isUnsignedIntegerType())
            uintFunctions.push_back(funcInfo);
        else if (funcDecl->getReturnType()->isPointerType())
            ptrFunctions.push_back(funcInfo);
        else if (funcDecl->getReturnType()->isVoidType())
            voidFunctions.push_back(funcInfo);
    }
    return true;
}

bool FunctionFinder::VisitFunctionDecl(clang::FunctionDecl* funcDecl) {
    clang::SourceManager& srcMgr = ctxt->getSourceManager();
    // if (isBlacklisted(funcDecl->getNameAsString())) return true;
    if (visitedFunctions.find(funcDecl) != visitedFunctions.end()) return true;
    visitedFunctions.insert(funcDecl);
    clang::DeclContext* parent = funcDecl->getLexicalDeclContext();
    if (llvm::isa<clang::FunctionDecl>(parent)) return true; // Skip if the function is declared in other functions
    std::string funcFilename = srcMgr.getFilename(srcMgr.getExpansionLoc(funcDecl->getBeginLoc())).str();
    clang::SourceLocation funcLoc = srcMgr.getExpansionLoc(funcDecl->getBeginLoc());
    clang::FileID funcFid = srcMgr.getFileID(funcLoc);
    while (funcFid != srcMgr.getMainFileID()) {
        clang::SourceLocation includeLoc = srcMgr.getIncludeLoc(funcFid);
        if (includeLoc.isInvalid()) break;
        funcLoc = srcMgr.getExpansionLoc(includeLoc);
        funcFid = srcMgr.getFileID(funcLoc);
    }
    uint32_t funcLine = srcMgr.getExpansionLineNumber(funcLoc);
    if ((funcFilename.substr(funcFilename.size()-2) != ".h" && funcFilename.substr(funcFilename.size()-4) != ".hpp") &&
            funcFilename != filename) {
        // Skip if the function is declared in other source files
        return true;
    }
    std::pair<clang::FunctionDecl*, std::pair<std::string, uint32_t>> funcInfo =
                std::make_pair(funcDecl, std::make_pair(funcFilename, funcLine));
    if (funcDecl->getReturnType()->isSignedIntegerOrEnumerationType())
        intFunctions.push_back(funcInfo);
    else if (funcDecl->getReturnType()->isUnsignedIntegerType())
        uintFunctions.push_back(funcInfo);
    else if (funcDecl->getReturnType()->isPointerType())
        ptrFunctions.push_back(funcInfo);
    else if (funcDecl->getReturnType()->isVoidType())
        voidFunctions.push_back(funcInfo);
    return true;
}

bool LabelFinder::VisitLabelStmt(clang::LabelStmt* labelStmt) {
    labels.push_back(labelStmt->getDecl()->getNameAsString());
    return true;
}