#include <clang/AST/Stmt.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Frontend/FrontendPluginRegistry.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Analysis/CallGraph.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <boost/filesystem.hpp>

class CallGraphFinder : public clang::RecursiveASTVisitor<CallGraphFinder> {
    clang::ASTContext &ctxt;
    clang::FunctionDecl* curFuncDecl;
    std::string targetFile;
    uint32_t targetLine;

public:
    std::map<std::string, std::vector<std::string>> callGraph;
    std::string fileName;

    explicit CallGraphFinder(clang::ASTContext &ctxt, std::string targetFile, uint32_t targetLine) : ctxt(ctxt), curFuncDecl(nullptr), fileName(""),
            targetFile(targetFile), targetLine(targetLine) {}

    bool VisitFunctionDecl(clang::FunctionDecl* decl) {
        if (decl->doesThisDeclarationHaveABody()) {
            clang::SourceManager& sm = ctxt.getSourceManager();
            fileName = sm.getFilename(sm.getExpansionLoc(decl->getLocation())).str();
            clang::CallGraph gc;
            gc.addToCallGraph(decl);
            clang::CallGraphNode* node=gc.getOrInsertNode(decl);
            std::string funcName=decl->getNameAsString();
            std::vector<std::string> callees;
            llvm::outs() << "Function: " << funcName << "\n";
            if (node != nullptr) {
                for (clang::CallGraphNode::CallRecord callee:node->callees()) {
                    callees.push_back(callee.Callee->getDecl()->getAsFunction()->getNameAsString());
                }
                callGraph[funcName] = callees;
            }
        }
        return true;
    }

    bool TraverseFunctionDecl(clang::FunctionDecl* decl) {
        curFuncDecl = decl;
        bool result = clang::RecursiveASTVisitor<CallGraphFinder>::TraverseFunctionDecl(decl);
        return result;
    }

    bool VisitStmt(clang::Stmt* stmt) {
        clang::SourceManager &sm = ctxt.getSourceManager();
        if (sm.getFilename(sm.getExpansionLoc(stmt->getBeginLoc())).endswith(targetFile)) {
            if (sm.getExpansionLineNumber(stmt->getBeginLoc()) <= targetLine &&
                            targetLine <= sm.getExpansionLineNumber(stmt->getEndLoc())) {
                std::string targetOutputFile(getenv("METAPRO_AST_FL_TARGET_OUTPUT_FILE"));
                std::ofstream fo(targetOutputFile);
                if (fo.good()) {
                    fo.write(curFuncDecl->getNameAsString().c_str(), curFuncDecl->getNameAsString().size());
                }
                fo.close();
            }
        }
        return true;
    }
};

class ASTFL : public clang::RecursiveASTVisitor<ASTFL> {
    clang::ASTContext &ctxt;
    std::string targetFile;
    uint32_t targetLine;
    std::vector<clang::Stmt*> stmtStack;
    clang::FunctionDecl* curFuncDecl;
    std::vector<std::pair<std::string, std::string>>& targetFuncs;

public:
    std::set<uint32_t> lineNumbers;
    clang::FunctionDecl* targetFuncDecl;
    std::string fileName;

    explicit ASTFL(clang::ASTContext &ctxt, std::string targetFile, uint32_t targetLine, std::vector<std::pair<std::string, std::string>> &targetFuncs) :
                ctxt(ctxt),targetFile(targetFile),targetLine(targetLine),targetFuncs(targetFuncs) {}

    bool TraverseStmt(clang::Stmt *stmt) {
        stmtStack.push_back(stmt);
        bool result = clang::RecursiveASTVisitor<ASTFL>::TraverseStmt(stmt);
        stmtStack.pop_back();
        return result;
    }

    bool VisitStmt(clang::Stmt* stmt) {
        clang::SourceManager &sm = ctxt.getSourceManager();
        fileName = sm.getFilename(sm.getExpansionLoc(stmt->getBeginLoc())).str();
        if (sm.getFilename(sm.getExpansionLoc(stmt->getBeginLoc())).endswith(targetFile)) {
            if (sm.getExpansionLineNumber(stmt->getBeginLoc()) <= targetLine &&
                            targetLine <= sm.getExpansionLineNumber(stmt->getEndLoc())) {
                for (clang::Stmt* parent: stmtStack) {
                    if (parent) {
                        uint32_t lineNumber=sm.getExpansionLineNumber(parent->getBeginLoc());
                        lineNumbers.insert(lineNumber);
                    }
                }
                targetFuncDecl = curFuncDecl;
            }
        }
        return true;
    }

    bool VisitCallExpr(clang::CallExpr* expr) {
        if (!expr->getCalleeDecl()) return true;
        if (clang::FunctionDecl::classof(expr->getCalleeDecl())) {
            clang::SourceManager &sm = ctxt.getSourceManager();
            clang::FunctionDecl* decl = (clang::FunctionDecl*)expr->getCalleeDecl();
            fileName = sm.getFilename(sm.getExpansionLoc(decl->getLocation())).str();
            for (std::pair<std::string, std::string> target:targetFuncs) {
                if (decl->getNameAsString() == target.second) {
                    for (clang::Stmt* parent: stmtStack) {
                        if (parent) {
                            uint32_t lineNumber=sm.getExpansionLineNumber(parent->getBeginLoc());
                            lineNumbers.insert(lineNumber);
                        }
                    }
                    break;
                }
            }
        }

        return true;
    }

    bool TraverseFunctionDecl(clang::FunctionDecl* decl) {
        curFuncDecl = decl;
        bool result = clang::RecursiveASTVisitor<ASTFL>::TraverseFunctionDecl(decl);
        return result;
    }
};

class CallGraphConsumer : public clang::ASTConsumer {
    clang::ASTContext &ctxt;
    std::string outputFile;
    std::string targetFile;
    uint32_t targetLine;

public:
    std::set<uint32_t> lineNumbers;
    explicit CallGraphConsumer(clang::ASTContext &ctxt, std::string outputFile, std::string targetFile, uint32_t targetLine) :
                ctxt(ctxt),outputFile(outputFile), targetFile(targetFile), targetLine(targetLine) {}

    void HandleTranslationUnit(clang::ASTContext &Context) override {
        CallGraphFinder finder(Context,targetFile, targetLine);
        finder.TraverseDecl(Context.getTranslationUnitDecl());

        if (!finder.callGraph.empty()) {
            clang::SourceManager& sm = ctxt.getSourceManager();
            if (finder.fileName.substr(0,8) != "conftest" && finder.fileName[0] != '/') {
                std::ofstream out(outputFile, std::ofstream::app);
                out << finder.fileName << std::endl;
                for (std::map<std::string, std::vector<std::string>>::value_type funcName : finder.callGraph) {
                    out << "\t" << funcName.first << std::endl;
                    for (std::string callee : funcName.second) {
                        out << "\t\t" << callee << std::endl;
                    }
                }
                out.close();
            }
        }
    }
};

class ASTFLConsumer : public clang::ASTConsumer {
    clang::ASTContext &ctxt;
    std::string targetFile;
    uint32_t targetLine;
    std::string outputFile;

public:
    std::set<uint32_t> lineNumbers;
    explicit ASTFLConsumer(clang::ASTContext &ctxt, std::string targetFile, uint32_t targetLine, std::string outputFile) :
                ctxt(ctxt),targetFile(targetFile),targetLine(targetLine),outputFile(outputFile) {}

    void HandleTranslationUnit(clang::ASTContext &Context) override {
        std::string targetFuncFile(getenv("METAPRO_AST_FL_INPUT_FILE"));
        std::ifstream targetFunc(targetFuncFile);
        std::vector<std::pair<std::string, std::string>> targetFuncs;
        while (!targetFunc.eof()) {
            std::string line;
            std::getline(targetFunc, line);
            if (line.empty()) continue;
            size_t colonPos = line.find(':');
            if (colonPos == std::string::npos) continue;
            std::string file = line.substr(0, colonPos);
            std::string func = line.substr(colonPos + 1);
            targetFuncs.push_back(std::make_pair(file, func));
        }
        ASTFL finder(Context,targetFile,targetLine,targetFuncs);
        finder.TraverseDecl(Context.getTranslationUnitDecl());

        if (finder.lineNumbers.size() > 0) {
            std::ofstream out(outputFile, std::ofstream::app);
            for (uint32_t line : finder.lineNumbers) {

                out << boost::filesystem::current_path().string() << "/" << finder.fileName << ":" << line << std::endl;
            }
            out.close();
        }
    }
};

class ASTFLAction : public clang::PluginASTAction {
    std::string targetFile;
    uint32_t targetLine;
    std::string outputFile;

public:
    std::set<uint32_t> lineNumbers;
    bool ParseArgs(const clang::CompilerInstance &CI, const std::vector<std::string> &args) override {
        if (args.size() >= 3) {
            targetFile = args[0];
            targetLine = std::stoi(args[1]);
            outputFile = args[2];    
        }
        else {
            targetFile = getenv("METAPRO_AST_FL_TARGET_FILE");
            char* temp_targetLine = getenv("METAPRO_AST_FL_TARGET_LINE");
            outputFile = getenv("METAPRO_AST_FL_OUTPUT_FILE");
            if (targetFile.empty() || temp_targetLine==nullptr || outputFile.empty()) {
                llvm::errs() << "Environment variables METAPRO_AST_FL_TARGET_FILE, METAPRO_AST_FL_TARGET_LINE, "
                             << "and METAPRO_AST_FL_OUTPUT_FILE must be set.\n";
                return false;
            }
            targetLine = std::stoi(temp_targetLine);
        }
        llvm::outs() << "Running AST FL plugin!\nTarget file: " << targetFile
                     << "\nTarget line: " << targetLine
                     << "\nOutput file: " << outputFile << "\n";
        return true;
    }

    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance &CI,
            llvm::StringRef file) override {
        std::string mode(getenv("METAPRO_AST_FL_MODE"));
        if (mode == "collect")
            return std::make_unique<CallGraphConsumer>(CI.getASTContext(), outputFile, targetFile, targetLine);
        else
            return std::make_unique<ASTFLConsumer>(CI.getASTContext(),targetFile,targetLine,outputFile);
    }

    PluginASTAction::ActionType getActionType() override {
        return PluginASTAction::AddAfterMainAction;
    }
};

static clang::FrontendPluginRegistry::Add<ASTFLAction> X("ast_fl_plugin", "finding AST nodes which are target line's ancester");