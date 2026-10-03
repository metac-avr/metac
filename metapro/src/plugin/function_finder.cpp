#include <clang/AST/Stmt.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Frontend/FrontendPluginRegistry.h>
#include <clang/Frontend/CompilerInstance.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

class FunctionFinder : public clang::RecursiveASTVisitor<FunctionFinder> {
    clang::ASTContext &ctxt;
    std::string targetFile;
    uint32_t targetLine;

public:
    std::vector<uint32_t> lineNumbers;
    explicit FunctionFinder(clang::ASTContext &ctxt, std::string targetFile, uint32_t targetLine) :
                ctxt(ctxt),targetFile(targetFile),targetLine(targetLine) {}

    bool VisitFunctionDecl(clang::FunctionDecl *decl) {
        if (decl->doesThisDeclarationHaveABody()) {
            clang::SourceManager &sm = ctxt.getSourceManager();
            llvm::outs() << "Current file: "
                     << sm.getFilename(sm.getExpansionLoc(decl->getBeginLoc())) << ", Current function: "
                     << decl->getNameAsString() << "\n";
            if (sm.getFilename(sm.getExpansionLoc(decl->getBeginLoc())).endswith(targetFile)) {
                if (sm.getExpansionLineNumber(decl->getBeginLoc()) <= targetLine &&
                                targetLine <= sm.getExpansionLineNumber(decl->getEndLoc())) {
                    lineNumbers.push_back(sm.getExpansionLineNumber(decl->getBeginLoc()));
                    lineNumbers.push_back(sm.getExpansionLineNumber(decl->getEndLoc()));
                    llvm::outs() << "Target function found\nStart line: "
                                    << lineNumbers[0] << ", End line: "
                                    << lineNumbers[1] << "\n";
                    // we found the function, no need to continue
                    return false;
                }
            }
        }
        return true;
    }
};

class FunctionConsumer : public clang::ASTConsumer {
    clang::ASTContext &ctxt;
    std::string targetFile;
    uint32_t targetLine;
    std::string outputFile;

public:
    std::vector<uint32_t> lineNumbers;
    explicit FunctionConsumer(clang::ASTContext &ctxt, std::string targetFile, uint32_t targetLine, std::string outputFile) :
                ctxt(ctxt),targetFile(targetFile),targetLine(targetLine),outputFile(outputFile) {}

    void HandleTranslationUnit(clang::ASTContext &Context) override {
        FunctionFinder finder(Context,targetFile,targetLine);
        finder.TraverseDecl(Context.getTranslationUnitDecl());

        if (finder.lineNumbers.size() > 0) {
            std::ofstream out(outputFile);
            for (uint32_t line : finder.lineNumbers) {
                out << line << std::endl;
            }
            out.close();
        }
    }
};

class FunctionFinderAction : public clang::PluginASTAction {
    std::string targetFile;
    uint32_t targetLine;
    std::string outputFile;

public:
    std::vector<uint32_t> lineNumbers;
    bool ParseArgs(const clang::CompilerInstance &CI, const std::vector<std::string> &args) override {
        if (args.size() >= 3) {
            targetFile = args[0];
            targetLine = std::stoi(args[1]);
            outputFile = args[2];    
        }
        else {
            targetFile = getenv("METAPRO_FUNC_FINDER_TARGET_FILE");
            char* temp_targetLine = getenv("METAPRO_FUNC_FINDER_TARGET_LINE");
            outputFile = getenv("METAPRO_FUNC_FINDER_OUTPUT_FILE");
            if (targetFile.empty() || temp_targetLine==nullptr || outputFile.empty()) {
                llvm::errs() << "Environment variables METAPRO_FUNC_FINDER_TARGET_FILE, METAPRO_FUNC_FINDER_TARGET_LINE, "
                             << "and METAPRO_FUNC_FINDER_OUTPUT_FILE must be set.\n";
                return false;
            }
            targetLine = std::stoi(temp_targetLine);
        }
        llvm::outs() << "Running function finder!\nTarget file: " << targetFile
                     << "\nTarget line: " << targetLine
                     << "\nOutput file: " << outputFile << "\n";
        return true;
    }

    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance &CI,
            llvm::StringRef file) override {
        return std::make_unique<FunctionConsumer>(CI.getASTContext(),targetFile,targetLine,outputFile);
    }

    PluginASTAction::ActionType getActionType() override {
        return PluginASTAction::AddAfterMainAction;
    }
};

static clang::FrontendPluginRegistry::Add<FunctionFinderAction> X("func_finder", "finding lines for a target function");