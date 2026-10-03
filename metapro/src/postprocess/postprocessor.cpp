#include "postprocess/postprocessor.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Tooling/Tooling.h"
#include <clang/Lex/Preprocessor.h>
#include <cmath>
#include "utils/string.h"
#include "config/config.h"
#include <boost/filesystem.hpp>
#include <spdlog/spdlog.h>
#include <fstream>

static std::string readCodeToString(const std::string &file) {
    FILE* f = fopen(file.c_str(), "r");
    if (f == NULL)
        return "";
    char tmp[1024];
    int ret;
    std::string code = "";
    while ((ret = fread(tmp, 1, 1000, f)) != 0) {
        tmp[ret] = 0;
        code += tmp;
    }
    fclose(f);
    return code;
}

PostProcessor::PostProcessor(std::string filename, LocationInformation& locInfo, std::map<uint64_t, uint64_t>& jmpIDs, std::vector<FaultLocalizer::ResultRecord> &flResult):
        filename(filename), code(""),locInfo(locInfo), jmpIDs(jmpIDs), ctxt(nullptr), flResult(flResult) {
    // Post-process patched source file
    std::ifstream ifs(Config::getConfig().workDir+"/compile_commands.json");
    json root=json::parse(ifs);
    ifs.close();
    std::string fullFilename=Config::getConfig().workDir + "/metapro-source/" + filename;
    fullFilename=boost::filesystem::canonical(fullFilename).string();

    std::vector<std::string> args;
    std::string target_dir;
    for (json entry:root) {
        std::string filename=entry["file"];
        if (filename[0]!='/') {
            // bear 2.x does not store full path
            std::string _temp=entry["directory"];
            filename=_temp+"/"+filename;
        }
        filename = boost::filesystem::path(filename).lexically_normal().string(); // Some system files does not exist to use canonical()

        if (fullFilename == filename) {
            for (size_t i=0;i<entry["arguments"].size();i++) {
                if (!endsWith(filename,entry["arguments"][i]) && i!=0 && entry["arguments"][i]!="-c")
                    args.push_back(entry["arguments"][i]);
            }
            target_dir=entry["directory"];
            break;
        }
    }
    args.insert(args.end(), Config::getConfig().buildOptions.begin(), Config::getConfig().buildOptions.end());
    
    if (args.size() != 0) {
        for (std::string arg:args) {
            if (!(arg.size()>4 && arg[0]!='-' && (arg.substr(arg.size()-2,2)==".c" || arg.substr(arg.size()-4,4)==".cpp" || arg.substr(arg.size()-3,3)==".cc")))
                args.push_back(arg);
            if (arg=="-D_GLIBCXX_DEBUG" || arg=="-D _GLIBCXX_DEBUG")
                Config::getConfig().isDebugForCXX=true;
        }
    }
    else {
        spdlog::warn("Cannot find compile options for "+fullFilename+", may be header file?");
    }

    char* orig_dir=getcwd(nullptr,0);
    if (chdir(target_dir.c_str()) != 0) {
        spdlog::error("Cannot change directory to {}", target_dir);
        exit(1);
    }

    size_t prepos=fullFilename.find_last_of('/');
    args.push_back("-I"+fullFilename.substr(0,prepos));
    if (Config::getConfig().metaproPath!="") {
        args.push_back("-I"+Config::getConfig().metaproPath+"/include");
    }
    else {
        args.push_back("-I/usr/local/include/metapro/include");
    }
    args.push_back("-Wno-strict-prototypes");
    args.push_back("-Wno-incompatible-pointer-types-discards-qualifiers");
    args.push_back("-Wno-parentheses");
    args.push_back("-ferror-limit=0");
    std::string newFilename=Config::getConfig().outputDirectory+"/"+replaceString(filename,"/","#");
    code=readCodeToString(newFilename);

    spdlog::info("Post-process file: "+filename);
    auto clock = std::chrono::system_clock::now();
    uint64_t startTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(clock.time_since_epoch()).count());
    preunit=clang::tooling::buildASTFromCodeWithArgs(
        code,
        args,
        fullFilename
    );
    uint64_t execTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - startTime;
    Config::getConfig().genTime += execTime;
    ctxt=&preunit->getASTContext();

    chdir(orig_dir);
    free(orig_dir);
}

bool PostProcessor::startTraverse() {
    clang::TranslationUnitDecl* decl=ctxt->getTranslationUnitDecl();
    auto clock = std::chrono::system_clock::now();
    uint64_t startTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(clock.time_since_epoch()).count());

    bool result = TraverseDecl(decl);

    uint64_t execTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - startTime;
    Config::getConfig().genTime += execTime;

    return result;
}

bool PostProcessor::VisitIfStmt(clang::IfStmt* ifStmt) {
    return true; // We patch condition in source level
    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::Expr* cond = ifStmt->getCond();
    clang::CharSourceRange condRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(cond->getSourceRange()));
    uint64_t curLine = sm.getExpansionLineNumber(condRange.getBegin());
    if (flResult.size()>0) {
        bool isSuspicious=false;
        for (FaultLocalizer::ResultRecord record:flResult) {
            if (record.loc.file==filename && record.loc.line + 1 == curLine) { // +1 for metapro runtime header
                isSuspicious=true;
                break;
            }
        }
        if (!isSuspicious) return true; // Skip non-suspicious line
    }

    uint64_t curJmpID;
    if (jmpIDs.find(curLine) == jmpIDs.end()) {
        // Find the closest jmpID
        auto it = jmpIDs.lower_bound(curLine);
        // A line with no scope of its own takes the next line's, or the sentinel when this is the
        // last line: reading curJmpID unset is what this did before.
        curJmpID = (it == jmpIDs.end()) ? (uint64_t)(std::pow(2, 63) - 1) : it->second;
    }
    else {
        curJmpID = jmpIDs[curLine];
    }
    locInfo.addLocation(filename, curLine, sm.getExpansionColumnNumber(condRange.getBegin()),
                        sm.getExpansionLineNumber(condRange.getEnd()), sm.getExpansionColumnNumber(condRange.getEnd()), curJmpID);
    return true;
}

bool PostProcessor::VisitForStmt(clang::ForStmt *forStmt) {
    return true; // We patch condition in source level
    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::Expr* cond = forStmt->getCond();
    clang::CharSourceRange condRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(cond->getSourceRange()));
    clang::SourceLocation condStartLoc = condRange.getBegin();
    uint64_t curLine = sm.getExpansionLineNumber(condStartLoc);
    if (flResult.size()>0) {
        bool isSuspicious=false;
        for (FaultLocalizer::ResultRecord record:flResult) {
            if (record.loc.file==filename && record.loc.line+1==curLine) {
                isSuspicious=true;
                break;
            }
        }
        if (!isSuspicious) return true; // Skip non-suspicious line
    }

    uint64_t curJmpID;
    if (jmpIDs.find(curLine) == jmpIDs.end()) {
        auto it = jmpIDs.lower_bound(curLine);
        // Closest jmpID, or the sentinel past the last line (curJmpID was read unset before).
        curJmpID = (it == jmpIDs.end()) ? (uint64_t)(std::pow(2, 63) - 1) : it->second;
    }
    else {
        curJmpID = jmpIDs[curLine];
    }
    locInfo.addLocation(filename, curLine, sm.getExpansionColumnNumber(condStartLoc),
                        sm.getExpansionLineNumber(condRange.getEnd()), sm.getExpansionColumnNumber(condRange.getEnd()), curJmpID);
    return true;
}

bool PostProcessor::VisitWhileStmt(clang::WhileStmt *whileStmt) {
    return true; // We patch condition in source level
    clang::SourceManager& sm = ctxt->getSourceManager();
    clang::Expr* cond = whileStmt->getCond();
    clang::CharSourceRange condRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(cond->getSourceRange()));
    clang::SourceLocation condStartLoc = condRange.getBegin();
    uint64_t curLine = sm.getExpansionLineNumber(condStartLoc);
    if (flResult.size()>0) {
        bool isSuspicious=false;
        for (FaultLocalizer::ResultRecord record:flResult) {
            if (record.loc.file==filename && record.loc.line+1==curLine) {
                isSuspicious=true;
                break;
            }
        }
        if (!isSuspicious) return true; // Skip non-suspicious line
    }

    uint64_t curJmpID;
    if (jmpIDs.find(curLine) == jmpIDs.end()) {
        auto it = jmpIDs.lower_bound(curLine);
        // Closest jmpID, or the sentinel past the last line (curJmpID was read unset before).
        curJmpID = (it == jmpIDs.end()) ? (uint64_t)(std::pow(2, 63) - 1) : it->second;
    }
    else {
        curJmpID = jmpIDs[curLine];
    }
    locInfo.addLocation(filename, curLine, sm.getExpansionColumnNumber(condStartLoc),
                        sm.getExpansionLineNumber(condRange.getEnd()), sm.getExpansionColumnNumber(condRange.getEnd()), curJmpID);
    return true;
}

bool PostProcessor::VisitCompoundStmt(clang::CompoundStmt* compoundStmt) {
    clang::SourceManager& sm = ctxt->getSourceManager();
    for (clang::Stmt* body:compoundStmt->body()) {
        if (compoundStmt->size() > 1 && clang::NullStmt::classof(body)) continue; // Skip null statement which may be generated by macros and cause problem for line number checking
        clang::CharSourceRange bodyRange = sm.getExpansionRange(clang::CharSourceRange::getTokenRange(body->getSourceRange()));
        clang::SourceLocation startLoc = bodyRange.getBegin();
        uint64_t curLine = sm.getExpansionLineNumber(startLoc);
        if (flResult.size()>0) {
            bool isSuspicious=false;
            for (FaultLocalizer::ResultRecord record:flResult) {
                if (record.loc.file==filename && record.loc.line+1==curLine) {
                    isSuspicious=true;
                    break;
                }
            }
            if (!isSuspicious) continue; // Skip non-suspicious line
        }
        uint64_t curJmpID;
        if (jmpIDs.find(curLine) == jmpIDs.end()) {
            auto it = jmpIDs.lower_bound(curLine);
            // Closest jmpID, or the sentinel past the last line (curJmpID was read unset before).
            curJmpID = (it == jmpIDs.end()) ? (uint64_t)(std::pow(2, 63) - 1) : it->second;
        }
        else {
            curJmpID = jmpIDs[curLine];
        }

        if (clang::CallExpr::classof(body)) {
            // TODO: Optimize patching unnecessary function calls
            clang::CallExpr* callExpr = llvm::dyn_cast<clang::CallExpr>(body);
            clang::FunctionDecl* funcDecl = callExpr->getDirectCallee();
            std::set<std::string> blacklistFunc = {"setjmp", "longjmp"};
            if (funcDecl != nullptr && blacklistFunc.find(funcDecl->getNameAsString()) == blacklistFunc.end() &&
                    (funcDecl->getNameAsString().size() < 9 || funcDecl->getNameAsString().substr(funcDecl->getNameAsString().size() - 9) != "__metapro")) {
                // locInfo.addLocation(filename, curLine, sm.getExpansionColumnNumber(startLoc), curJmpID);
            }
        }
        locInfo.addLocation(filename, curLine, sm.getExpansionColumnNumber(startLoc),
                            sm.getExpansionLineNumber(bodyRange.getEnd()), sm.getExpansionColumnNumber(bodyRange.getEnd()), curJmpID);
    }

    clang::Stmt* last_stmt = *(compoundStmt->body_rbegin());
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
    uint64_t curLine = sm.getExpansionLineNumber(endLoc);
    if (flResult.size()>0) {
        bool isSuspicious=false;
        for (FaultLocalizer::ResultRecord record:flResult) {
            if (record.loc.file==filename && record.loc.line+1==curLine) {
                isSuspicious=true;
                break;
            }
        }
        if (!isSuspicious) return true; // Skip non-suspicious line
    }
    uint64_t curJmpID;
    if (jmpIDs.find(curLine) == jmpIDs.end()) {
        auto it = jmpIDs.lower_bound(curLine);
        // Closest jmpID, or the sentinel past the last line (curJmpID was read unset before).
        curJmpID = (it == jmpIDs.end()) ? (uint64_t)(std::pow(2, 63) - 1) : it->second;
    }
    else {
        curJmpID = jmpIDs[curLine];
    }
    locInfo.addLocation(filename, curLine, sm.getExpansionColumnNumber(endLoc),
                        sm.getExpansionLineNumber(bodyRange.getEnd()), sm.getExpansionColumnNumber(bodyRange.getEnd()), curJmpID);
    return true;
}   