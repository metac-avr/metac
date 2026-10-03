#include "patch/metaprogram_writer.h"
#include "patch/template.h"
#include "utils/project.h"
#include "utils/string.h"
#include "utils/path.h"
#include "config/config.h"

#include "spdlog/spdlog.h"
#include "clang/AST/ASTContext.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include <fstream>
#include <algorithm>
#include <unistd.h>
#include "clang/AST/AST.h"
#include "clang/Tooling/Tooling.h"
#include "postprocess/postprocessor.h"

void MetaprogramWriter::write() {
    clang::ASTContext* ctxt=nullptr;
    clang::Rewriter rewriter;
    clang::SourceLocation loc;
    for (Patch* patch:patches) {
        if (ctxt==nullptr) {
            ctxt=patch->ctxt;
            rewriter=clang::Rewriter(ctxt->getSourceManager(), ctxt->getLangOpts());
        }

        if (patch->patchTemplate==PatchTemplate::REPLACE_CONDITION){
            ReplaceConditionPatch* replacePatch=(ReplaceConditionPatch*) patch;
            loc = replacePatch->range.getBegin();
            rewriter.ReplaceText(replacePatch->range, replacePatch->patchStringInMetaProgram);
        }
        else if (patch->patchTemplate==PatchTemplate::INSERT) {
            InsertPatch* insertPatch=(InsertPatch*) patch;
            loc = insertPatch->insertLoc;
            rewriter.InsertTextAfter(loc, insertPatch->patchStringInMetaProgram);
        }
        else if (patch->patchTemplate==PatchTemplate::INSERT_NOT_NULL_CHECKER) {
            InsertNotNullChecker* insertPatch=(InsertNotNullChecker*) patch;
            loc = insertPatch->insertLoc;
            rewriter.InsertTextAfter(loc, insertPatch->patchStringInMetaProgram);
        }
        else {
            // Unknown template, error!
            spdlog::error("Unknown template: "+patch->patchTemplate.toString());
            exit(1);
        }
    }

    // Write to file
    std::string newFilename=Config::getConfig().outputDirectory+"/"+replaceString(filename,"/","#");
    if (patches.size() > 0) {
        clang::SourceManager& sm=ctxt->getSourceManager();
        std::string newCode=rewriter.getRewrittenText(clang::SourceRange(sm.getLocForStartOfFile(sm.getFileID(loc)),
                                                                         sm.getLocForEndOfFile(sm.getFileID(loc))));
        std::ofstream newFile(newFilename.c_str(),std::ofstream::out);
        newFile << newCode;
        newFile.close();
    }
}